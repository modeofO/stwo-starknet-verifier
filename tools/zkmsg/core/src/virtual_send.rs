//! The SNIP-36 send route: Prepare → Prove → Publish, one transaction.
//!
//! Since Starknet 0.14.2 the sequencer verifies S-two proofs natively, but
//! only proofs of the *virtual* Starknet OS running one invoke on top of a
//! past block. So the zkmsg statement lives in a contract (`ZkmsgSendProver`)
//! that only ever runs inside that virtual OS, here: its calldata is the
//! witness (scan private key, ephemeral private key, Merkle paths) and the
//! chain never sees it. What leaves is the proof and its facts, whose one
//! L2→L1 message hash binds (store, commitment, ephemeral pubkey, root,
//! content hash). `MessageStoreSnip36.send_message` recomputes that hash from
//! public data in the same transaction that publishes the ciphertext.
//!
//! A port of zkmsg-ios `VirtualSendExecutor`; its rules, exactly:
//!
//!   * Prepare reads the tree root, both members, both paths and the nonce at
//!     ONE block N — the block the virtual OS then runs on — so the witness
//!     can't disagree with the state the proof is about.
//!   * The witness is never written down. The proof and its facts are public
//!     and are, so a killed process resumes at Publish. A proof doesn't expire:
//!     the sequencer only needs its base block to trail the head by 10.
//!   * Verify before spending: the facts must attest exactly the message hash
//!     this send should produce, on block N.
//!   * Never sign against a forgotten root. The store keeps the current root
//!     and a short history; a proof against an evicted root would revert and
//!     keep the fee. `is_known_root` is checked first, and a stale proof is
//!     retired so the next attempt proves afresh.
//!   * Never submit twice. The publish hash is saved the moment the gateway
//!     takes it; a resume polls that hash before it would ever resubmit.

use std::fs;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starknet_crypto::poseidon_hash_many;
use starknet_types_core::felt::Felt;

use crate::app::{Member, short_string_felt};
use crate::chain::{Chain, bytearray_calldata, bytearray_decode, felt_hex, snkeccak};
use crate::config::{Config, Home, Keys, STRK_TOKEN, is_current_store, store_deploy_block};
use crate::crypto::{SealedV2, kem_digest, leaf_v3, member_commit, send_v2};
use crate::tree::fold_path;
use crate::invoke_v3::{Bounds, Call, InvokeV3, ResourceBounds, Signer, execute_calldata};
use crate::pipeline::PipelineEvent;
use crate::sequencer::{Gateway, GatewayError, ProofAttachment};
use crate::state::{SendState, StepKind};

/// The contracts a virtual send is bound to. The store pins the prover, so
/// they travel together.
#[derive(Debug, Clone)]
pub struct VirtualRoute {
    pub store: Felt,
    /// The contract whose virtual execution is proven.
    pub prover: Felt,
    pub chain_id: Felt,
}

impl VirtualRoute {
    /// The route for `store`: the v3 store and its pinned prover. The v3
    /// statement proves only the sender's membership, by knowledge of the
    /// membership secret under the root (hash-only); the store publishes
    /// `kem_ct ‖ blob`.
    pub fn for_store(store: &str) -> Option<Self> {
        use crate::config::{SEPOLIA_STORE_V3, SEPOLIA_V3_SEND_PROVER};
        is_current_store(store).then(|| Self {
            store: Felt::from_hex(SEPOLIA_STORE_V3).expect("constant"),
            prover: Felt::from_hex(SEPOLIA_V3_SEND_PROVER).expect("constant"),
            chain_id: crate::invoke_v3::short_string("SN_SEPOLIA"),
        })
    }
}

/// What Prepare hands Prove: the public tuple, the bytes to publish, and the
/// `prove_send` calldata — which IS the witness, so this never touches disk.
struct Prepared {
    id: String,
    block: u64,
    nonce: Felt,
    commitment: Felt,
    ephemeral: Felt,
    root: Felt,
    /// The ByteArray `send_message` publishes: `kem_ct ‖ blob`.
    content: Vec<u8>,
    content_hash: Felt,
    prove_calldata: Vec<Felt>,
}

/// A send's id: the commitment's first 10 hex digits.
fn send_id(commitment: &Felt) -> String {
    format!("{:.10}", felt_hex(commitment).trim_start_matches("0x"))
}

/// v3 `prove_send` calldata: `(store, content_hash, commitment, E, root,
/// sender_scan_pub, sender_kem_digest, member_secret, sender_leaf_index,
/// sender_path)`. The witness is the membership secret m; the scan key is a
/// public input here (no elliptic-curve step in the statement).
pub fn prove_send_calldata_v3(
    store: Felt,
    sealed: &SealedV2,
    root: Felt,
    sender_scan_pub: Felt,
    sender_kem_digest: Felt,
    member_secret: Felt,
    sender_leaf_index: u32,
    sender_path: &[Felt],
) -> Result<Vec<Felt>> {
    ensure!(sender_path.len() == 20, "sender path has {} siblings, not 20", sender_path.len());
    let mut out = vec![
        store,
        sealed.content_hash,
        sealed.commitment,
        sealed.ephemeral_pub,
        root,
        sender_scan_pub,
        sender_kem_digest,
        member_secret,
        Felt::from(sender_leaf_index),
        Felt::from(20u64),
    ];
    out.extend_from_slice(sender_path);
    Ok(out)
}

/// What the prover hands back: the proof as the gateway takes it (base64)
/// and the facts the transaction signs over. Saved in the send's workdir.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VirtualProof {
    pub proof: String,
    pub proof_facts: Vec<String>,
}

impl VirtualProof {
    fn facts(&self) -> Result<Vec<Felt>> {
        self.proof_facts.iter().map(|f| Felt::from_hex(f).context("proof fact")).collect()
    }
}

// --- pure encodings the contracts must agree with ---------------------------

/// `[PROOF1, VIRTUAL_SNOS, program_hash, VIRTUAL_SNOS0, block_number,
/// block_hash, os_config_hash, n_messages, message_hash]`.
const FACTS_LEN: usize = 9;
const FACT_BLOCK: usize = 4;
const FACT_N_MESSAGES: usize = 7;
const FACT_MESSAGE_HASH: usize = 8;

/// Poseidon over the Cairo serialization of the ciphertext `ByteArray` —
/// what the proof carries in the ciphertext's place
/// (`MessageStoreSnip36::content_hash`).
pub fn content_hash(ciphertext: &[u8]) -> Felt {
    let felts: Vec<Felt> = bytearray_calldata(ciphertext)
        .iter()
        .map(|h| Felt::from_hex(h).expect("bytearray_calldata emits hex"))
        .collect();
    poseidon_hash_many(&felts)
}

/// The L2→L1 message hash the virtual OS writes into the facts:
/// `poseidon([from, to, payload_len, ...payload])`, `to` = 0 (an L1 address
/// must fit 160 bits, so the store rides in the payload), payload
/// `[store, commitment, ephemeral_pubkey, root, content_hash]`.
pub fn message_hash(route: &VirtualRoute, commitment: Felt, ephemeral: Felt, root: Felt, content: Felt) -> Felt {
    let payload = [route.store, commitment, ephemeral, root, content];
    let mut fields = vec![route.prover, Felt::ZERO, Felt::from(payload.len() as u64)];
    fields.extend_from_slice(&payload);
    poseidon_hash_many(&fields)
}

/// The facts must attest exactly `expected`, proven on `block`.
pub fn check_facts(facts: &[Felt], expected: Felt, block: u64) -> Result<()> {
    ensure!(facts.len() == FACTS_LEN, "proof does not attest this send: {} facts, expected {FACTS_LEN}", facts.len());
    ensure!(
        facts[FACT_BLOCK] == Felt::from(block),
        "proof does not attest this send: proven on block {}, not {block}",
        felt_hex(&facts[FACT_BLOCK]),
    );
    ensure!(
        facts[FACT_N_MESSAGES] == Felt::ONE,
        "proof does not attest this send: {} messages",
        felt_hex(&facts[FACT_N_MESSAGES]),
    );
    ensure!(facts[FACT_MESSAGE_HASH] == expected, "proof does not attest this send: message hash differs");
    Ok(())
}

/// Resource bounds of the virtual transaction. It is never charged; the
/// virtual OS only needs amounts large enough to run it (the reference
/// prover's defaults).
pub const VIRTUAL_BOUNDS: Bounds = Bounds {
    l1_gas: ResourceBounds { max_amount: 0, max_price_per_unit: 0 },
    l2_gas: ResourceBounds { max_amount: 0x700_0000, max_price_per_unit: 0 },
    l1_data_gas: ResourceBounds { max_amount: 0x1b0, max_price_per_unit: 0 },
};

/// The signed virtual invoke in RPC shape, as `starknet_proveTransaction`
/// takes it. The account's `__validate__` runs inside the virtual OS, so it
/// carries a real signature over the ordinary (fact-less) hash.
pub fn virtual_invoke(signer: &Signer, calls: &[Call], nonce: Felt, chain_id: Felt) -> Result<Value> {
    let calldata = execute_calldata(calls);
    let hash = InvokeV3 {
        sender: signer.address,
        calldata: &calldata,
        chain_id,
        nonce,
        tip: 0,
        bounds: VIRTUAL_BOUNDS,
        proof_facts: &[],
    }
    .hash();
    let [r, s] = signer.sign(&hash)?;
    Ok(json!({
        "type": "INVOKE",
        "version": "0x3",
        "sender_address": felt_hex(&signer.address),
        "calldata": calldata.iter().map(felt_hex).collect::<Vec<_>>(),
        "nonce": felt_hex(&nonce),
        "resource_bounds": VIRTUAL_BOUNDS.rpc_json(),
        "tip": "0x0",
        "paymaster_data": [],
        "account_deployment_data": [],
        "nonce_data_availability_mode": "L1",
        "fee_data_availability_mode": "L1",
        "signature": [felt_hex(&r), felt_hex(&s)],
    }))
}

/// Fee bounds for the one real transaction. Measured on the phone: ~77M L2
/// gas and 384 data gas for a send whose ~300 KB proof is priced as calldata.
pub struct GasPolicy {
    pub l2_gas: u64,
    pub l1_data_gas: u64,
    pub l1_gas: u64,
    /// Applied to the latest block's prices, in percent.
    pub price_percent: u128,
}

pub const GAS_POLICY: GasPolicy =
    GasPolicy { l2_gas: 120_000_000, l1_data_gas: 4_096, l1_gas: 0, price_percent: 150 };

impl GasPolicy {
    pub fn bounds(&self, (l1, l2, l1_data): (u128, u128, u128)) -> Bounds {
        let scale = |p: u128| p.saturating_mul(self.price_percent) / 100;
        Bounds {
            l1_gas: ResourceBounds { max_amount: self.l1_gas, max_price_per_unit: scale(l1) },
            l2_gas: ResourceBounds { max_amount: self.l2_gas, max_price_per_unit: scale(l2) },
            l1_data_gas: ResourceBounds { max_amount: self.l1_data_gas, max_price_per_unit: scale(l1_data) },
        }
    }
}

/// The fee ceiling an account must hold for `bounds` to pass validation:
/// the sequencer checks the balance against the full ceiling, not what the
/// send ends up costing.
pub fn fee_ceiling_fri(bounds: &Bounds) -> u128 {
    [bounds.l1_gas, bounds.l2_gas, bounds.l1_data_gas]
        .iter()
        .map(|b| (b.max_amount as u128).saturating_mul(b.max_price_per_unit))
        .fold(0u128, u128::saturating_add)
}

// --- the executor -----------------------------------------------------------

const PUBLISH_POLL: Duration = Duration::from_secs(5);
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(1800);
const TOO_RECENT_WAIT: Duration = Duration::from_secs(10);
const PUBLISH_ATTEMPTS: usize = 12;

pub struct VirtualSender<'a> {
    pub home: &'a Home,
    pub route: VirtualRoute,
    /// Every read goes through the prover's RPC, so the block the tree is
    /// read at is a block the prover can fetch storage proofs for.
    pub chain: Chain,
    pub gateway: Gateway,
    pub signer: Signer,
    pub prover_bin: PathBuf,
}

impl<'a> VirtualSender<'a> {
    pub fn new(home: &'a Home, config: &Config) -> Result<Self> {
        let route = VirtualRoute::for_store(&config.store)
            .with_context(|| {
                format!("{} is not the v3 store — `zkmsg migrate-store` moves this profile", config.store)
            })?;
        Ok(Self {
            home,
            route,
            chain: Chain::new(config.prover_rpc_url(), &config.account),
            gateway: Gateway::sepolia(),
            signer: Signer::from_sncast_account(&config.account)?,
            prover_bin: config.virtual_prover_bin(),
        })
    }

    /// A fresh send: prepare, prove, publish. Returns the finished state.
    pub fn send(
        &self,
        keys: &Keys,
        handle: &str,
        text: &str,
        sink: &mut dyn FnMut(PipelineEvent),
    ) -> Result<SendState> {
        let total = 3;

        // 1. Prepare, all at one block.
        sink(PipelineEvent::StepStarted { index: 0, total, kind: StepKind::Prepare });
        let p = self.prepare(keys, handle, text)?;
        let block = p.block;
        let mut state = SendState::new_virtual_plan(
            p.id.clone(),
            handle.to_string(),
            hex::encode(&p.content),
            (felt_hex(&p.commitment), felt_hex(&p.ephemeral), felt_hex(&p.root)),
            block,
        );
        state.mark_done(0, None, Some(format!("block {block}")));
        sink(PipelineEvent::StepCompleted { kind: StepKind::Prepare, tx_hash: None, note: None });

        // Spend check before minutes of proving: the account must hold the
        // whole fee ceiling, or the publish is refused at validation.
        let ceiling = fee_ceiling_fri(&GAS_POLICY.bounds(self.chain.gas_prices()?));
        let balance = self.balance_fri()?;
        ensure!(
            balance >= ceiling,
            "account holds {} STRK; a send needs a fee ceiling of {} STRK",
            strk(balance),
            strk(ceiling),
        );

        // 2. Prove. The witness rides in the virtual transaction's calldata,
        //    handed to the prover on stdin and dropped after.
        sink(PipelineEvent::StepStarted { index: 1, total, kind: StepKind::Prove });
        let Prepared { nonce, commitment, ephemeral, root, content_hash: content, prove_calldata, .. } = p;
        let call = Call::new(self.route.prover, "prove_send", prove_calldata);
        let transaction = virtual_invoke(&self.signer, &[call], nonce, self.route.chain_id)?;
        let started = Instant::now();
        let proof = self.prove(&state, transaction, block)?;
        let expected = message_hash(&self.route, commitment, ephemeral, root, content);
        check_facts(&proof.facts()?, expected, block)?;
        fs::write(self.proof_path(&state), serde_json::to_string(&proof)?)?;
        state.mark_done(
            1,
            None,
            Some(format!("{:.0} s, {} b64 bytes, facts verified", started.elapsed().as_secs_f64(), proof.proof.len())),
        );
        state.save(self.home)?;
        sink(PipelineEvent::Checkpointed { id: state.id.clone() });
        sink(PipelineEvent::StepCompleted { kind: StepKind::Prove, tx_hash: None, note: None });

        // 3. Publish.
        self.publish(&mut state, sink)?;
        Ok(state)
    }

    /// Only the sender's membership is proven. The recipient's ML-KEM key
    /// comes from its registration event and must hash to the `kem_digest`
    /// the store holds for it at block N.
    fn prepare(&self, keys: &Keys, handle: &str, text: &str) -> Result<Prepared> {
        let sender_handle = keys.handle.as_deref().context("not registered — run `zkmsg register`")?;
        let scan_pub = keys.scan_pub_felt()?;
        let own_digest = kem_digest(&keys.kem_keypair()?.1);
        let member_secret = keys.member_secret_felt()?;
        let own_m_commit = member_commit(&member_secret);

        let block = self.block_number()?;
        let recipient = self.member(handle, block)?;
        let sender = self.member(sender_handle, block)?;
        ensure!(
            sender.scan_pub == scan_pub
                && sender.kem_digest == own_digest
                && sender.m_commit == own_m_commit,
            "'{sender_handle}' is registered to different keys in this store",
        );
        let root = self.root(block)?;
        let sender_path = self.path(sender.leaf_index, block)?;
        let nonce = self.nonce(Some(block))?;
        ensure!(
            fold_path(&leaf_v3(&scan_pub, &own_digest, &own_m_commit), sender.leaf_index, &sender_path)
                == root,
            "sender path does not fold to the root at block {block}",
        );

        let recipient_ek = self.registered_kem_key(handle)?;
        ensure!(
            kem_digest(&recipient_ek) == recipient.kem_digest,
            "'{handle}': the registered ML-KEM key does not match the store's kem_digest",
        );
        let sealed = send_v2(&recipient.scan_pub, &recipient_ek, text.as_bytes())?;
        let prove_calldata = prove_send_calldata_v3(
            self.route.store,
            &sealed,
            root,
            scan_pub,
            own_digest,
            member_secret,
            sender.leaf_index,
            &sender_path,
        )?;
        Ok(Prepared {
            id: send_id(&sealed.commitment),
            block,
            nonce,
            commitment: sealed.commitment,
            ephemeral: sealed.ephemeral_pub,
            root,
            content_hash: sealed.content_hash,
            content: sealed.content,
            prove_calldata,
        })
    }

    /// The 1184-byte ML-KEM key `handle` registered with, from its
    /// `UserRegistered` event: data `[handle, scan_pubkey, leaf_index,
    /// m_commit, kem_pubkey ByteArray…]`. A handle registers once, so the
    /// first match is the only one.
    fn registered_kem_key(&self, handle: &str) -> Result<Vec<u8>> {
        let store = felt_hex(&self.route.store);
        let key0 = felt_hex(&snkeccak("UserRegistered"));
        let want = short_string_felt(handle)?;
        for (_, data) in self.chain.events(&store, &key0, store_deploy_block(&store))? {
            let felts: Vec<Felt> =
                data.iter().map(|s| Felt::from_hex(s).context("event felt")).collect::<Result<_>>()?;
            if felts.len() > 4 && felts[0] == want {
                return Ok(bytearray_decode(&felts[4..])?.0);
            }
        }
        bail!("no registration event for '{handle}'")
    }

    /// Resumes a saved virtual send. Only Publish can be pending: the state
    /// is first written after the proof exists.
    pub fn resume(&self, state: &mut SendState, sink: &mut dyn FnMut(PipelineEvent)) -> Result<()> {
        match state.next_pending().map(|i| state.steps[i].kind.clone()) {
            None => {
                sink(PipelineEvent::Completed);
                Ok(())
            }
            Some(StepKind::Publish) => self.publish(state, sink),
            Some(other) => bail!(
                "send '{}' stopped at {other:?}, before its proof existed; nothing to resume — send again",
                state.id
            ),
        }
    }

    fn publish(&self, state: &mut SendState, sink: &mut dyn FnMut(PipelineEvent)) -> Result<()> {
        let index = state
            .steps
            .iter()
            .position(|s| s.kind == StepKind::Publish)
            .context("virtual plan has no Publish step")?;
        let total = state.steps.len();
        sink(PipelineEvent::StepStarted { index, total, kind: StepKind::Publish });

        // A hash saved by an earlier attempt is settled before anything is
        // signed. Landed or still in flight: wait for it. Reverted: the fee
        // is spent and the send is over. Only an explicit drop (never
        // received, or rejected before execution) falls through, and then to
        // the IDENTICAL transaction (saved nonce + bounds), which can land at
        // most once however often it is resubmitted.
        if let Some(saved) = state.steps[index].tx_hash.clone() {
            let hash = Felt::from_hex(&saved)?;
            let status = self.gateway.status(&hash)?;
            if status.is_reverted() {
                self.retire(state)?;
                bail!(
                    "publish {saved} reverted ({}); its fee is spent — send again",
                    status.revert_reason.as_deref().unwrap_or("no reason")
                );
            }
            if !status.is_dropped() || !self.rpc_agrees_dropped(&hash) {
                self.gateway.await_acceptance(&hash, PUBLISH_POLL, PUBLISH_TIMEOUT)?;
                return self.finish(state, index, saved, sink);
            }
        }

        let root = Felt::from_hex(&state.expected_merkle_root)?;
        let known = self.store_call("is_known_root", &[root], None)?;
        if known.first() != Some(&Felt::ONE) {
            self.retire(state)?;
            bail!(
                "the tree moved on since this send was proven (root {} is no longer known to the \
                 store); send again to re-prove",
                state.expected_merkle_root
            );
        }

        let proof: VirtualProof = serde_json::from_str(
            &fs::read_to_string(self.proof_path(state)).context("reading the saved proof")?,
        )?;
        let facts = proof.facts()?;
        let content = hex::decode(&state.ciphertext_hex)?;
        // The saved proof must still attest exactly this send (a swapped or
        // corrupted file would be signed over and burn the fee).
        let expected = message_hash(
            &self.route,
            Felt::from_hex(&state.expected_commitment)?,
            Felt::from_hex(&state.expected_ephemeral_pubkey)?,
            root,
            content_hash(&content),
        );
        check_facts(&facts, expected, state.base_block.context("state has no base block")?)?;

        let mut calldata = vec![
            Felt::from_hex(&state.expected_commitment)?,
            Felt::from_hex(&state.expected_ephemeral_pubkey)?,
            root,
        ];
        for word in bytearray_calldata(&content) {
            calldata.push(Felt::from_hex(&word)?);
        }
        let call = Call::new(self.route.store, "send_message", calldata);
        let attachment = ProofAttachment { proof: &proof.proof, proof_facts: &facts };

        let (mut nonce, bounds) = match (&state.publish_nonce, state.publish_bounds) {
            (Some(nonce), Some(bounds)) => (Felt::from_hex(nonce)?, bounds),
            _ => (self.nonce(None)?, GAS_POLICY.bounds(self.chain.gas_prices()?)),
        };
        for attempt in 0..PUBLISH_ATTEMPTS {
            let last = attempt + 1 == PUBLISH_ATTEMPTS;
            let signed =
                self.gateway.sign_invoke(&self.signer, std::slice::from_ref(&call), nonce, bounds, Some(&attachment))?;
            let hex = felt_hex(&signed.hash);
            // Recorded BEFORE the POST: whatever happens to the request, a
            // resume knows the one hash this send may have produced.
            state.record_submission(index, hex.clone());
            state.publish_nonce = Some(felt_hex(&nonce));
            state.publish_bounds = Some(bounds);
            state.save(self.home)?;

            let rejected = match self.gateway.submit(&signed) {
                Ok(()) => {
                    sink(PipelineEvent::TxSubmitted { kind: StepKind::Publish, tx_hash: hex.clone() });
                    self.gateway.await_acceptance(&signed.hash, PUBLISH_POLL, PUBLISH_TIMEOUT)?;
                    return self.finish(state, index, hex, sink);
                }
                Err(e) => match e.downcast_ref::<GatewayError>() {
                    Some(g @ GatewayError::Rejected { .. }) => (g.clone(), e),
                    // Timeout, 5xx, a hash mismatch: the gateway may hold the
                    // transaction. Stop; the saved hash is polled on resume.
                    _ => return Err(e),
                },
            };
            let (gateway, err) = rejected;
            if !last && gateway.too_recent() {
                // Same transaction again once the base block is old enough.
                std::thread::sleep(TOO_RECENT_WAIT);
                continue;
            }
            if let (false, Some(expected)) = (last, gateway.expected_nonce()) {
                // The nonce moved. If it moved because THIS send landed (an
                // earlier attempt the gateway did take), finish instead of
                // paying again under the next nonce.
                let status = self.gateway.status(&signed.hash)?;
                if !status.is_dropped() || !self.rpc_agrees_dropped(&signed.hash) {
                    self.gateway.await_acceptance(&signed.hash, PUBLISH_POLL, PUBLISH_TIMEOUT)?;
                    return self.finish(state, index, hex, sink);
                }
                ensure!(
                    Felt::from(expected) != nonce,
                    "gateway rejected nonce {} but expects the same one",
                    felt_hex(&nonce)
                );
                nonce = Felt::from(expected);
                continue;
            }
            return Err(err);
        }
        bail!("publish retries exhausted")
    }

    /// Second opinion before anything is resubmitted under a new nonce: the
    /// feeder can lag, so a transaction counts as dropped only if the RPC
    /// doesn't know it either. Any doubt (an RPC error included) says "not
    /// dropped", which waits instead of paying twice.
    fn rpc_agrees_dropped(&self, hash: &Felt) -> bool {
        match self.chain.rpc("starknet_getTransactionStatus", json!([felt_hex(hash)])) {
            Ok(v) => matches!(v["finality_status"].as_str(), Some("REJECTED")),
            // TXN_HASH_NOT_FOUND (code 29) is the RPC's "never seen it".
            Err(e) => format!("{e:#}").contains("\"code\":29"),
        }
    }

    fn finish(
        &self,
        state: &mut SendState,
        index: usize,
        tx_hash: String,
        sink: &mut dyn FnMut(PipelineEvent),
    ) -> Result<()> {
        state.mark_done(index, Some(tx_hash.clone()), Some("message published".into()));
        state.save(self.home)?;
        sink(PipelineEvent::StepCompleted { kind: StepKind::Publish, tx_hash: Some(tx_hash), note: None });
        sink(PipelineEvent::Completed);
        Ok(())
    }

    /// Takes a stale send out of the pending list: its proof can never be
    /// published. Renamed, not deleted, so the record survives.
    fn retire(&self, state: &SendState) -> Result<()> {
        let path = SendState::path(self.home, &state.id);
        fs::rename(&path, path.with_extension("stale"))
            .with_context(|| format!("retiring {}", path.display()))
    }

    fn prove(&self, state: &SendState, transaction: Value, block: u64) -> Result<VirtualProof> {
        let workdir = SendState::workdir(self.home, &state.id);
        fs::create_dir_all(&workdir)?;
        let spill = self.home.dir.join("spill");
        fs::create_dir_all(&spill)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&spill, fs::Permissions::from_mode(0o700))?;
        }
        let out_path = workdir.join("prover_out.json");
        let request = json!({
            "rpc_url": self.chain.rpc_url,
            "chain_id": crate::invoke_v3::short_string_text(&self.route.chain_id)?,
            "block_id": {"block_number": block},
            "transaction": transaction,
        });

        ensure!(
            self.prover_bin.exists(),
            "prover binary {} not found — build it (tools/snip36-phone-ffi/README.md) or set \
             \"virtual_prover_bin\" in config.json",
            self.prover_bin.display()
        );
        let mut child = Command::new(&self.prover_bin)
            .arg(&out_path)
            .env("ZKMSG_SPILL_DIR", &spill)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("starting {}", self.prover_bin.display()))?;
        {
            let mut stdin = child.stdin.take().context("prover stdin")?;
            stdin.write_all(request.to_string().as_bytes())?;
        }
        drop(request);
        let output = child.wait_with_output();
        // The spill files hold the prover's memory, witness included: gone
        // whatever happened.
        let _ = fs::remove_dir_all(&spill);
        let output = output?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail: Vec<String> = stderr.lines().rev().take(8).map(redact_felts).collect();
            bail!(
                "snip36-prove failed ({}):\n{}",
                output.status,
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            );
        }
        let out: Value = serde_json::from_str(&fs::read_to_string(&out_path)?)?;
        let _ = fs::remove_file(&out_path);
        Ok(VirtualProof {
            proof: out["proof"].as_str().context("prover output has no proof")?.to_string(),
            proof_facts: out["proof_facts"]
                .as_array()
                .context("prover output has no proof_facts")?
                .iter()
                .map(|f| f.as_str().map(String::from).context("proof fact is not a string"))
                .collect::<Result<_>>()?,
        })
    }

    fn proof_path(&self, state: &SendState) -> PathBuf {
        SendState::workdir(self.home, &state.id).join("virtual_proof.json")
    }

    // --- reads (all through the prover's RPC) -------------------------------

    fn block_id(block: Option<u64>) -> Value {
        match block {
            Some(n) => json!({"block_number": n}),
            None => json!("latest"),
        }
    }

    fn block_number(&self) -> Result<u64> {
        let v = self.chain.rpc("starknet_blockNumber", json!([]))?;
        v.as_u64().with_context(|| format!("starknet_blockNumber: {v}"))
    }

    fn call_at(&self, contract: Felt, entrypoint: &str, calldata: &[Felt], block: Option<u64>) -> Result<Vec<Felt>> {
        let v = self.chain.rpc(
            "starknet_call",
            json!([
                {
                    "contract_address": felt_hex(&contract),
                    "entry_point_selector": felt_hex(&snkeccak(entrypoint)),
                    "calldata": calldata.iter().map(felt_hex).collect::<Vec<_>>(),
                },
                Self::block_id(block),
            ]),
        )?;
        v.as_array()
            .with_context(|| format!("starknet_call {entrypoint}: {v}"))?
            .iter()
            .map(|x| Felt::from_hex(x.as_str().unwrap_or_default()).context("call result felt"))
            .collect()
    }

    fn store_call(&self, entrypoint: &str, calldata: &[Felt], block: Option<u64>) -> Result<Vec<Felt>> {
        self.call_at(self.route.store, entrypoint, calldata, block)
    }

    /// `get_user(handle)` at `block`; the store panics on an unknown handle.
    fn member(&self, handle: &str, block: u64) -> Result<Member> {
        let user = self
            .store_call("get_user", &[short_string_felt(handle)?], Some(block))
            .with_context(|| format!("'{handle}' is not registered in this store"))?;
        Member::from_felts(&user)
    }

    fn root(&self, block: u64) -> Result<Felt> {
        let root = self.store_call("get_merkle_root", &[], Some(block))?;
        root.first().copied().context("get_merkle_root returned nothing")
    }

    /// `get_merkle_path(leaf) -> Array<felt252>`: length prefix + 20 siblings.
    fn path(&self, leaf: u32, block: u64) -> Result<Vec<Felt>> {
        let raw = self.store_call("get_merkle_path", &[Felt::from(leaf)], Some(block))?;
        ensure!(raw.len() == 21, "get_merkle_path shape: {} felts", raw.len());
        Ok(raw[1..].to_vec())
    }

    fn nonce(&self, block: Option<u64>) -> Result<Felt> {
        let v = self.chain.rpc(
            "starknet_getNonce",
            json!([Self::block_id(block), felt_hex(&self.signer.address)]),
        )?;
        Felt::from_hex(v.as_str().with_context(|| format!("starknet_getNonce: {v}"))?).context("nonce")
    }

    fn balance_fri(&self) -> Result<u128> {
        let out = self.call_at(Felt::from_hex(STRK_TOKEN)?, "balance_of", &[self.signer.address], None)?;
        let low = out.first().context("balance_of shape")?;
        Ok(u128::from_str_radix(felt_hex(low).trim_start_matches("0x"), 16)?)
    }
}

/// Masks long hex runs in a prover log line: if the prover ever echoed its
/// request, the witness (scan private key) must not reach the UI.
fn redact_felts(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut rest = line;
    while let Some(pos) = rest.find("0x") {
        out.push_str(&rest[..pos]);
        let tail = &rest[pos + 2..];
        let len = tail.chars().take_while(char::is_ascii_hexdigit).count();
        if len >= 16 {
            out.push_str("0x…");
        } else {
            out.push_str(&rest[pos..pos + 2 + len]);
        }
        rest = &tail[len..];
    }
    out.push_str(rest);
    out
}

fn strk(fri: u128) -> String {
    format!("{:.2}", fri as f64 / 1e18)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn felts(v: &Value) -> Vec<Felt> {
        v.as_array().unwrap().iter().map(|x| Felt::from_hex(x.as_str().unwrap()).unwrap()).collect()
    }

    /// The real phone send in testdata: its facts attest the message hash we
    /// recompute from its own public send_message calldata.
    #[test]
    fn live_send_facts_check_out() {
        let tx: Value = serde_json::from_str(include_str!("../testdata/snip36_send_tx.json")).unwrap();
        let calldata = felts(&tx["calldata"]);
        let facts = felts(&tx["proof_facts"]);
        // The phone's send on the SNIP-36 v1 deployment: same facts layout and
        // message-hash rule as v2, which is what this pins.
        let route = VirtualRoute {
            store: Felt::from_hex("0x002b9c6f617b3197dfed76401c32aa3b4b597ebdd01a7eba4b5657236bc8084f").unwrap(),
            prover: Felt::from_hex("0x012b85a4b5e6918eb6f18a07fddc1667d67beaac0ab647928105b8ccf7ee5346").unwrap(),
            chain_id: crate::invoke_v3::short_string("SN_SEPOLIA"),
        };
        assert_eq!(calldata[1], route.store);
        // send_message args: commitment, ephemeral, root, then the ciphertext
        // ByteArray, whose serialization is exactly what content_hash hashes.
        let args = &calldata[4..];
        let content = poseidon_hash_many(&args[3..]);
        let (bytes, consumed) = crate::chain::bytearray_decode(&args[3..]).unwrap();
        assert_eq!(consumed, args.len() - 3);
        assert_eq!(content_hash(&bytes), content);

        let expected = message_hash(&route, args[0], args[1], args[2], content);
        let block = crate::chain::felt_to_u64(&facts[FACT_BLOCK]).unwrap();
        check_facts(&facts, expected, block).unwrap();
        // Any other block, or any other message, is refused.
        assert!(check_facts(&facts, expected, block + 1).is_err());
        assert!(check_facts(&facts, Felt::ONE, block).is_err());
        assert!(check_facts(&facts[..8], expected, block).is_err());
    }

    #[test]
    fn virtual_invoke_signs_the_factless_hash() {
        let key = Felt::from_hex("0xabc123").unwrap();
        let signer = Signer::new(Felt::from_hex("0x5617").unwrap(), key);
        let call = Call::new(Felt::from(7u64), "prove_send", vec![Felt::ONE]);
        let tx = virtual_invoke(&signer, &[call.clone()], Felt::from(3u64), crate::invoke_v3::short_string("SN_SEPOLIA")).unwrap();
        let calldata = execute_calldata(&[call]);
        let hash = InvokeV3 {
            sender: signer.address,
            calldata: &calldata,
            chain_id: crate::invoke_v3::short_string("SN_SEPOLIA"),
            nonce: Felt::from(3u64),
            tip: 0,
            bounds: VIRTUAL_BOUNDS,
            proof_facts: &[],
        }
        .hash();
        let sig = felts(&tx["signature"]);
        let public = starknet_crypto::get_public_key(&key);
        assert!(starknet_crypto::verify(&public, &hash, &sig[0], &sig[1]).unwrap());
        assert_eq!(tx["resource_bounds"]["l2_gas"]["max_amount"], "0x7000000");
        assert_eq!(tx["nonce_data_availability_mode"], "L1");
    }

    #[test]
    fn v3_calldata_layout_and_content_hash() {
        let (_, ek) = crate::crypto::kem_keygen_from_seed(&[7u8; 64]);
        let recipient_pub = crate::crypto::ec_mul_gen_x(&Felt::from(11u64));
        let sealed = send_v2(&recipient_pub, &ek, b"hello v3").unwrap();
        // The store hashes the published ByteArray the same way we do.
        assert_eq!(content_hash(&sealed.content), sealed.content_hash);
        assert!(sealed.content.len() >= crate::crypto::MIN_CONTENT_V2_LEN);

        let path: Vec<Felt> = (100..120u64).map(Felt::from).collect();
        let out = prove_send_calldata_v3(
            Felt::from(1u64), &sealed, Felt::from(2u64), Felt::from(3u64), Felt::from(4u64),
            Felt::from(9u64), 5, &path,
        )
        .unwrap();
        assert_eq!(
            &out[..10],
            &[
                Felt::from(1u64),
                sealed.content_hash,
                sealed.commitment,
                sealed.ephemeral_pub,
                Felt::from(2u64),
                Felt::from(3u64), // scan PUBKEY
                Felt::from(4u64), // kem_digest
                Felt::from(9u64), // member secret
                Felt::from(5u64),
                Felt::from(20u64),
            ]
        );
        assert_eq!(&out[10..], &path[..]);
        assert!(prove_send_calldata_v3(Felt::ONE, &sealed, Felt::ONE, Felt::ONE, Felt::ONE, Felt::ONE, 0, &path[..19]).is_err());
    }

    #[test]
    fn fee_ceiling_prices_the_whole_bound() {
        // 120M L2 gas at 1 gfri ×1.5 + 4096 data gas at 1000 ×1.5.
        let bounds = GAS_POLICY.bounds((0, 1_000_000_000, 1_000));
        assert_eq!(bounds.l2_gas.max_price_per_unit, 1_500_000_000);
        assert_eq!(fee_ceiling_fri(&bounds), 120_000_000 * 1_500_000_000 + 4_096 * 1_500);
    }

    #[test]
    fn only_the_current_store_routes() {
        let v2 = VirtualRoute::for_store(crate::config::SEPOLIA_STORE_V3).unwrap();
        assert_eq!(v2.prover, Felt::from_hex(crate::config::SEPOLIA_V3_SEND_PROVER).unwrap());
        assert!(VirtualRoute::for_store("0x002b9c6f617b3197dfed76401c32aa3b4b597ebdd01a7eba4b5657236bc8084f").is_none());
        assert!(VirtualRoute::for_store("0x04dc92ef9a90d336a79188c5408cdf9ce480f3ecd5b1ce55ef2ca207f2c3afe8").is_none());
    }
}
