//! The SNIP-36 send route on the v4 pool: Prepare → Prove → Publish, one
//! transaction, and none of it from the member's own account.
//!
//! Since Starknet 0.14.2 the sequencer verifies S-two proofs natively, but
//! only proofs of the *virtual* Starknet OS running one invoke on top of a
//! past block. So the zkmsg statement lives in a contract
//! (`ZkmsgSendProverV4`) that only ever runs inside that virtual OS, here: its
//! calldata is the witness (the sender's scan pubkey R, kem_digest,
//! membership secret m, quota slot, leaf index and Merkle path, and a fee
//! ticket's secret, index and path) and the chain never sees it. What leaves
//! is the proof and its facts, whose one L2→L1 message hash binds
//! (store, commitment, ephemeral pubkey, root, content hash, quota nullifier,
//! epoch, quota, ticket root, ticket nullifier).
//!
//! v4 removes the member's account from the send entirely:
//!
//!   * the virtual invoke comes from the SHARED `ZkmsgVirtualSenderV4`
//!     (zero fee, nonce 0 forever, any signature), so the proof request
//!     names no member's account;
//!   * the publish is an UNSIGNED invoke whose sender is the pool itself
//!     (`ZkmsgPoolV4` is the store and an account): its `__validate__`
//!     admits exactly the proven send, burns the ticket and pays the fee
//!     from the STRK tickets brought in.
//!
//! The rules (a port of zkmsg-ios `VirtualSendExecutor`, extended):
//!
//!   * Prepare reads everything at ONE block N — the block the virtual OS
//!     then runs on: every registration and every ticket purchase up to N,
//!     both roots at N, the rate limit, the virtual sender's nonce.
//!   * No read names a handle, a leaf, a ticket or the user's account. Both
//!     trees are rebuilt locally from all events (`registry`, `tickets`) and
//!     must reproduce the store's roots at N; the RPC sees the same requests
//!     from every sender.
//!   * The witness is never written down. The proof and its facts are public
//!     and are, so a killed process resumes at Publish. A proof doesn't
//!     expire at the protocol level; the pool accepts its epoch for
//!     `max_epoch_lag` epochs.
//!   * Verify before spending: the facts must attest exactly the message hash
//!     this send should produce, on block N.
//!   * Never publish against a forgotten root. The store keeps the current
//!     member root and a short history; a stale proof is retired (and its
//!     ticket released) so the next attempt proves afresh.
//!   * Never submit twice. The publish hash is saved the moment before the
//!     gateway takes it; a resume polls that hash before it would ever
//!     resubmit. A lost nonce race resubmits the SAME proof at the next pool
//!     nonce (no re-proving).

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use starknet_crypto::poseidon_hash_many;
use starknet_types_core::felt::Felt;

use crate::chain::{Chain, bytearray_calldata, felt_hex, felt_to_u64, snkeccak};
use crate::config::{Config, Home, Keys, is_current_store};
use crate::crypto::{
    kem_digest, leaf_v3, member_commit, nullifier_v4, send_v4, ticket_leaf, ticket_nullifier,
};
use crate::invoke_v3::{Bounds, Call, ResourceBounds, execute_calldata};
use crate::pipeline::PipelineEvent;
use crate::registry::Registry;
use crate::sequencer::{Gateway, GatewayError, ProofAttachment};
use crate::state::{SendState, StepKind, V4Binding};
use crate::tickets::{QuotaLog, TicketNotInTreeYet, TicketState, TicketTree, Wallet};
use crate::txpolicy::{self, TIP};
use crate::tree::fold_path;

/// The contracts a v4 send is bound to. The pool pins the prover; the
/// virtual sender is the shared account the proof runs from.
#[derive(Debug, Clone)]
pub struct VirtualRoute {
    /// The pool: store and publishing account in one.
    pub store: Felt,
    /// The contract whose virtual execution is proven.
    pub prover: Felt,
    pub virtual_sender: Felt,
    pub chain_id: Felt,
}

impl VirtualRoute {
    /// The route for `store`: only the current (v4 pool) store has one.
    pub fn for_store(store: &str) -> Option<Self> {
        use crate::config::{SEPOLIA_POOL_V4, SEPOLIA_V4_SEND_PROVER, SEPOLIA_V4_VIRTUAL_SENDER};
        is_current_store(store).then(|| Self {
            store: Felt::from_hex(SEPOLIA_POOL_V4).expect("constant"),
            prover: Felt::from_hex(SEPOLIA_V4_SEND_PROVER).expect("constant"),
            virtual_sender: Felt::from_hex(SEPOLIA_V4_VIRTUAL_SENDER).expect("constant"),
            chain_id: crate::invoke_v3::short_string("SN_SEPOLIA"),
        })
    }
}

// --- pure encodings the contracts must agree with ---------------------------

/// Everything a v4 proof makes public: the L2→L1 payload, in order.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicV4 {
    pub store: Felt,
    pub commitment: Felt,
    pub ephemeral: Felt,
    pub root: Felt,
    pub content_hash: Felt,
    pub nullifier: Felt,
    pub epoch: u64,
    pub quota: u32,
    pub ticket_root: Felt,
    pub ticket_nullifier: Felt,
}

impl PublicV4 {
    /// `[store, commitment, ephemeral_pubkey, merkle_root, content_hash,
    /// nullifier, epoch, quota, ticket_root, ticket_nullifier]`
    /// (`prover::send_payload_v4`).
    pub fn payload(&self) -> [Felt; 10] {
        [
            self.store,
            self.commitment,
            self.ephemeral,
            self.root,
            self.content_hash,
            self.nullifier,
            Felt::from(self.epoch),
            Felt::from(self.quota),
            self.ticket_root,
            self.ticket_nullifier,
        ]
    }

    /// The L2→L1 message hash the virtual OS writes into the facts:
    /// `poseidon([from = prover, to = 0, 10, ...payload])` (`facts::message_hash`).
    pub fn message_hash(&self, prover: Felt) -> Felt {
        let payload = self.payload();
        let mut fields = vec![prover, Felt::ZERO, Felt::from(payload.len() as u64)];
        fields.extend_from_slice(&payload);
        poseidon_hash_many(&fields)
    }

    fn binding(&self) -> V4Binding {
        V4Binding {
            nullifier: felt_hex(&self.nullifier),
            epoch: self.epoch,
            quota: self.quota,
            ticket_root: felt_hex(&self.ticket_root),
            ticket_nullifier: felt_hex(&self.ticket_nullifier),
        }
    }

    /// The tuple a saved send state recorded.
    fn from_state(store: Felt, state: &SendState, content: &[u8]) -> Result<Self> {
        let b = state.binding.as_ref().context("send state predates v4 (no binding)")?;
        Ok(Self {
            store,
            commitment: Felt::from_hex(&state.expected_commitment)?,
            ephemeral: Felt::from_hex(&state.expected_ephemeral_pubkey)?,
            root: Felt::from_hex(&state.expected_merkle_root)?,
            content_hash: content_hash(content),
            nullifier: Felt::from_hex(&b.nullifier)?,
            epoch: b.epoch,
            quota: b.quota,
            ticket_root: Felt::from_hex(&b.ticket_root)?,
            ticket_nullifier: Felt::from_hex(&b.ticket_nullifier)?,
        })
    }
}

/// The private half of `prove_send`.
pub struct WitnessV4<'a> {
    pub scan_pub: Felt,
    pub kem_digest: Felt,
    pub member_secret: Felt,
    pub slot: u32,
    pub leaf_index: u32,
    pub path: &'a [Felt],
    pub ticket_secret: Felt,
    pub ticket_index: u32,
    pub ticket_path: &'a [Felt],
}

/// v4 `prove_send` calldata: `(store, content_hash, commitment, E, root,
/// epoch, quota, ticket_root, sender_scan_pub, sender_kem_digest,
/// member_secret, slot, sender_leaf_index, sender_path, ticket_secret,
/// ticket_index, ticket_path)`. The nullifiers are not inputs: the prover
/// computes them from the secrets.
pub fn prove_send_calldata_v4(public: &PublicV4, w: &WitnessV4<'_>) -> Result<Vec<Felt>> {
    ensure!(w.path.len() == 20, "sender path has {} siblings, not 20", w.path.len());
    ensure!(w.ticket_path.len() == 20, "ticket path has {} siblings, not 20", w.ticket_path.len());
    ensure!(w.slot < public.quota, "slot {} is over the quota {}", w.slot, public.quota);
    let mut out = vec![
        public.store,
        public.content_hash,
        public.commitment,
        public.ephemeral,
        public.root,
        Felt::from(public.epoch),
        Felt::from(public.quota),
        public.ticket_root,
        w.scan_pub,
        w.kem_digest,
        w.member_secret,
        Felt::from(w.slot),
        Felt::from(w.leaf_index),
        Felt::from(20u64),
    ];
    out.extend_from_slice(w.path);
    out.push(w.ticket_secret);
    out.push(Felt::from(w.ticket_index));
    out.push(Felt::from(20u64));
    out.extend_from_slice(w.ticket_path);
    Ok(out)
}

/// The pool's `send_message(commitment, ephemeral_pubkey, merkle_root,
/// nullifier, ticket_root, ticket_nullifier, content: ByteArray)` arguments.
pub fn send_message_calldata_v4(public: &PublicV4, content: &[u8]) -> Result<Vec<Felt>> {
    let mut out = vec![
        public.commitment,
        public.ephemeral,
        public.root,
        public.nullifier,
        public.ticket_root,
        public.ticket_nullifier,
    ];
    for word in bytearray_calldata(content) {
        out.push(Felt::from_hex(&word)?);
    }
    Ok(out)
}

/// What the prover hands back: the proof as the gateway takes it (base64)
/// and the facts the transaction carries. Saved in the send's workdir.
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

/// `[PROOF1, VIRTUAL_SNOS, program_hash, VIRTUAL_SNOS0, block_number,
/// block_hash, os_config_hash, n_messages, message_hash]`.
const FACTS_LEN: usize = 9;
const FACT_BLOCK: usize = 4;
const FACT_N_MESSAGES: usize = 7;
const FACT_MESSAGE_HASH: usize = 8;

/// Poseidon over the Cairo serialization of the ciphertext `ByteArray` —
/// what the proof carries in the ciphertext's place (`pool::content_hash`).
pub fn content_hash(ciphertext: &[u8]) -> Felt {
    let felts: Vec<Felt> = bytearray_calldata(ciphertext)
        .iter()
        .map(|h| Felt::from_hex(h).expect("bytearray_calldata emits hex"))
        .collect();
    poseidon_hash_many(&felts)
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

/// Resource bounds of the virtual transaction. It is never charged (the
/// virtual sender refuses any nonzero price); the virtual OS only needs
/// amounts large enough to run it.
pub const VIRTUAL_BOUNDS: Bounds = Bounds {
    l1_gas: ResourceBounds { max_amount: 0, max_price_per_unit: 0 },
    l2_gas: ResourceBounds { max_amount: 0x700_0000, max_price_per_unit: 0 },
    l1_data_gas: ResourceBounds { max_amount: 0x1b0, max_price_per_unit: 0 },
};

/// The virtual invoke in RPC shape, as `starknet_proveTransaction` takes
/// it: from the shared virtual sender, at its base-block nonce, unsigned
/// (its `__validate__` accepts any signature and only zero fees).
pub fn virtual_invoke(virtual_sender: Felt, calls: &[Call], nonce: Felt) -> Value {
    let calldata = execute_calldata(calls);
    json!({
        "type": "INVOKE",
        "version": "0x3",
        "sender_address": felt_hex(&virtual_sender),
        "calldata": calldata.iter().map(felt_hex).collect::<Vec<_>>(),
        "nonce": felt_hex(&nonce),
        "resource_bounds": VIRTUAL_BOUNDS.rpc_json(),
        "tip": "0x0",
        "paymaster_data": [],
        "account_deployment_data": [],
        "nonce_data_availability_mode": "L1",
        "fee_data_availability_mode": "L1",
        "signature": [],
    })
}

/// The pool's fee policy (`fee_policy()`): its `__validate__` refuses a
/// publish whose worst-case fee exceeds `max_fee` (= at most the ticket
/// price), whose tip exceeds `max_tip`, or whose L2 gas bound is under
/// `min_l2_gas` (so execute can never run out of gas after the ticket burnt).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolFeePolicy {
    pub max_fee: u128,
    pub max_tip: u128,
    pub min_l2_gas: u64,
}

impl PoolFeePolicy {
    /// `fee_policy()` returns `(max_fee: u128, max_tip: u128, min_l2_gas: u64)`.
    pub fn from_felts(felts: &[Felt]) -> Result<Self> {
        ensure!(felts.len() == 3, "fee_policy returned {} felts, expected 3", felts.len());
        let u128_of = |f: &Felt| -> Result<u128> {
            let bytes = f.to_bytes_be();
            ensure!(bytes[..16].iter().all(|b| *b == 0), "fee policy value does not fit u128");
            Ok(u128::from_be_bytes(bytes[16..].try_into().expect("16 bytes")))
        };
        Ok(Self { max_fee: u128_of(&felts[0])?, max_tip: u128_of(&felts[1])?, min_l2_gas: felt_to_u64(&felts[2])? })
    }

    /// Publish bounds per the shared policy (`txpolicy::publish_bounds`).
    pub fn bounds(&self, prices: (u128, u128, u128)) -> Result<Bounds> {
        crate::txpolicy::publish_bounds(prices, self.max_fee, self.max_tip, self.min_l2_gas)
    }
}

/// Runs `snip36-prove` on one virtual transaction at `block`. The request
/// (the witness included) goes to the prover on stdin and nowhere else; the
/// prover's spill files are removed whatever happens.
pub fn run_prover(
    prover_bin: &Path,
    spill: &Path,
    out_path: &Path,
    rpc_url: &str,
    chain_id: &str,
    block: u64,
    transaction: Value,
) -> Result<VirtualProof> {
    fs::create_dir_all(spill)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(spill, fs::Permissions::from_mode(0o700))?;
    }
    let request = json!({
        "rpc_url": rpc_url,
        "chain_id": chain_id,
        "block_id": {"block_number": block},
        "transaction": transaction,
    });
    ensure!(
        prover_bin.exists(),
        "prover binary {} not found — build it (tools/snip36-phone-ffi/README.md) or set \
         \"virtual_prover_bin\" in config.json",
        prover_bin.display()
    );
    let mut child = Command::new(prover_bin)
        .arg(out_path)
        .env("ZKMSG_SPILL_DIR", spill)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", prover_bin.display()))?;
    {
        let mut stdin = child.stdin.take().context("prover stdin")?;
        stdin.write_all(request.to_string().as_bytes())?;
    }
    drop(request);
    let output = child.wait_with_output();
    // The spill files hold the prover's memory, witness included: gone
    // whatever happened.
    let _ = fs::remove_dir_all(spill);
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
    let out: Value = serde_json::from_str(&fs::read_to_string(out_path)?)?;
    let _ = fs::remove_file(out_path);
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

// --- the executor -----------------------------------------------------------

const PUBLISH_POLL: Duration = Duration::from_secs(5);
/// How often the scheduled publish re-reads the head while it waits.
const SCHEDULE_POLL: Duration = Duration::from_secs(6);
/// Prepare retries (× SCHEDULE_POLL) for a ticket younger than the base.
const TICKET_WAIT_TRIES: usize = 20;
const PUBLISH_TIMEOUT: Duration = Duration::from_secs(1800);
const TOO_RECENT_WAIT: Duration = Duration::from_secs(10);
const PUBLISH_ATTEMPTS: usize = 12;

/// The pool's `__validate__` reasons after which this proof can never land.
/// `ticket spent` is handled apart: the ticket is gone, not just the proof.
const FINAL_REFUSALS: [&str; 4] = ["nullifier spent", "envelope consumed", "stale epoch", "unknown merkle root"];

/// What Prepare hands Prove: the public tuple, the bytes to publish, and the
/// `prove_send` calldata — which IS the witness, so this never touches disk.
struct Prepared {
    id: String,
    block: u64,
    /// The virtual sender's nonce at `block`.
    nonce: Felt,
    public: PublicV4,
    /// The ByteArray `send_message` publishes: `kem_ct ‖ blob`.
    content: Vec<u8>,
    prove_calldata: Vec<Felt>,
}

/// A send's id: the commitment's first 10 hex digits.
fn send_id(commitment: &Felt) -> String {
    format!("{:.10}", felt_hex(commitment).trim_start_matches("0x"))
}

pub struct VirtualSender<'a> {
    pub home: &'a Home,
    pub route: VirtualRoute,
    /// Every read goes through the prover's RPC, so the block the trees are
    /// read at is a block the prover can fetch storage proofs for.
    pub chain: Chain,
    pub gateway: Gateway,
    pub prover_bin: PathBuf,
}

impl<'a> VirtualSender<'a> {
    pub fn new(home: &'a Home, config: &Config) -> Result<Self> {
        let route = VirtualRoute::for_store(&config.store).with_context(|| {
            format!("{} is not the v4 pool — `zkmsg migrate-store` moves this profile", config.store)
        })?;
        Ok(Self {
            home,
            route,
            chain: Chain::new(config.prover_rpc_url(), &config.account),
            gateway: Gateway::sepolia(),
            prover_bin: config.virtual_prover_bin(),
        })
    }

    fn store_hex(&self) -> String {
        felt_hex(&self.route.store)
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

        // 1. Prepare, all at one block. Takes a quota slot and reserves a ticket.
        sink(PipelineEvent::StepStarted { index: 0, total, kind: StepKind::Prepare });
        // A ticket bought moments ago enters the tree after the base block:
        // wait for the base to catch up (≈1 min) rather than fail.
        let mut tries = 0;
        let p = loop {
            match self.prepare(keys, handle, text) {
                Err(e) if tries < TICKET_WAIT_TRIES && e.downcast_ref::<TicketNotInTreeYet>().is_some() => {
                    tries += 1;
                    std::thread::sleep(SCHEDULE_POLL);
                }
                other => break other?,
            }
        };
        let block = p.block;
        let mut state = SendState::new_virtual_plan(
            p.id.clone(),
            handle.to_string(),
            hex::encode(&p.content),
            (felt_hex(&p.public.commitment), felt_hex(&p.public.ephemeral), felt_hex(&p.public.root)),
            block,
        );
        state.binding = Some(p.public.binding());
        state.publish_after_block = Some(txpolicy::publish_after(block, txpolicy::jitter()));
        state.mark_done(0, None, Some(format!("block {block}, epoch {}", p.public.epoch)));
        sink(PipelineEvent::StepCompleted { kind: StepKind::Prepare, tx_hash: None, note: None });

        // 2. Prove. The witness rides in the virtual transaction's calldata,
        //    handed to the prover on stdin and dropped after. A failure here
        //    hands the ticket back: no proof of it exists.
        sink(PipelineEvent::StepStarted { index: 1, total, kind: StepKind::Prove });
        let public = p.public;
        if let Err(e) = self.prove_and_save(&mut state, p) {
            self.release_ticket(&public);
            return Err(e);
        }
        sink(PipelineEvent::Checkpointed { id: state.id.clone() });
        sink(PipelineEvent::StepCompleted { kind: StepKind::Prove, tx_hash: None, note: None });

        // 3. Publish, from the pool.
        self.publish(&mut state, sink)?;
        Ok(state)
    }

    fn prove_and_save(&self, state: &mut SendState, p: Prepared) -> Result<()> {
        let Prepared { nonce, public, prove_calldata, block, .. } = p;
        let call = Call::new(self.route.prover, "prove_send", prove_calldata);
        let transaction = virtual_invoke(self.route.virtual_sender, &[call], nonce);
        let started = Instant::now();
        let workdir = SendState::workdir(self.home, &state.id);
        fs::create_dir_all(&workdir)?;
        let proof = run_prover(
            &self.prover_bin,
            &self.home.dir.join("spill"),
            &workdir.join("prover_out.json"),
            &self.chain.rpc_url,
            &crate::invoke_v3::short_string_text(&self.route.chain_id)?,
            block,
            transaction,
        )?;
        check_facts(&proof.facts()?, public.message_hash(self.route.prover), block)?;
        fs::write(self.proof_path(state), serde_json::to_string(&proof)?)?;
        state.mark_done(
            1,
            None,
            Some(format!("{:.0} s, {} b64 bytes, facts verified", started.elapsed().as_secs_f64(), proof.proof.len())),
        );
        state.save(self.home)
    }

    /// Both members, the sender's path and the ticket's path come from
    /// events, rebuilt locally: no read names a handle, a leaf or a ticket,
    /// so the RPC can't tell who is sending to whom, or with which ticket.
    fn prepare(&self, keys: &Keys, handle: &str, text: &str) -> Result<Prepared> {
        let sender_handle = keys.handle.as_deref().context("not registered — run `zkmsg register`")?;
        // Refuse an over-long message before any slot or ticket is taken.
        crate::crypto::pad_v4(text.as_bytes())?;
        let scan_pub = keys.scan_pub_felt()?;
        let own_digest = kem_digest(&keys.kem_keypair()?.1);
        let member_secret = keys.member_secret_felt()?;
        let own_m_commit = member_commit(&member_secret);

        let (block, registry, root, tickets) = self.pinned_state()?;
        let recipient = registry.get(handle)?;
        let sender = registry.get(sender_handle)?;
        ensure!(
            sender.scan_pub == scan_pub
                && sender.kem_digest == own_digest
                && sender.m_commit == own_m_commit,
            "'{sender_handle}' is registered to different keys in this store",
        );
        let sender_path = registry.path(sender.leaf_index)?;
        ensure!(
            fold_path(&leaf_v3(&scan_pub, &own_digest, &own_m_commit), sender.leaf_index, &sender_path)
                == root,
            "sender path does not fold to the root at block {block}",
        );

        let store = self.store_hex();
        let mut wallet = Wallet::load(self.home, &store)?;
        if wallet.settle(&tickets)? > 0 {
            wallet.save(self.home)?;
        }
        let ti = match wallet.pick(&tickets) {
            Ok(ti) => ti,
            // Nothing usable at the base block, but a purchase is pending: it
            // may be newer than the base and only in the latest tree. Settle
            // it there so `pick` reports "not yet" (which `send` waits on)
            // instead of "no ticket". Same all-purchases event query.
            Err(_) if wallet.counts().pending > 0 => {
                if wallet.settle(&TicketTree::fetch(&self.chain, &store, None)?)? > 0 {
                    wallet.save(self.home)?;
                }
                wallet.pick(&tickets)?
            }
            Err(e) => return Err(e),
        };
        let ticket_secret = wallet.tickets[ti].secret_felt()?;
        let ticket_index = wallet.tickets[ti].index.context("picked ticket has no index")?;
        let ticket_path = tickets.path(ticket_index)?;
        ensure!(
            fold_path(&ticket_leaf(&ticket_secret), ticket_index, &ticket_path) == tickets.root(),
            "ticket path does not fold to the ticket root at block {block}",
        );

        let (epoch_blocks, _, quota) = self.rate_limit(block)?;
        let epoch = block / epoch_blocks;
        let nonce = self.virtual_nonce(block)?;
        let slot = QuotaLog::take_slot(self.home, &store, epoch, quota)?;

        let sealed = send_v4(&recipient.scan_pub, &recipient.kem_pubkey, text.as_bytes())?;
        let public = PublicV4 {
            store: self.route.store,
            commitment: sealed.commitment,
            ephemeral: sealed.ephemeral_pub,
            root,
            content_hash: sealed.content_hash,
            nullifier: nullifier_v4(&self.route.store, &member_secret, epoch, slot),
            epoch,
            quota,
            ticket_root: tickets.root(),
            ticket_nullifier: ticket_nullifier(&self.route.store, &ticket_secret),
        };
        let prove_calldata = prove_send_calldata_v4(
            &public,
            &WitnessV4 {
                scan_pub,
                kem_digest: own_digest,
                member_secret,
                slot,
                leaf_index: sender.leaf_index,
                path: &sender_path,
                ticket_secret,
                ticket_index,
                ticket_path: &ticket_path,
            },
        )?;
        let id = send_id(&sealed.commitment);
        wallet.tickets[ti].state = TicketState::Reserved { send_id: id.clone() };
        wallet.save(self.home)?;
        Ok(Prepared { id, block, nonce, public, content: sealed.content, prove_calldata })
    }

    /// Pins block N, rebuilds both trees from every registration and every
    /// ticket purchase up to N, and checks them against the store's roots
    /// at N — requests every client makes alike. A mismatch (an RPC whose
    /// event index trails its state) is retried once at a fresh block, then
    /// refused: a witness against the wrong tree would only fail after
    /// minutes of proving.
    fn pinned_state(&self) -> Result<(u64, Registry, Felt, TicketTree)> {
        let store = self.store_hex();
        let mut mismatch = String::new();
        for _ in 0..2 {
            // The shared schedule's base: a multiple of 32, ≥ 10 behind the head.
            let block = txpolicy::base_block(self.block_number()?);
            let registry = Registry::fetch(&self.chain, &store, Some(block))?;
            let root = self.store_felt("get_merkle_root", &[], Some(block))?;
            let tickets = TicketTree::fetch(&self.chain, &store, Some(block))?;
            let ticket_root = self.store_felt("get_ticket_root", &[], Some(block))?;
            if registry.root() == root && tickets.root() == ticket_root {
                return Ok((block, registry, root, tickets));
            }
            mismatch = format!(
                "up to block {block}: {} registrations rebuild root {} (store: {}), {} tickets \
                 rebuild {} (store: {})",
                registry.len(),
                felt_hex(&registry.root()),
                felt_hex(&root),
                tickets.len(),
                felt_hex(&tickets.root()),
                felt_hex(&ticket_root),
            );
        }
        bail!("the local trees disagree with the store ({mismatch}); the RPC's event index may be behind — try again shortly")
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
        let content = hex::decode(&state.ciphertext_hex)?;
        let public = PublicV4::from_state(self.route.store, state, &content)?;

        // A hash saved by an earlier attempt is settled before anything is
        // built. Landed or still in flight: wait for it. Reverted: the
        // ticket burnt in validate and the send is over. Only an explicit
        // drop (never received, or rejected before execution) falls through,
        // and then to the IDENTICAL transaction (saved nonce + bounds).
        if let Some(saved) = state.steps[index].tx_hash.clone() {
            let hash = Felt::from_hex(&saved)?;
            let status = self.gateway.status(&hash)?;
            if status.is_reverted() {
                self.spend_ticket(&public, Some(saved.clone()));
                self.retire(state)?;
                bail!(
                    "publish {saved} reverted ({}); its ticket is spent — send again",
                    status.revert_reason.as_deref().unwrap_or("no reason")
                );
            }
            if !status.is_dropped() || !self.rpc_agrees_dropped(&hash) {
                return self.await_and_finish(state, index, &public, hash, sink);
            }
        }

        // The shared schedule: never before base + 90..110 blocks, however
        // fast this device proved.
        if let Some(target) = state.publish_after_block {
            wait_for_head(target, || self.block_number(), std::thread::sleep, SCHEDULE_POLL, sink)?;
        }

        let known = self.store_felt("is_known_root", &[public.root], None)?;
        if known != Felt::ONE {
            self.release_ticket(&public);
            self.retire(state)?;
            bail!(
                "the member tree moved on since this send was proven (root {} is no longer known \
                 to the store); send again to re-prove",
                state.expected_merkle_root
            );
        }

        let proof: VirtualProof = serde_json::from_str(
            &fs::read_to_string(self.proof_path(state)).context("reading the saved proof")?,
        )?;
        let facts = proof.facts()?;
        // The saved proof must still attest exactly this send (a swapped or
        // corrupted file would burn the ticket for nothing).
        check_facts(
            &facts,
            public.message_hash(self.route.prover),
            state.base_block.context("state has no base block")?,
        )?;

        let call = Call::new(self.route.store, "send_message", send_message_calldata_v4(&public, &content)?);
        let attachment = ProofAttachment { proof: &proof.proof, proof_facts: &facts };
        let (mut nonce, bounds) = match (&state.publish_nonce, state.publish_bounds) {
            (Some(nonce), Some(bounds)) => (Felt::from_hex(nonce)?, bounds),
            _ => self.publish_inputs()?,
        };
        for attempt in 0..PUBLISH_ATTEMPTS {
            let last = attempt + 1 == PUBLISH_ATTEMPTS;
            let tx = self.gateway.unsigned_invoke(
                self.route.store,
                std::slice::from_ref(&call),
                nonce,
                bounds,
                TIP,
                Some(&attachment),
            );
            let hex = felt_hex(&tx.hash);
            // Recorded BEFORE the POST: whatever happens to the request, a
            // resume knows the one hash this send may have produced.
            state.record_submission(index, hex.clone());
            state.publish_nonce = Some(felt_hex(&nonce));
            state.publish_bounds = Some(bounds);
            state.save(self.home)?;

            let err = match self.gateway.submit(&tx) {
                Ok(()) => {
                    sink(PipelineEvent::TxSubmitted { kind: StepKind::Publish, tx_hash: hex.clone() });
                    return self.await_and_finish(state, index, &public, tx.hash, sink);
                }
                Err(e) => e,
            };
            let Some(gateway) = err.downcast_ref::<GatewayError>().cloned() else {
                // Timeout, 5xx, a hash mismatch: the gateway may hold the
                // transaction. Stop; the saved hash is polled on resume.
                return Err(err);
            };
            if !matches!(gateway, GatewayError::Rejected { .. }) {
                return Err(err);
            }
            if !last && gateway.too_recent() {
                // Same transaction again once the base block is old enough.
                std::thread::sleep(TOO_RECENT_WAIT);
                continue;
            }
            if gateway.refused_with("ticket spent") {
                self.spend_ticket(&public, None);
                self.retire(state)?;
                return Err(err.context("the pool says this send's ticket is already spent — send again"));
            }
            if let Some(reason) = FINAL_REFUSALS.iter().find(|r| gateway.refused_with(r)) {
                self.release_ticket(&public);
                self.retire(state)?;
                return Err(err.context(format!("the pool refused this proof ({reason}) — send again")));
            }
            if !last && is_nonce_rejection(&gateway) {
                // Another send took this pool nonce. If it was THIS send (an
                // earlier attempt the gateway did take), finish instead.
                let status = self.gateway.status(&tx.hash)?;
                if !status.is_dropped() || !self.rpc_agrees_dropped(&tx.hash) {
                    return self.await_and_finish(state, index, &public, tx.hash, sink);
                }
                // Same proof, next nonce: no re-proving.
                nonce = next_nonce(nonce, gateway.expected_nonce(), self.pool_nonce()?);
                continue;
            }
            return Err(err);
        }
        bail!("publish retries exhausted")
    }

    /// The pool's nonce and policy bounds for a first publish attempt.
    fn publish_inputs(&self) -> Result<(Felt, Bounds)> {
        let policy = PoolFeePolicy::from_felts(&self.store_call("fee_policy", &[], None)?)?;
        Ok((self.pool_nonce()?, policy.bounds(self.chain.gas_prices()?)?))
    }

    fn await_and_finish(
        &self,
        state: &mut SendState,
        index: usize,
        public: &PublicV4,
        hash: Felt,
        sink: &mut dyn FnMut(PipelineEvent),
    ) -> Result<()> {
        let tx_hash = felt_hex(&hash);
        if let Err(e) = self.gateway.await_acceptance(&hash, PUBLISH_POLL, PUBLISH_TIMEOUT) {
            if matches!(e.downcast_ref::<GatewayError>(), Some(GatewayError::Reverted { .. })) {
                // Validate burnt the ticket before execute reverted.
                self.spend_ticket(public, Some(tx_hash));
                self.retire(state)?;
            }
            return Err(e);
        }
        self.spend_ticket(public, Some(tx_hash.clone()));
        state.mark_done(index, Some(tx_hash.clone()), Some("message published by the pool".into()));
        state.save(self.home)?;
        sink(PipelineEvent::StepCompleted { kind: StepKind::Publish, tx_hash: Some(tx_hash), note: None });
        sink(PipelineEvent::Completed);
        Ok(())
    }

    /// Wallet bookkeeping is best effort: a failure here must not hide the
    /// send's own outcome (the wallet re-settles against the chain later).
    fn spend_ticket(&self, public: &PublicV4, tx: Option<String>) {
        if let Ok(mut wallet) = Wallet::load(self.home, &self.store_hex()) {
            if wallet.mark_spent(&public.store, &public.ticket_nullifier, tx) {
                let _ = wallet.save(self.home);
            }
        }
    }

    fn release_ticket(&self, public: &PublicV4) {
        if let Ok(mut wallet) = Wallet::load(self.home, &self.store_hex()) {
            if wallet.release(&public.store, &public.ticket_nullifier) {
                let _ = wallet.save(self.home);
            }
        }
    }

    /// Second opinion before anything is resubmitted under a new nonce: the
    /// feeder can lag, so a transaction counts as dropped only if the RPC
    /// doesn't know it either. Any doubt (an RPC error included) says "not
    /// dropped", which waits instead of resubmitting.
    fn rpc_agrees_dropped(&self, hash: &Felt) -> bool {
        match self.chain.rpc("starknet_getTransactionStatus", json!([felt_hex(hash)])) {
            Ok(v) => matches!(v["finality_status"].as_str(), Some("REJECTED")),
            // TXN_HASH_NOT_FOUND (code 29) is the RPC's "never seen it".
            Err(e) => format!("{e:#}").contains("\"code\":29"),
        }
    }

    /// Takes a stale send out of the pending list: its proof can never be
    /// published. Renamed, not deleted, so the record survives.
    fn retire(&self, state: &SendState) -> Result<()> {
        let path = SendState::path(self.home, &state.id);
        fs::rename(&path, path.with_extension("stale"))
            .with_context(|| format!("retiring {}", path.display()))
    }

    fn proof_path(&self, state: &SendState) -> PathBuf {
        SendState::workdir(self.home, &state.id).join("virtual_proof.json")
    }

    // --- reads (all through the prover's RPC; none names a member) --------

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

    fn store_call(&self, entrypoint: &str, calldata: &[Felt], block: Option<u64>) -> Result<Vec<Felt>> {
        let v = self.chain.rpc(
            "starknet_call",
            json!([
                {
                    "contract_address": felt_hex(&self.route.store),
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

    fn store_felt(&self, entrypoint: &str, calldata: &[Felt], block: Option<u64>) -> Result<Felt> {
        self.store_call(entrypoint, calldata, block)?
            .first()
            .copied()
            .with_context(|| format!("{entrypoint} returned nothing"))
    }

    /// `rate_limit()` at `block`: (epoch_blocks, max_epoch_lag, quota).
    fn rate_limit(&self, block: u64) -> Result<(u64, u64, u32)> {
        let v = self.store_call("rate_limit", &[], Some(block))?;
        ensure!(v.len() == 3, "rate_limit returned {} felts", v.len());
        let epoch_blocks = felt_to_u64(&v[0])?;
        ensure!(epoch_blocks != 0, "rate_limit: zero epoch");
        Ok((epoch_blocks, felt_to_u64(&v[1])?, u32::try_from(felt_to_u64(&v[2])?)?))
    }

    fn nonce_of(&self, address: Felt, block: Option<u64>) -> Result<Felt> {
        let v = self.chain.rpc("starknet_getNonce", json!([Self::block_id(block), felt_hex(&address)]))?;
        Felt::from_hex(v.as_str().with_context(|| format!("starknet_getNonce: {v}"))?).context("nonce")
    }

    /// The shared virtual sender's nonce at the base block (0: it can never
    /// transact for real).
    fn virtual_nonce(&self, block: u64) -> Result<Felt> {
        self.nonce_of(self.route.virtual_sender, Some(block))
    }

    fn pool_nonce(&self) -> Result<Felt> {
        self.nonce_of(self.route.store, None)
    }
}

/// Waits until `head()` reaches `target`, reporting the wait once.
fn wait_for_head(
    target: u64,
    mut head: impl FnMut() -> Result<u64>,
    mut sleep: impl FnMut(Duration),
    poll: Duration,
    sink: &mut dyn FnMut(PipelineEvent),
) -> Result<()> {
    let mut reported = false;
    loop {
        let now = head()?;
        if now >= target {
            return Ok(());
        }
        if !reported {
            sink(PipelineEvent::Waiting { until_block: target, blocks_left: target - now });
            reported = true;
        }
        sleep(poll);
    }
}

/// A rejection over the pool's nonce: stale (`INVALID_TRANSACTION_NONCE`) or
/// already taken by a pending send (a duplicate in the mempool).
fn is_nonce_rejection(e: &GatewayError) -> bool {
    matches!(e, GatewayError::Rejected { code, message }
        if code.contains("NONCE") || message.to_ascii_lowercase().contains("nonce"))
}

/// The nonce to retry at: the one the gateway names, else the chain's,
/// and always past the one just refused.
fn next_nonce(refused: Felt, expected: Option<u64>, chain: Felt) -> Felt {
    let candidate = expected.map(Felt::from).unwrap_or(chain);
    if candidate > refused { candidate } else { refused + Felt::ONE }
}

/// Masks long hex runs in a prover log line: if the prover ever echoed its
/// request, the witness (membership and ticket secrets) must not reach the UI.
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

#[cfg(test)]
mod tests {
    use super::*;

    fn felts(v: &Value) -> Vec<Felt> {
        v.as_array().unwrap().iter().map(|x| Felt::from_hex(x.as_str().unwrap()).unwrap()).collect()
    }

    /// The real phone send in testdata (SNIP-36 v1 store): its facts attest
    /// the message hash recomputed from its own public calldata. Pins the
    /// facts layout and the message-hash rule, which v4 keeps (only the
    /// payload grew).
    #[test]
    fn live_send_facts_check_out() {
        let tx: Value = serde_json::from_str(include_str!("../testdata/snip36_send_tx.json")).unwrap();
        let calldata = felts(&tx["calldata"]);
        let facts = felts(&tx["proof_facts"]);
        let store = Felt::from_hex("0x002b9c6f617b3197dfed76401c32aa3b4b597ebdd01a7eba4b5657236bc8084f").unwrap();
        let prover = Felt::from_hex("0x012b85a4b5e6918eb6f18a07fddc1667d67beaac0ab647928105b8ccf7ee5346").unwrap();
        assert_eq!(calldata[1], store);
        // send_message args: commitment, ephemeral, root, then the ciphertext
        // ByteArray, whose serialization is exactly what content_hash hashes.
        let args = &calldata[4..];
        let content = poseidon_hash_many(&args[3..]);
        let (bytes, consumed) = crate::chain::bytearray_decode(&args[3..]).unwrap();
        assert_eq!(consumed, args.len() - 3);
        assert_eq!(content_hash(&bytes), content);

        let expected = poseidon_hash_many(&[prover, Felt::ZERO, Felt::from(5u64), store, args[0], args[1], args[2], content]);
        let block = crate::chain::felt_to_u64(&facts[FACT_BLOCK]).unwrap();
        check_facts(&facts, expected, block).unwrap();
        // Any other block, or any other message, is refused.
        assert!(check_facts(&facts, expected, block + 1).is_err());
        assert!(check_facts(&facts, Felt::ONE, block).is_err());
        assert!(check_facts(&facts[..8], expected, block).is_err());
    }

    #[test]
    fn virtual_invoke_is_unsigned_zero_fee_from_the_shared_sender() {
        let route = VirtualRoute::for_store(crate::config::SEPOLIA_POOL_V4).unwrap();
        let call = Call::new(route.prover, "prove_send", vec![Felt::ONE]);
        let tx = virtual_invoke(route.virtual_sender, &[call.clone()], Felt::ZERO);
        assert_eq!(tx["sender_address"], felt_hex(&route.virtual_sender));
        assert_eq!(tx["signature"], json!([]));
        assert_eq!(tx["nonce"], "0x0");
        assert_eq!(felts(&tx["calldata"]), execute_calldata(&[call]));
        for r in ["l1_gas", "l2_gas", "l1_data_gas"] {
            assert_eq!(tx["resource_bounds"][r]["max_price_per_unit"], "0x0", "{r} must be free");
        }
        assert_eq!(tx["tip"], "0x0");
    }

    fn sample_public() -> PublicV4 {
        PublicV4 {
            store: Felt::from(1u64),
            commitment: Felt::from(2u64),
            ephemeral: Felt::from(3u64),
            root: Felt::from(4u64),
            content_hash: Felt::from(5u64),
            nullifier: Felt::from(6u64),
            epoch: 7,
            quota: 8,
            ticket_root: Felt::from(9u64),
            ticket_nullifier: Felt::from(10u64),
        }
    }

    #[test]
    fn v4_calldata_layouts() {
        let public = sample_public();
        let path: Vec<Felt> = (100..120u64).map(Felt::from).collect();
        let tpath: Vec<Felt> = (200..220u64).map(Felt::from).collect();
        let w = WitnessV4 {
            scan_pub: Felt::from(11u64),
            kem_digest: Felt::from(12u64),
            member_secret: Felt::from(13u64),
            slot: 3,
            leaf_index: 5,
            path: &path,
            ticket_secret: Felt::from(14u64),
            ticket_index: 6,
            ticket_path: &tpath,
        };
        let out = prove_send_calldata_v4(&public, &w).unwrap();
        let head: Vec<Felt> = [1u64, 5, 2, 3, 4, 7, 8, 9, 11, 12, 13, 3, 5, 20].into_iter().map(Felt::from).collect();
        assert_eq!(&out[..14], &head[..]);
        assert_eq!(&out[14..34], &path[..]);
        assert_eq!(&out[34..37], &[Felt::from(14u64), Felt::from(6u64), Felt::from(20u64)]);
        assert_eq!(&out[37..], &tpath[..]);
        assert!(prove_send_calldata_v4(&public, &WitnessV4 { slot: 8, ..w }).is_err(), "slot must be < quota");
        assert!(prove_send_calldata_v4(&public, &WitnessV4 { slot: 0, path: &path[..19], ..w }).is_err());

        let send = send_message_calldata_v4(&public, b"hi").unwrap();
        let want: Vec<Felt> = [2u64, 3, 4, 6, 9, 10, 0, 0x6869, 2].into_iter().map(Felt::from).collect();
        assert_eq!(send, want);
        assert_eq!(public.payload()[6], Felt::from(7u64));
    }

    #[test]
    fn pool_fee_policy_reads_and_bounds() {
        let policy = PoolFeePolicy { max_fee: 3_000_000_000_000_000_000, max_tip: 1_000_000_000, min_l2_gas: 100_000_000 };
        assert_eq!(
            PoolFeePolicy::from_felts(&[Felt::from(policy.max_fee), Felt::from(policy.max_tip), Felt::from(policy.min_l2_gas)]).unwrap(),
            policy
        );
        let b = policy.bounds((52_616_363_968_810, 18_090_898_182, 52_616)).unwrap();
        assert_eq!(b, txpolicy::bounds(txpolicy::TxKind::Publish, (52_616_363_968_810, 18_090_898_182, 52_616)));
    }

    #[test]
    fn the_publish_waits_for_its_block() {
        let heads = std::cell::RefCell::new(vec![100u64, 104, 109, 110, 111]);
        let mut slept = 0;
        let mut events = vec![];
        wait_for_head(
            110,
            || Ok(heads.borrow_mut().remove(0)),
            |_| slept += 1,
            Duration::ZERO,
            &mut |e| events.push(e),
        )
        .unwrap();
        assert_eq!(slept, 3);
        assert_eq!(events.len(), 1, "reported once");
        assert!(matches!(events[0], PipelineEvent::Waiting { until_block: 110, blocks_left: 10 }));
        // Already past: no wait, no event.
        let mut events = vec![];
        wait_for_head(110, || Ok(200), |_| panic!("no sleep"), Duration::ZERO, &mut |e| events.push(e)).unwrap();
        assert!(events.is_empty());
    }

    #[test]
    fn nonce_retry_always_moves_forward() {
        let n = |x: u64| Felt::from(x);
        assert_eq!(next_nonce(n(5), Some(7), n(6)), n(7));
        assert_eq!(next_nonce(n(5), None, n(6)), n(6));
        assert_eq!(next_nonce(n(5), Some(5), n(5)), n(6), "pending duplicate: queue behind it");
        assert_eq!(next_nonce(n(5), None, n(3)), n(6));
        let dup = GatewayError::Rejected { code: "StarknetErrorCode.DUPLICATED_TRANSACTION".into(), message: "nonce already used".into() };
        assert!(is_nonce_rejection(&dup));
        let other = GatewayError::Rejected { code: "StarknetErrorCode.VALIDATE_FAILURE".into(), message: "stale epoch".into() };
        assert!(!is_nonce_rejection(&other));
    }

    // --- prepare against a fake pool ----------------------------------------

    /// One profile of the fake store: keys.json plus its registration event.
    fn profile(handle: &str, seed: u8, leaf_index: u32) -> (Keys, (Vec<String>, Vec<String>)) {
        let scan_priv = Felt::from(seed as u64 + 100);
        let scan_pub = crate::crypto::ec_mul_gen_x(&scan_priv);
        let mut m = [seed; 32];
        m[0] = 0;
        let keys = Keys {
            scan_priv: felt_hex(&scan_priv),
            scan_pub: felt_hex(&scan_pub),
            handle: Some(handle.into()),
            leaf_index: Some(leaf_index),
            kem_seed: Some(crate::config::kem_seed_hex(&[seed; 64])),
            member_secret: Some(crate::config::member_secret_hex(&m)),
        };
        let ek = keys.kem_keypair().unwrap().1;
        let m_commit = member_commit(&keys.member_secret_felt().unwrap());
        let event = crate::registry::tests::event(
            Felt::from(0x5000 + seed as u64), handle, scan_pub, leaf_index, m_commit, &ek,
        );
        (keys, event)
    }

    type Log = std::sync::Arc<std::sync::Mutex<Vec<(String, Value)>>>;

    const BLOCK: u64 = 16_000_123;
    /// `txpolicy::base_block(BLOCK)`.
    const BASE: u64 = 16_000_096;
    const EPOCH_BLOCKS: u64 = 5_000;
    const QUOTA: u32 = 2;

    struct Fake {
        members: Vec<(Vec<String>, Vec<String>)>,
        tickets: Vec<(Vec<String>, Vec<String>)>,
        /// `get_merkle_root` answers, one per call, the last repeating.
        roots: Vec<Felt>,
        ticket_root: Felt,
        /// The latest ticket tree, when it differs from the base block's.
        latest_tickets: Option<Vec<(Vec<String>, Vec<String>)>>,
    }

    /// A sender whose RPC is a fake v4 pool at block `BLOCK`. Every request
    /// is recorded.
    fn fake_sender<'a>(home: &'a Home, fake: Fake) -> (VirtualSender<'a>, Log) {
        let log: Log = Default::default();
        let roots = std::sync::Mutex::new(fake.roots);
        let record = log.clone();
        let route = VirtualRoute::for_store(crate::config::SEPOLIA_POOL_V4).unwrap();
        let vsender = felt_hex(&route.virtual_sender);
        let transport: crate::chain::Transport = std::sync::Arc::new(move |method: &str, params: &Value| {
            record.lock().unwrap().push((method.to_string(), params.clone()));
            let as_events = |evs: &Vec<(Vec<String>, Vec<String>)>| {
                let events: Vec<Value> = evs.iter().map(|(k, d)| json!({"keys": k, "data": d})).collect();
                json!({"events": events})
            };
            Ok(match method {
                "starknet_blockNumber" => json!(BLOCK),
                "starknet_getEvents" => {
                    let key = params[0]["keys"][0][0].as_str().unwrap().to_string();
                    // Pending purchases are also settled against the latest
                    // ticket tree; every other read stops at the base block.
                    let latest_tickets = key == felt_hex(&snkeccak("TicketBought"))
                        && params[0]["to_block"] == json!("latest");
                    if !latest_tickets {
                        assert_eq!(params[0]["to_block"], json!({"block_number": BASE}), "events must stop at N");
                    }
                    if key == felt_hex(&snkeccak("UserRegistered")) {
                        as_events(&fake.members)
                    } else if key == felt_hex(&snkeccak("TicketBought")) {
                        match (&fake.latest_tickets, latest_tickets) {
                            (Some(latest), true) => as_events(latest),
                            _ => as_events(&fake.tickets),
                        }
                    } else {
                        anyhow::bail!("unexpected event filter {key}")
                    }
                }
                "starknet_call" => {
                    let selector = params[0]["entry_point_selector"].as_str().unwrap().to_string();
                    if selector == felt_hex(&snkeccak("get_merkle_root")) {
                        let mut roots = roots.lock().unwrap();
                        let root = if roots.len() > 1 { roots.remove(0) } else { roots[0] };
                        json!([felt_hex(&root)])
                    } else if selector == felt_hex(&snkeccak("get_ticket_root")) {
                        json!([felt_hex(&fake.ticket_root)])
                    } else if selector == felt_hex(&snkeccak("rate_limit")) {
                        json!([felt_hex(&Felt::from(EPOCH_BLOCKS)), "0x1", felt_hex(&Felt::from(QUOTA))])
                    } else {
                        anyhow::bail!("unexpected call {selector}")
                    }
                }
                "starknet_getNonce" => {
                    assert_eq!(params[1], json!(vsender), "only the virtual sender's nonce is read");
                    json!("0x0")
                }
                other => anyhow::bail!("unexpected rpc {other}"),
            })
        });
        let sender = VirtualSender {
            home,
            route,
            chain: Chain::with_transport("fake://rpc", "unused", transport),
            gateway: Gateway::sepolia(),
            prover_bin: PathBuf::from("/nonexistent"),
        };
        (sender, log)
    }

    struct World {
        alice: Keys,
        home: Home,
        fake: Fake,
        /// alice's ticket leaves in the tree (at indices 1 and 2).
        ticket_leaves: Vec<Felt>,
    }

    /// alice, bob, carol registered; alice holds two bought tickets (one
    /// stranger's ticket sits before them) and one whose purchase never landed.
    fn world(tag: &str) -> World {
        let home = Home::new(std::env::temp_dir().join(format!("zkmsg-v4-{tag}-{}", std::process::id())));
        let _ = fs::remove_dir_all(&home.dir);
        fs::create_dir_all(&home.dir).unwrap();
        let (alice, a) = profile("alice", 0x11, 0);
        let (_, b) = profile("bob", 0x22, 1);
        let (_, c) = profile("carol", 0x33, 2);
        let members = vec![a, b, c];
        let root = Registry::from_events(&members).unwrap().root();

        let mut wallet = Wallet::load(&home, crate::config::SEPOLIA_POOL_V4).unwrap();
        let leaves = wallet.mint(3).unwrap();
        wallet.save(&home).unwrap();
        let tickets = vec![
            crate::tickets::tests::event(Felt::from(0x5157u64), 0),
            crate::tickets::tests::event(leaves[0], 1),
            crate::tickets::tests::event(leaves[1], 2),
        ];
        let ticket_root = TicketTree::from_events(&tickets).unwrap().root();
        World {
            alice,
            home,
            fake: Fake { members, tickets, roots: vec![root], ticket_root, latest_tickets: None },
            ticket_leaves: leaves[..2].to_vec(),
        }
    }

    /// The send path names no handle, no leaf, no ticket and no account of
    /// the user's to the RPC: its only requests are the head block, ALL
    /// registrations and ALL ticket purchases (filtered by event selector
    /// alone), the two roots and the rate limit (no calldata), and the
    /// SHARED virtual sender's nonce.
    #[test]
    fn prepare_reads_name_no_handle_leaf_ticket_or_account() {
        let w = world("egress");
        let (sender, log) = fake_sender(&w.home, w.fake);
        let p = sender.prepare(&w.alice, "carol", "hi carol").unwrap();
        assert_eq!(p.block, BASE, "proved on the schedule's base block");
        assert_eq!(p.public.epoch, BASE / EPOCH_BLOCKS);
        assert_eq!(p.public.quota, QUOTA);
        // The witness: alice's leaf 0, slot 0, ticket at index 1.
        assert_eq!(p.prove_calldata[11], Felt::ZERO, "slot");
        assert_eq!(p.prove_calldata[12], Felt::ZERO, "leaf index");
        assert_eq!(p.prove_calldata[35], Felt::ONE, "ticket index");
        let member_secret = w.alice.member_secret_felt().unwrap();
        assert_eq!(p.public.nullifier, nullifier_v4(&sender.route.store, &member_secret, p.public.epoch, 0));

        // The ticket is reserved for this send; the next one is the other.
        let wallet = Wallet::load(&w.home, crate::config::SEPOLIA_POOL_V4).unwrap();
        assert_eq!(wallet.tickets[0].state, TicketState::Reserved { send_id: p.id.clone() });
        assert_eq!(wallet.counts().unspent, 1);
        assert_eq!(wallet.counts().pending, 1, "an unlanded purchase stays pending");
        let ticket_secret = wallet.tickets[0].secret_felt().unwrap();

        let log = log.lock().unwrap();
        let methods: Vec<&str> = log.iter().map(|(m, _)| m.as_str()).collect();
        assert_eq!(
            methods,
            [
                "starknet_blockNumber",
                "starknet_getEvents",
                "starknet_call",
                "starknet_getEvents",
                "starknet_call",
                "starknet_call",
                "starknet_getNonce",
            ]
        );
        let mut secrets: Vec<String> = ["alice", "bob", "carol"]
            .iter()
            .map(|h| felt_hex(&crate::app::short_string_felt(h).unwrap()))
            .collect();
        secrets.push(w.alice.scan_pub.clone());
        secrets.push(felt_hex(&member_secret));
        secrets.push(felt_hex(&p.public.nullifier));
        secrets.push(felt_hex(&ticket_secret));
        secrets.push(felt_hex(&p.public.ticket_nullifier));
        secrets.extend(w.ticket_leaves.iter().map(felt_hex));
        secrets.push(felt_hex(&Felt::from(0x5011u64))); // alice's account (event owner)
        for (method, params) in log.iter() {
            let text = params.to_string();
            for s in &secrets {
                assert!(!text.contains(s.as_str()), "{method} names {s}: {text}");
            }
            match method.as_str() {
                "starknet_getEvents" => assert_eq!(params[0]["keys"].as_array().unwrap()[0].as_array().unwrap().len(), 1, "the event filter selects no user or ticket"),
                "starknet_call" => assert_eq!(params[0]["calldata"], json!([]), "no call takes an argument"),
                _ => {}
            }
        }
        fs::remove_dir_all(&w.home.dir).unwrap();
    }

    /// Quota slots advance per send within an epoch, and the quota is
    /// enforced before anything is sealed or proven.
    #[test]
    fn prepare_takes_quota_slots_and_tickets_in_turn() {
        let w = world("quota");
        let (sender, _) = fake_sender(&w.home, w.fake);
        let first = sender.prepare(&w.alice, "bob", "one").unwrap();
        let second = sender.prepare(&w.alice, "bob", "two").unwrap();
        assert_eq!(second.prove_calldata[11], Felt::ONE, "the second send takes slot 1");
        assert_eq!(second.prove_calldata[35], Felt::TWO, "and the other ticket");
        assert_ne!(first.public.nullifier, second.public.nullifier);
        // No ticket left: refused before the quota is touched.
        let err = sender.prepare(&w.alice, "bob", "three").err().unwrap();
        assert!(format!("{err:#}").contains("no unspent ticket"), "{err:#}");
        let log = QuotaLog::load(&w.home).unwrap().unwrap();
        assert_eq!(log.used, 2);
        fs::remove_dir_all(&w.home.dir).unwrap();
    }

    /// A purchase that landed after the base block is settled against the
    /// latest tree and reported as "not yet", which `send` waits on, instead
    /// of "no unspent ticket".
    #[test]
    fn a_purchase_newer_than_the_base_block_is_waited_for() {
        let w = world("fresh");
        let stranger = crate::tickets::tests::event(Felt::from(0x5157u64), 0);
        let base = vec![stranger.clone()];
        let latest = vec![stranger, crate::tickets::tests::event(w.ticket_leaves[0], 1)];
        let fake = Fake {
            ticket_root: TicketTree::from_events(&base).unwrap().root(),
            tickets: base,
            latest_tickets: Some(latest),
            ..w.fake
        };
        let (sender, _) = fake_sender(&w.home, fake);
        let err = sender.prepare(&w.alice, "bob", "hi").err().unwrap();
        assert_eq!(err.downcast_ref::<TicketNotInTreeYet>(), Some(&TicketNotInTreeYet { unspent: 1 }), "{err:#}");
        let wallet = Wallet::load(&w.home, crate::config::SEPOLIA_POOL_V4).unwrap();
        assert_eq!(wallet.tickets[0].state, TicketState::Unspent, "settled from the latest tree");
        assert_eq!(wallet.tickets[0].index, Some(1));
        assert!(QuotaLog::load(&w.home).unwrap().is_none_or(|l| l.used == 0), "no quota slot taken");
        fs::remove_dir_all(&w.home.dir).unwrap();
    }

    #[test]
    fn prepare_refuses_trees_that_disagree_with_the_store() {
        let w = world("mismatch");
        let good = w.fake.roots[0];
        // Wrong once: refreshed and retried at a fresh block, then fine.
        let fake = Fake { roots: vec![Felt::from(7u64), good], ..w.fake };
        let (sender, log) = fake_sender(&w.home, fake);
        sender.prepare(&w.alice, "bob", "hi").unwrap();
        let n = log.lock().unwrap().iter().filter(|(m, _)| m == "starknet_getEvents").count();
        assert_eq!(n, 4, "both trees fetched twice");
        fs::remove_dir_all(&w.home.dir).unwrap();

        // A ticket tree that never matches: a clear error, nothing reserved.
        let w = world("mismatch2");
        let fake = Fake { ticket_root: Felt::from(9u64), ..w.fake };
        let (sender, _) = fake_sender(&w.home, fake);
        let err = sender.prepare(&w.alice, "bob", "hi").err().unwrap();
        assert!(format!("{err:#}").contains("disagree with the store"), "{err:#}");
        let wallet = Wallet::load(&w.home, crate::config::SEPOLIA_POOL_V4).unwrap();
        assert_eq!(wallet.counts().reserved, 0);
        assert!(QuotaLog::load(&w.home).unwrap().is_none(), "no slot taken");
        fs::remove_dir_all(&w.home.dir).unwrap();
    }

    #[test]
    fn prepare_checks_the_sender_registration_and_recipient() {
        let w = world("checks");
        let (sender, _) = fake_sender(&w.home, w.fake);
        let err = sender.prepare(&w.alice, "dave", "hi").err().unwrap();
        assert!(format!("{err:#}").contains("'dave' is not registered"), "{err:#}");
        let (mut other, _) = profile("alice", 0x11, 0);
        other.member_secret = Some(crate::config::member_secret_hex(&[0x01; 32]));
        let err = sender.prepare(&other, "bob", "hi").err().unwrap();
        assert!(format!("{err:#}").contains("registered to different keys"), "{err:#}");
        fs::remove_dir_all(&w.home.dir).unwrap();
    }

    #[test]
    fn only_the_current_store_routes() {
        let v4 = VirtualRoute::for_store(crate::config::SEPOLIA_POOL_V4).unwrap();
        assert_eq!(v4.prover, Felt::from_hex(crate::config::SEPOLIA_V4_SEND_PROVER).unwrap());
        assert_eq!(v4.virtual_sender, Felt::from_hex(crate::config::SEPOLIA_V4_VIRTUAL_SENDER).unwrap());
        assert!(VirtualRoute::for_store(crate::config::SEPOLIA_STORE_V3).is_none());
        assert!(VirtualRoute::for_store("0x04dc92ef9a90d336a79188c5408cdf9ce480f3ecd5b1ce55ef2ca207f2c3afe8").is_none());
    }
}
