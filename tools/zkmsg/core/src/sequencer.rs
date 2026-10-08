//! Sepolia's sequencer gateway, for the one write the SNIP-36 route makes: an
//! INVOKE v3 carrying `proof` + `proof_facts`. JSON-RPC's
//! `addInvokeTransaction` has no field for either, so the publish leg goes to
//! the gateway, and its status polls go to the feeder beside it (the same pair
//! the phone uses — zkmsg-ios `GatewayClient`).
//!
//! A rejection is information, not just failure: `INVALID_TRANSACTION_NONCE`
//! names the nonce the sequencer expected, and a proof whose base block is
//! within 10 blocks of the head is refused as "too recent" — both are retried
//! by the caller ([`GatewayError::expected_nonce`], [`GatewayError::too_recent`]).

use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use starknet_types_core::felt::Felt;

use crate::chain::felt_hex;
use crate::invoke_v3::{Bounds, Call, InvokeV3, Signer, execute_calldata};

pub const SEPOLIA_GATEWAY: &str = "https://alpha-sepolia.starknet.io/gateway";
pub const SEPOLIA_FEEDER: &str = "https://feeder.alpha-sepolia.starknet.io/feeder_gateway";

/// How long a just-submitted transaction may read as NOT_RECEIVED before it
/// counts as dropped (feeder replicas lag the gateway).
const DROP_GRACE: Duration = Duration::from_secs(90);

/// Why the gateway turned a request down. Kept typed (and reachable through
/// `anyhow::Error::downcast_ref`) so the caller can retry on the two
/// rejections that tell it what to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GatewayError {
    Rejected { code: String, message: String },
    /// The echoed hash differs from the one we signed: the gateway hashed a
    /// different transaction, and the account will refuse the signature.
    HashMismatch { signed: String, echoed: String },
    Reverted { hash: String, reason: String },
}

impl std::fmt::Display for GatewayError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected { code, message } => write!(f, "gateway rejected: {code}: {message}"),
            Self::HashMismatch { signed, echoed } => {
                write!(f, "gateway hash {echoed} differs from signed {signed}")
            }
            Self::Reverted { hash, reason } => write!(f, "tx {hash} reverted: {reason}"),
        }
    }
}

impl std::error::Error for GatewayError {}

impl GatewayError {
    /// The nonce the sequencer expects, parsed from an
    /// `INVALID_TRANSACTION_NONCE` rejection (`… Expected: 7 …`).
    pub fn expected_nonce(&self) -> Option<u64> {
        let Self::Rejected { code, message } = self else { return None };
        if !code.contains("INVALID_TRANSACTION_NONCE") {
            return None;
        }
        let rest = message[message.find("Expected: ")? + "Expected: ".len()..].trim_start();
        // Decimal on the gateways seen so far; accept hex too rather than
        // read "0x5" as 0.
        if let Some(hex) = rest.strip_prefix("0x") {
            let digits: String = hex.chars().take_while(char::is_ascii_hexdigit).collect();
            return u64::from_str_radix(&digits, 16).ok();
        }
        rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse().ok()
    }

    /// The account's `__validate__` refused with this Cairo reason (the v4
    /// pool's `'ticket spent'`, …). The gateway quotes it as text and/or as
    /// its hex encoding; either matches.
    pub fn refused_with(&self, reason: &str) -> bool {
        matches!(
            self,
            Self::Rejected { message, .. }
                if message.contains(reason) || message.contains(&hex::encode(reason))
        )
    }

    /// The proof's base block is still within 10 blocks of the head; waiting
    /// fixes it.
    pub fn too_recent(&self) -> bool {
        matches!(self, Self::Rejected { message, .. } if message.contains("too recent"))
    }
}

/// A transaction's status as the feeder reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxStatus {
    pub finality: String,
    pub execution: String,
    pub revert_reason: Option<String>,
}

impl TxStatus {
    pub fn is_accepted(&self) -> bool {
        self.finality.starts_with("ACCEPTED")
    }
    pub fn is_reverted(&self) -> bool {
        self.execution == "REVERTED"
    }
    /// The gateway does not have it: never received, or rejected before
    /// execution (no fee). Only these make a resubmission safe. Anything
    /// else that is not accepted or reverted — RECEIVED, a pre-confirmed
    /// state, a status this code doesn't know — is waited on.
    pub fn is_dropped(&self) -> bool {
        matches!(self.finality.as_str(), "NOT_RECEIVED" | "REJECTED")
    }
}

/// The SNIP-36 attachment: the proof exactly as the gateway takes it
/// (base64), and the facts the transaction signs over.
#[derive(Debug, Clone)]
pub struct ProofAttachment<'a> {
    pub proof: &'a str,
    pub proof_facts: &'a [Felt],
}

/// An INVOKE v3 built (and signed, unless its account takes no signature)
/// and ready to submit. Kept whole so a retry resubmits the identical
/// transaction (same hash, so it can only ever land once).
pub struct SignedInvoke {
    pub hash: Felt,
    body: Value,
}

pub struct Gateway {
    pub gateway_url: String,
    pub feeder_url: String,
    pub chain_id: Felt,
}

impl Gateway {
    pub fn sepolia() -> Self {
        Self {
            gateway_url: SEPOLIA_GATEWAY.into(),
            feeder_url: SEPOLIA_FEEDER.into(),
            chain_id: crate::invoke_v3::short_string("SN_SEPOLIA"),
        }
    }

    /// Signs one INVOKE v3 with `attachment`'s facts in the hash. Nothing is
    /// sent: the caller records the hash first, then `submit`s.
    pub fn sign_invoke(
        &self,
        signer: &Signer,
        calls: &[Call],
        nonce: Felt,
        bounds: Bounds,
        attachment: Option<&ProofAttachment<'_>>,
    ) -> Result<SignedInvoke> {
        let mut invoke = self.invoke(signer.address, calls, nonce, bounds, attachment);
        let [r, s] = signer.sign(&invoke.hash)?;
        invoke.body["signature"] = json!([felt_hex(&r), felt_hex(&s)]);
        Ok(invoke)
    }

    /// One INVOKE v3 from an account that authorizes by proof, not by
    /// signature (the v4 pool): the signature is empty. Like `sign_invoke`,
    /// nothing is sent.
    pub fn unsigned_invoke(
        &self,
        sender: Felt,
        calls: &[Call],
        nonce: Felt,
        bounds: Bounds,
        attachment: Option<&ProofAttachment<'_>>,
    ) -> SignedInvoke {
        self.invoke(sender, calls, nonce, bounds, attachment)
    }

    fn invoke(
        &self,
        sender: Felt,
        calls: &[Call],
        nonce: Felt,
        bounds: Bounds,
        attachment: Option<&ProofAttachment<'_>>,
    ) -> SignedInvoke {
        let calldata = execute_calldata(calls);
        let proof_facts = attachment.map(|a| a.proof_facts).unwrap_or(&[]);
        let hash = InvokeV3 {
            sender,
            calldata: &calldata,
            chain_id: self.chain_id,
            nonce,
            tip: 0,
            bounds,
            proof_facts,
        }
        .hash();
        let mut body = json!({
            "type": "INVOKE_FUNCTION",
            "version": "0x3",
            "sender_address": felt_hex(&sender),
            "calldata": calldata.iter().map(felt_hex).collect::<Vec<_>>(),
            "signature": [],
            "nonce": felt_hex(&nonce),
            "resource_bounds": bounds.gateway_json(),
            "tip": "0x0",
            "paymaster_data": [],
            "account_deployment_data": [],
            "nonce_data_availability_mode": 0,
            "fee_data_availability_mode": 0,
        });
        if let Some(a) = attachment {
            body["proof"] = json!(a.proof);
            body["proof_facts"] = json!(a.proof_facts.iter().map(felt_hex).collect::<Vec<_>>());
        }
        SignedInvoke { hash, body }
    }

    /// Submits a signed invoke, checking the gateway echoes the hash we
    /// signed. An `Err` that is not a `GatewayError::Rejected` says nothing
    /// about whether the gateway kept the transaction: poll the hash.
    pub fn submit(&self, signed: &SignedInvoke) -> Result<()> {
        let reply = self.post("add_transaction", &signed.body)?;
        let echoed = reply["transaction_hash"]
            .as_str()
            .with_context(|| format!("no transaction_hash in gateway reply: {reply}"))?;
        if Felt::from_hex(echoed).ok() != Some(signed.hash) {
            return Err(GatewayError::HashMismatch {
                signed: felt_hex(&signed.hash),
                echoed: echoed.to_string(),
            }
            .into());
        }
        Ok(())
    }

    pub fn status(&self, hash: &Felt) -> Result<TxStatus> {
        let url = format!("{}/get_transaction_status", self.feeder_url);
        let reply: Value = with_retries(|| {
            ureq::get(&url)
                .query("transactionHash", &felt_hex(hash))
                .timeout(Duration::from_secs(60))
                .call()
        })?
        .into_json()?;
        Ok(TxStatus {
            finality: reply["finality_status"]
                .as_str()
                .or_else(|| reply["tx_status"].as_str())
                .unwrap_or("UNKNOWN")
                .to_string(),
            execution: reply["execution_status"].as_str().unwrap_or("").to_string(),
            revert_reason: reply["tx_revert_reason"].as_str().map(String::from),
        })
    }

    /// Polls until accepted. A revert is an error, and is final: the fee is
    /// spent, so a caller must not resubmit blindly. A transaction still
    /// reported dropped after `DROP_GRACE` (feeders can lag the gateway) is
    /// an error too; the caller may then resubmit the identical transaction.
    pub fn await_acceptance(&self, hash: &Felt, poll: Duration, timeout: Duration) -> Result<TxStatus> {
        let started = Instant::now();
        let deadline = started + timeout;
        loop {
            let status = self.status(hash)?;
            if status.is_dropped() && started.elapsed() > DROP_GRACE {
                bail!("tx {} was dropped by the gateway ({})", felt_hex(hash), status.finality);
            }
            if status.is_reverted() {
                return Err(GatewayError::Reverted {
                    hash: felt_hex(hash),
                    reason: status.revert_reason.clone().unwrap_or_else(|| status.execution.clone()),
                }
                .into());
            }
            if status.is_accepted() {
                return Ok(status);
            }
            if Instant::now() > deadline {
                bail!("tx {}: not accepted after {timeout:?} (last {})", felt_hex(hash), status.finality);
            }
            std::thread::sleep(poll);
        }
    }

    fn post(&self, path: &str, body: &Value) -> Result<Value> {
        let url = format!("{}/{path}", self.gateway_url);
        // A proof-carrying submission is verified before the gateway answers.
        match ureq::post(&url).timeout(Duration::from_secs(180)).send_json(body.clone()) {
            Ok(resp) => Ok(resp.into_json()?),
            Err(ureq::Error::Status(status, resp)) => {
                let text = resp.into_string().unwrap_or_default();
                match serde_json::from_str::<Value>(&text) {
                    Ok(v) if v["code"].is_string() => Err(GatewayError::Rejected {
                        code: v["code"].as_str().unwrap_or_default().to_string(),
                        message: v["message"].as_str().unwrap_or_default().to_string(),
                    }
                    .into()),
                    _ => bail!("gateway {path}: HTTP {status}: {text}"),
                }
            }
            Err(e) => Err(e).with_context(|| format!("gateway {path}")),
        }
    }
}

/// Feeder reads retry transport errors, 429 and 5xx with backoff. Never used
/// for `add_transaction`: a resubmission must be a deliberate decision.
fn with_retries(
    mut request: impl FnMut() -> std::result::Result<ureq::Response, ureq::Error>,
) -> Result<ureq::Response> {
    let mut last = None;
    for attempt in 0..6u32 {
        match request() {
            Ok(resp) => return Ok(resp),
            Err(ureq::Error::Status(code, resp)) if code == 429 || code >= 500 => {
                last = Some(anyhow::anyhow!("HTTP {code}: {}", resp.into_string().unwrap_or_default()));
            }
            Err(ureq::Error::Status(code, resp)) => {
                bail!("feeder HTTP {code}: {}", resp.into_string().unwrap_or_default())
            }
            Err(e) => last = Some(e.into()),
        }
        std::thread::sleep(Duration::from_millis(250 << attempt.min(4)));
    }
    Err(last.unwrap_or_else(|| anyhow::anyhow!("feeder request failed")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rejected(code: &str, message: &str) -> GatewayError {
        GatewayError::Rejected { code: code.into(), message: message.into() }
    }

    #[test]
    fn parses_expected_nonce() {
        let e = rejected(
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
            "Invalid transaction nonce of contract at address 0x12. Account nonce: 0x5; got: 0x4. Expected: 5",
        );
        assert_eq!(e.expected_nonce(), Some(5));
        let hex = rejected("StarknetErrorCode.INVALID_TRANSACTION_NONCE", "... Expected: 0x1a.");
        assert_eq!(hex.expected_nonce(), Some(26));
        assert_eq!(rejected("StarknetErrorCode.VALIDATE_FAILURE", "Expected: 5").expected_nonce(), None);
    }

    #[test]
    fn only_explicit_drops_allow_resubmission() {
        let status = |f: &str| TxStatus { finality: f.into(), execution: String::new(), revert_reason: None };
        assert!(status("NOT_RECEIVED").is_dropped());
        assert!(status("REJECTED").is_dropped());
        for waiting in ["RECEIVED", "PRE_CONFIRMED", "CANDIDATE", "UNKNOWN"] {
            assert!(!status(waiting).is_dropped(), "{waiting} must be waited on");
        }
    }

    #[test]
    fn detects_too_recent() {
        assert!(rejected("StarknetErrorCode.INVALID_PROOF", "proof block is too recent").too_recent());
        assert!(!rejected("StarknetErrorCode.INVALID_PROOF", "bad proof").too_recent());
    }

    #[test]
    fn detects_validate_refusals() {
        let e = rejected(
            "StarknetErrorCode.VALIDATE_FAILURE",
            "Execution failed. Failure reason: 0x7469636b6574207370656e74 ('ticket spent').",
        );
        assert!(e.refused_with("ticket spent"));
        assert!(!e.refused_with("nullifier spent"));
        let hex_only = rejected("StarknetErrorCode.VALIDATE_FAILURE", "Failure reason: 0x7469636b6574207370656e74.");
        assert!(hex_only.refused_with("ticket spent"));
    }

    /// The pool's publish: the v3 invoke hash with the pool as sender and an
    /// EMPTY signature on the wire.
    #[test]
    fn unsigned_invoke_hashes_like_a_signed_one() {
        let gateway = Gateway::sepolia();
        let pool = Felt::from_hex("0x9001").unwrap();
        let call = Call::new(pool, "send_message", vec![Felt::ONE, Felt::TWO]);
        let facts = [Felt::THREE];
        let attachment = ProofAttachment { proof: "AAAA", proof_facts: &facts };
        let bounds = Bounds::default();
        let tx = gateway.unsigned_invoke(pool, std::slice::from_ref(&call), Felt::from(4u64), bounds, Some(&attachment));
        let calldata = execute_calldata(&[call.clone()]);
        let want = InvokeV3 {
            sender: pool,
            calldata: &calldata,
            chain_id: gateway.chain_id,
            nonce: Felt::from(4u64),
            tip: 0,
            bounds,
            proof_facts: &facts,
        }
        .hash();
        assert_eq!(tx.hash, want);
        assert_eq!(tx.body["signature"], json!([]));
        assert_eq!(tx.body["sender_address"], felt_hex(&pool));
        assert_eq!(tx.body["proof_facts"], json!(["0x3"]));

        // A signed invoke is the same transaction plus its signature.
        let signer = Signer::new(pool, Felt::from_hex("0x1234").unwrap());
        let signed = gateway
            .sign_invoke(&signer, &[call], Felt::from(4u64), bounds, Some(&attachment))
            .unwrap();
        assert_eq!(signed.hash, want);
        assert_eq!(signed.body["signature"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn rejection_survives_anyhow() {
        let err: anyhow::Error = rejected("X", "too recent").into();
        assert!(err.downcast_ref::<GatewayError>().is_some_and(GatewayError::too_recent));
    }
}
