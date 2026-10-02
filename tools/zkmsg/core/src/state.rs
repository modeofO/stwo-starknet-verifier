//! Send checkpoints. A SNIP-36 send is Prepare → Prove → Publish; its state
//! is first written once the proof exists (the witness Prepare builds is
//! never written down), and the publish hash is recorded the moment the
//! gateway takes it, so `zkmsg resume <id>` polls that hash rather than
//! paying twice.
//!
//! State files from the removed lane-1 pipeline (2026-10-01) no longer
//! parse; `app::pending_sends` skips them.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::Home;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    /// Read the tree, the members and the nonce at one block. Never
    /// checkpointed on its own: nothing is resumable before the proof exists.
    Prepare,
    /// Virtual-OS proof of `prove_send`, facts checked against the send.
    Prove,
    /// The one paid transaction: `send_message` carrying proof + facts.
    Publish,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StepRecord {
    pub kind: StepKind,
    pub done: bool,
    pub tx_hash: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SendState {
    pub id: String,
    pub recipient_handle: String,
    /// Hex of the published content ByteArray (v2: `kem_ct ‖ blob`).
    pub ciphertext_hex: String,
    /// The public tuple the proof attests (hex felts).
    pub expected_commitment: String,
    pub expected_ephemeral_pubkey: String,
    pub expected_merkle_root: String,
    pub steps: Vec<StepRecord>,
    /// The block the send was prepared and proven on.
    pub base_block: Option<u64>,
}

impl SendState {
    pub fn new_virtual_plan(
        id: String,
        recipient_handle: String,
        ciphertext_hex: String,
        expected: (String, String, String),
        base_block: u64,
    ) -> Self {
        let steps = [StepKind::Prepare, StepKind::Prove, StepKind::Publish]
            .into_iter()
            .map(|kind| StepRecord { kind, done: false, tx_hash: None, note: None })
            .collect();
        Self {
            id,
            recipient_handle,
            ciphertext_hex,
            expected_commitment: expected.0,
            expected_ephemeral_pubkey: expected.1,
            expected_merkle_root: expected.2,
            steps,
            base_block: Some(base_block),
        }
    }

    pub fn next_pending(&self) -> Option<usize> {
        self.steps.iter().position(|s| !s.done)
    }

    pub fn mark_done(&mut self, index: usize, tx_hash: Option<String>, note: Option<String>) {
        self.steps[index].done = true;
        self.steps[index].tx_hash = tx_hash;
        self.steps[index].note = note;
    }

    /// Records a submitted (not yet accepted) transaction on step `index`.
    pub fn record_submission(&mut self, index: usize, tx_hash: String) {
        self.steps[index].tx_hash = Some(tx_hash);
    }

    pub fn path(home: &Home, id: &str) -> PathBuf {
        home.sends_dir().join(format!("{id}.json"))
    }

    /// The send's working directory (the proof lives here, not in the state
    /// json — it is ~300 KB).
    pub fn workdir(home: &Home, id: &str) -> PathBuf {
        home.sends_dir().join(id)
    }

    pub fn save(&self, home: &Home) -> Result<()> {
        fs::create_dir_all(home.sends_dir())?;
        fs::write(Self::path(home, &self.id), serde_json::to_string_pretty(self)?)?;
        Ok(())
    }

    pub fn load(home: &Home, id: &str) -> Result<Self> {
        let raw = fs::read_to_string(Self::path(home, id))
            .with_context(|| format!("no send state '{id}'"))?;
        serde_json::from_str(&raw)
            .with_context(|| format!("send state '{id}' is not a SNIP-36 send (lane-1 sends are retired)"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> SendState {
        SendState::new_virtual_plan(
            "v1".into(),
            "mode2".into(),
            "00".into(),
            ("0xa".into(), "0xb".into(), "0xc".into()),
            42,
        )
    }

    #[test]
    fn plan_shape_and_progression() {
        let mut s = plan();
        let kinds: Vec<_> = s.steps.iter().map(|r| r.kind.clone()).collect();
        assert_eq!(kinds, vec![StepKind::Prepare, StepKind::Prove, StepKind::Publish]);
        s.mark_done(0, None, None);
        s.mark_done(1, None, None);
        assert_eq!(s.next_pending(), Some(2));
        s.record_submission(2, "0xabc".into());
        assert_eq!(s.next_pending(), Some(2), "submitted is not done");
        assert_eq!(s.steps[2].tx_hash.as_deref(), Some("0xabc"));
    }

    #[test]
    fn round_trips_and_reads_states_written_before_the_cleanup() {
        let dir = std::env::temp_dir().join(format!("zkmsg-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let home = Home::new(dir.clone());
        let mut s = plan();
        s.mark_done(0, None, Some("block 42".into()));
        s.save(&home).unwrap();
        assert_eq!(SendState::load(&home, "v1").unwrap().next_pending(), Some(1));

        // A SNIP-36 state saved by the 2026-10-01 build, which still carried
        // the lane-1 fields: they are ignored.
        let mut old = serde_json::to_value(&s).unwrap();
        old["args_hex"] = serde_json::json!([]);
        old["proof_id"] = serde_json::json!("");
        old["fri_offset"] = serde_json::Value::Null;
        old["fact"] = serde_json::Value::Null;
        fs::write(SendState::path(&home, "old"), old.to_string()).unwrap();
        assert!(SendState::load(&home, "old").is_ok());

        // A lane-1 state does not parse.
        fs::write(
            SendState::path(&home, "lane1"),
            r#"{"id":"lane1","recipient_handle":"bob","ciphertext_hex":"00",
                "expected_commitment":"0x1","expected_ephemeral_pubkey":"0x2",
                "expected_merkle_root":"0x3","steps":[{"kind":"Wrap","done":true,
                "tx_hash":null,"note":null}]}"#,
        )
        .unwrap();
        assert!(SendState::load(&home, "lane1").is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
