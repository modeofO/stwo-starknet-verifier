//! Send-pipeline checkpoints: every step is recorded BEFORE it runs and
//! marked done (with tx hashes) after, so `zkmsg send --resume <id>`
//! re-enters at the first incomplete step — a gas spike or RPC flake
//! mid-pipeline never re-pays the lane-1 transactions already landed.

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::config::Home;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum StepKind {
    /// bridge prove (writes cairo_proof + preimage; checks the tuple).
    Prove,
    /// bridge wrap (writes the multiverifier proof; checks the inner root).
    Wrap,
    /// pack v1 + head/tail split (pure local).
    Pack,
    /// stage_proof chunk at packed-tail offset.
    Stage { offset: u32 },
    /// verify_phase1 (returns fri_offset via trace).
    Phase1,
    /// verify_phase2 (registers the fact).
    Phase2,
    /// MessageStore v3 send_message.
    SendMessage,
    /// SNIP-36 route: read the tree, both members and the nonce at one block.
    /// Never checkpointed on its own — the witness it builds is kept in
    /// memory only, so there is nothing to resume before the proof exists.
    Prepare,
    /// SNIP-36 route: the one paid transaction, `send_message` carrying the
    /// proof and its facts. Its hash is recorded the moment the gateway
    /// takes it, before `done`, so a resume polls it instead of resubmitting.
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
    /// Hex-encoded AEAD blob (nonce ‖ ct ‖ tag).
    pub ciphertext_hex: String,
    /// The 46 circuit args (hex felts).
    pub args_hex: Vec<String>,
    /// The tuple the proof must output (hex felts).
    pub expected_commitment: String,
    pub expected_ephemeral_pubkey: String,
    pub expected_merkle_root: String,
    /// proof_id used for staging/verification (hex felt).
    pub proof_id: String,
    /// Filled after Phase1.
    pub fri_offset: Option<u32>,
    /// Filled after Phase2 (the registered fact).
    pub fact: Option<String>,
    pub steps: Vec<StepRecord>,
    /// SNIP-36 route: the block the send was prepared and proven on.
    #[serde(default)]
    pub base_block: Option<u64>,
}

impl SendState {
    /// The step plan up to Pack; staging steps are appended once the
    /// packed length is known (after Pack runs).
    pub fn new_plan(
        id: String,
        recipient_handle: String,
        ciphertext_hex: String,
        args_hex: Vec<String>,
        expected: (String, String, String),
        proof_id: String,
    ) -> Self {
        let steps = vec![
            StepRecord { kind: StepKind::Prove, done: false, tx_hash: None, note: None },
            StepRecord { kind: StepKind::Wrap, done: false, tx_hash: None, note: None },
            StepRecord { kind: StepKind::Pack, done: false, tx_hash: None, note: None },
            // Stage steps inserted here by `set_stage_offsets` after Pack.
            StepRecord { kind: StepKind::Phase1, done: false, tx_hash: None, note: None },
            StepRecord { kind: StepKind::Phase2, done: false, tx_hash: None, note: None },
            StepRecord { kind: StepKind::SendMessage, done: false, tx_hash: None, note: None },
        ];
        Self {
            id,
            recipient_handle,
            ciphertext_hex,
            args_hex,
            expected_commitment: expected.0,
            expected_ephemeral_pubkey: expected.1,
            expected_merkle_root: expected.2,
            proof_id,
            fri_offset: None,
            fact: None,
            steps,
            base_block: None,
        }
    }

    /// The SNIP-36 plan: Prepare → Prove → Publish. The witness is not part
    /// of it (`args_hex` stays empty): it lives in memory between Prepare and
    /// Prove, and only the public tuple, the ciphertext and (in the workdir)
    /// the proof are written down.
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
            args_hex: vec![],
            expected_commitment: expected.0,
            expected_ephemeral_pubkey: expected.1,
            expected_merkle_root: expected.2,
            proof_id: String::new(),
            fri_offset: None,
            fact: None,
            steps,
            base_block: Some(base_block),
        }
    }

    /// Whether this is a SNIP-36 send. The two routes never adopt each
    /// other's state: a lane-1 plan has no Publish step, a virtual one has
    /// no Wrap.
    pub fn is_virtual(&self) -> bool {
        self.steps.iter().any(|s| s.kind == StepKind::Publish)
    }

    /// Records a submitted (not yet accepted) transaction on step `index`.
    pub fn record_submission(&mut self, index: usize, tx_hash: String) {
        self.steps[index].tx_hash = Some(tx_hash);
    }

    /// Inserts the Stage{offset} steps (idempotent) once Pack has
    /// determined the tail chunking.
    pub fn set_stage_offsets(&mut self, offsets: &[u32]) {
        if self.steps.iter().any(|s| matches!(s.kind, StepKind::Stage { .. })) {
            return;
        }
        let insert_at = self
            .steps
            .iter()
            .position(|s| s.kind == StepKind::Phase1)
            .expect("plan always has Phase1");
        for (i, offset) in offsets.iter().enumerate() {
            self.steps.insert(
                insert_at + i,
                StepRecord {
                    kind: StepKind::Stage { offset: *offset },
                    done: false,
                    tx_hash: None,
                    note: None,
                },
            );
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

    pub fn path(home: &Home, id: &str) -> PathBuf {
        home.sends_dir().join(format!("{id}.json"))
    }

    /// The send's working directory (proof artifacts live here, NOT in the
    /// state json — they are megabytes).
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
        Ok(serde_json::from_str(&raw)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> SendState {
        SendState::new_plan(
            "s1".into(),
            "bob".into(),
            "00".into(),
            vec!["0x1".into()],
            ("0xa".into(), "0xb".into(), "0xc".into()),
            "0xd".into(),
        )
    }

    #[test]
    fn resume_point_progression() {
        let mut s = plan();
        assert_eq!(s.next_pending(), Some(0)); // Prove
        s.mark_done(0, None, None);
        s.mark_done(1, None, None);
        s.mark_done(2, None, None); // Pack done -> stages known
        s.set_stage_offsets(&[0, 1900]);
        // Steps: Prove, Wrap, Pack, Stage{0}, Stage{1900}, Phase1, Phase2, Send
        assert_eq!(s.steps.len(), 8);
        assert_eq!(s.next_pending(), Some(3));
        assert!(matches!(s.steps[3].kind, StepKind::Stage { offset: 0 }));
        s.mark_done(3, Some("0xabc".into()), None);
        assert!(matches!(s.steps[s.next_pending().unwrap()].kind, StepKind::Stage {
            offset: 1900
        }));
    }

    #[test]
    fn stage_insertion_is_idempotent() {
        let mut s = plan();
        s.set_stage_offsets(&[0]);
        s.set_stage_offsets(&[0]);
        let stages = s
            .steps
            .iter()
            .filter(|r| matches!(r.kind, StepKind::Stage { .. }))
            .count();
        assert_eq!(stages, 1);
    }

    #[test]
    fn virtual_plan_shape() {
        let s = SendState::new_virtual_plan(
            "v1".into(),
            "mode2".into(),
            "00".into(),
            ("0xa".into(), "0xb".into(), "0xc".into()),
            42,
        );
        assert!(s.is_virtual());
        assert!(!plan().is_virtual());
        assert!(s.args_hex.is_empty(), "the witness is never part of a virtual state");
        let kinds: Vec<_> = s.steps.iter().map(|r| r.kind.clone()).collect();
        assert_eq!(kinds, vec![StepKind::Prepare, StepKind::Prove, StepKind::Publish]);
    }

    #[test]
    fn lane1_state_without_base_block_still_loads() {
        let mut v = serde_json::to_value(plan()).unwrap();
        v.as_object_mut().unwrap().remove("base_block");
        let s: SendState = serde_json::from_value(v).unwrap();
        assert_eq!(s.base_block, None);
    }

    #[test]
    fn round_trips_to_disk() {
        let dir = std::env::temp_dir().join(format!("zkmsg-state-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let home = Home::new(dir.clone());
        let mut s = plan();
        s.mark_done(0, Some("0x123".into()), Some("proved".into()));
        s.save(&home).unwrap();
        let loaded = SendState::load(&home, "s1").unwrap();
        assert_eq!(loaded.next_pending(), Some(1));
        assert_eq!(loaded.steps[0].tx_hash.as_deref(), Some("0x123"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
