//! The checkpointed send pipeline — the lane-1 runbook as code:
//!
//!   Prove → Wrap → Pack → Stage{…} → Phase1 → Phase2 → SendMessage
//!
//! Local legs first (free), then the paid transactions. Every step is
//! persisted before and after execution (state.rs), so a failure at any
//! point resumes without re-paying landed txs. Two pre-spend gates make
//! wrong-proof spends impossible:
//!  - after Prove: the bootloader preimage must carry EXACTLY the
//!    locally computed (program_hash, commitment, eph_pub, root);
//!  - after Wrap: the printed inner circuit root must equal the pinned
//!    config::INNER_ROOT (a different root would produce a fact the
//!    store can never accept).

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
use starknet_types_core::felt::Felt;

use crate::chain::{Chain, GasBounds, bytearray_calldata, felt_hex, span_calldata};
use crate::config::{Config, Home, INNER_ROOT, PROGRAM_HASH};
use crate::pack::{load_proof_json, pack_v1};
use crate::state::{SendState, StepKind};

/// Head slots carried as phase-1 calldata (lane-1 runbook: 4,995 usable
/// minus the account envelope).
const HEAD_LEN: usize = 4_991;
/// Staged slots per stage tx (the state-diff bouncer counts 2 felts per
/// write against 4,000).
const STAGE_CHUNK: usize = 1_900;
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(600);

pub struct Pipeline<'a> {
    pub home: &'a Home,
    pub config: &'a Config,
    pub chain: Chain,
}

impl<'a> Pipeline<'a> {
    pub fn new(home: &'a Home, config: &'a Config) -> Self {
        Self { home, config, chain: Chain::new(&config.rpc_url, &config.account) }
    }

    fn workdir(&self, state: &SendState) -> PathBuf {
        SendState::workdir(self.home, &state.id)
    }

    fn packed_path(&self, state: &SendState) -> PathBuf {
        self.workdir(state).join("packed.txt")
    }

    fn load_packed(&self, state: &SendState) -> Result<Vec<Felt>> {
        let raw = fs::read_to_string(self.packed_path(state))?;
        raw.lines()
            .filter(|l| !l.trim().is_empty())
            .map(|l| Felt::from_hex(l.trim()).context("packed slot"))
            .collect()
    }

    /// Runs every remaining step; prints progress per step.
    pub fn run(&self, state: &mut SendState) -> Result<()> {
        fs::create_dir_all(self.workdir(state))?;
        while let Some(index) = state.next_pending() {
            let kind = state.steps[index].kind.clone();
            println!("[{}] step {}/{}: {:?}", state.id, index + 1, state.steps.len(), kind);
            let (tx, note) = self.execute(state, &kind)?;
            state.mark_done(index, tx, note);
            state.save(self.home)?;
        }
        println!(
            "[{}] complete — fact {}",
            state.id,
            state.fact.as_deref().unwrap_or("(recorded on-chain)"),
        );
        Ok(())
    }

    fn execute(
        &self,
        state: &mut SendState,
        kind: &StepKind,
    ) -> Result<(Option<String>, Option<String>)> {
        match kind {
            StepKind::Prove => self.step_prove(state),
            StepKind::Wrap => self.step_wrap(state),
            StepKind::Pack => self.step_pack(state),
            StepKind::Stage { offset } => self.step_stage(state, *offset),
            StepKind::Phase1 => self.step_phase1(state),
            StepKind::Phase2 => self.step_phase2(state),
            StepKind::SendMessage => self.step_send(state),
        }
    }

    // --- local legs ---------------------------------------------------------

    fn step_prove(&self, state: &SendState) -> Result<(Option<String>, Option<String>)> {
        let dir = self.workdir(state);
        let args_path = dir.join("args.json");
        fs::write(&args_path, serde_json::to_string(&state.args_hex)?)?;

        run_tool(
            Command::new(&self.config.bridge_bin).args([
                "prove".as_ref(),
                self.config.circuit_executable.as_os_str(),
                dir.join("cairo_proof.json").as_os_str(),
                dir.join("preimage.json").as_os_str(),
                args_path.as_os_str(),
            ]),
            "bridge prove",
        )?;

        // Pre-spend gate 1: the preimage must be exactly what we computed.
        let preimage: Vec<String> =
            serde_json::from_str(&fs::read_to_string(dir.join("preimage.json"))?)?;
        ensure!(preimage.len() == 6, "unexpected preimage shape: {preimage:?}");
        let want = [
            ("program_hash", PROGRAM_HASH, &preimage[2]),
            ("commitment", state.expected_commitment.as_str(), &preimage[3]),
            ("ephemeral_pubkey", state.expected_ephemeral_pubkey.as_str(), &preimage[4]),
            ("merkle_root", state.expected_merkle_root.as_str(), &preimage[5]),
        ];
        for (name, expected, got) in want {
            ensure!(
                Felt::from_hex(expected)? == Felt::from_hex(got)?,
                "preimage {name} mismatch: expected {expected}, proof says {got}",
            );
        }
        Ok((None, Some("preimage tuple verified".into())))
    }

    fn step_wrap(&self, state: &SendState) -> Result<(Option<String>, Option<String>)> {
        let dir = self.workdir(state);
        let output = run_tool(
            Command::new(&self.config.bridge_bin).args([
                "wrap".as_ref(),
                dir.join("cairo_proof.json").as_os_str(),
                dir.join("preimage.json").as_os_str(),
                dir.join("proof.json").as_os_str(),
            ]),
            "bridge wrap",
        )?;

        // Pre-spend gate 2: the inner root must be the pinned one.
        let printed = parse_inner_root(&output)
            .context("wrap output did not contain the inner circuit root line")?;
        ensure!(
            printed == INNER_ROOT,
            "inner circuit root changed: wrap printed {printed:?}, pinned {INNER_ROOT:?} — \
             the store would never accept this fact (rebuild/repin required)",
        );
        Ok((None, Some("inner root verified".into())))
    }

    fn step_pack(&self, state: &mut SendState) -> Result<(Option<String>, Option<String>)> {
        let values = load_proof_json(&self.workdir(state).join("proof.json"))?;
        let packed = pack_v1(&values)?;
        ensure!(packed.len() > HEAD_LEN, "proof unexpectedly small: {} slots", packed.len());
        let lines: Vec<String> = packed.iter().map(felt_hex).collect();
        fs::write(self.packed_path(state), lines.join("\n"))?;

        let tail_len = packed.len() - HEAD_LEN;
        let offsets: Vec<u32> =
            (0..tail_len).step_by(STAGE_CHUNK).map(|o| o as u32).collect();
        state.set_stage_offsets(&offsets);
        Ok((
            None,
            Some(format!(
                "{} slots ({} values); head {HEAD_LEN}, tail {tail_len} in {} stage tx(s)",
                packed.len(),
                values.len(),
                offsets.len(),
            )),
        ))
    }

    // --- paid legs ----------------------------------------------------------

    fn step_stage(
        &self,
        state: &SendState,
        offset: u32,
    ) -> Result<(Option<String>, Option<String>)> {
        let packed = self.load_packed(state)?;
        let tail = &packed[HEAD_LEN..];
        let end = usize::min(offset as usize + STAGE_CHUNK, tail.len());
        let chunk = &tail[offset as usize..end];

        let mut calldata = vec![state.proof_id.clone(), format!("{offset:#x}")];
        calldata.extend(span_calldata(chunk));
        let tx = self.chain.invoke(
            &self.config.registry,
            "stage_proof",
            &calldata,
            &bounds_for(&StepKind::Stage { offset }),
        )?;
        self.chain.wait_receipt(&tx, RECEIPT_TIMEOUT)?;
        Ok((Some(tx), Some(format!("staged {} slots at {offset}", chunk.len()))))
    }

    fn step_phase1(&self, state: &mut SendState) -> Result<(Option<String>, Option<String>)> {
        let packed = self.load_packed(state)?;
        let values = load_proof_json(&self.workdir(state).join("proof.json"))?;
        let head = &packed[..HEAD_LEN];
        let n_tail = packed.len() - HEAD_LEN;

        let mut calldata = vec![state.proof_id.clone()];
        calldata.extend(span_calldata(head));
        calldata.push(format!("{n_tail:#x}"));
        calldata.push(format!("{:#x}", values.len()));

        let tx = self.chain.invoke(
            &self.config.registry,
            "verify_phase1",
            &calldata,
            &bounds_for(&StepKind::Phase1),
        )?;
        self.chain.wait_receipt(&tx, RECEIPT_TIMEOUT)?;

        let retdata = self.chain.trace_retdata(&tx)?;
        ensure!(retdata.len() == 1, "phase1 retdata shape: {retdata:?}");
        let fri_offset = crate::chain::felt_to_u64(&Felt::from_hex(&retdata[0])?)? as u32;
        state.fri_offset = Some(fri_offset);
        Ok((Some(tx), Some(format!("fri_offset {fri_offset}"))))
    }

    fn step_phase2(&self, state: &mut SendState) -> Result<(Option<String>, Option<String>)> {
        let values = load_proof_json(&self.workdir(state).join("proof.json"))?;
        let fri_offset =
            state.fri_offset.context("phase2 before phase1 (no fri_offset)")? as usize;
        // The fri section: everything from fri_offset up to (not incl.)
        // the trailing channel_salt — mirror of the registry test.
        let n_fri_values = values.len() - fri_offset - 1;
        let fri_slots = pack_v1(&values[fri_offset..fri_offset + n_fri_values])?;

        let mut calldata = vec![state.proof_id.clone()];
        calldata.extend(span_calldata(&fri_slots));
        calldata.push(format!("{n_fri_values:#x}"));

        let tx = self.chain.invoke(
            &self.config.registry,
            "verify_phase2",
            &calldata,
            &bounds_for(&StepKind::Phase2),
        )?;
        self.chain.wait_receipt(&tx, RECEIPT_TIMEOUT)?;

        let retdata = self.chain.trace_retdata(&tx)?;
        ensure!(retdata.len() == 1, "phase2 retdata shape: {retdata:?}");
        state.fact = Some(retdata[0].clone());
        Ok((Some(tx), Some(format!("fact {}", retdata[0]))))
    }

    fn step_send(&self, state: &SendState) -> Result<(Option<String>, Option<String>)> {
        let ciphertext = hex::decode(&state.ciphertext_hex).context("state ciphertext hex")?;
        let mut calldata = vec![
            state.expected_commitment.clone(),
            state.expected_ephemeral_pubkey.clone(),
            state.expected_merkle_root.clone(),
        ];
        calldata.extend(bytearray_calldata(&ciphertext));

        let tx = self.chain.invoke(
            &self.config.store,
            "send_message",
            &calldata,
            &bounds_for(&StepKind::SendMessage),
        )?;
        self.chain.wait_receipt(&tx, RECEIPT_TIMEOUT)?;
        Ok((Some(tx), Some("message published".into())))
    }
}

/// Per-step l2-gas ceilings: measured lane-1 Sepolia values (phase 1
/// 873.8M, phase 2 815.7M) plus margin; prices are left to estimation
/// unless the runbook forces overrides at deploy time.
fn bounds_for(kind: &StepKind) -> GasBounds {
    let l2_gas = match kind {
        StepKind::Stage { .. } => Some(400_000_000),
        StepKind::Phase1 => Some(1_050_000_000),
        StepKind::Phase2 => Some(1_000_000_000),
        StepKind::SendMessage => Some(60_000_000),
        _ => None,
    };
    GasBounds { l2_gas, ..Default::default() }
}

fn run_tool(cmd: &mut Command, label: &str) -> Result<String> {
    let out = cmd.output().with_context(|| format!("running {label}"))?;
    let combined = format!(
        "{}\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr),
    );
    if !out.status.success() {
        bail!("{label} failed:\n{combined}");
    }
    Ok(combined)
}

/// Parses wrap's "[wrap 1/3] inner circuit root …: [(lo + hi i) + (0 + 0i)u, …]"
/// QM31 rendering into the [u32; 8] word form (lo16 + hi16·2^16).
pub fn parse_inner_root(wrap_output: &str) -> Option<[u32; 8]> {
    let line = wrap_output.lines().find(|l| l.contains("inner circuit root"))?;
    // Integers after the ':' come as (lo, hi, 0, 0) per word, 8 words =
    // 32 integers; word = lo16 + hi16·2^16.
    let nums: Vec<u64> = line
        .split(':')
        .next_back()?
        .split(|c: char| !c.is_ascii_digit())
        .filter(|s| !s.is_empty())
        .filter_map(|s| s.parse().ok())
        .collect();
    if nums.len() != 32 {
        return None;
    }
    let mut words = [0u32; 8];
    for (i, word) in words.iter_mut().enumerate() {
        *word = (nums[4 * i] + (nums[4 * i + 1] << 16)) as u32;
    }
    Some(words)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact line the milestone-1 wrap printed; must decode to the
    /// pinned INNER_ROOT.
    #[test]
    fn parses_milestone1_inner_root_line() {
        let line = "[wrap 1/3] inner circuit root (consumers whitelist this): \
            [(36042 + 40816i) + (0 + 0i)u, (33692 + 60862i) + (0 + 0i)u, \
            (58924 + 21139i) + (0 + 0i)u, (24428 + 25350i) + (0 + 0i)u, \
            (20832 + 53931i) + (0 + 0i)u, (39329 + 5439i) + (0 + 0i)u, \
            (8808 + 32063i) + (0 + 0i)u, (32732 + 42068i) + (0 + 0i)u]";
        assert_eq!(parse_inner_root(line), Some(INNER_ROOT));
    }

    #[test]
    fn missing_root_line_is_none() {
        assert_eq!(parse_inner_root("no root here"), None);
    }
}
