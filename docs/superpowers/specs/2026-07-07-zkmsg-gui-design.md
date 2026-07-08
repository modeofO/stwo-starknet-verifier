# zkmsg GUI (egui) + core-library refactor (2026-07-07)

Approved direction from the 2026-07-07 discussion: **egui now, Tauri
later** — the deliverable that makes both possible is the same
core-library refactor, so nothing done here is wasted when the product
shell upgrades. Builds on the shipped v1
(`docs/superpowers/specs/2026-07-05-zkmsg-lane1-port-design.md`,
`docs/zkmsg-deployment.md`).

## Shape: one cargo workspace, three crates

`tools/zkmsg/` becomes a small workspace (still self-contained, still
outside any parent workspace):

- **`core/` (`zkmsg-core`, lib)** — everything that exists today minus
  `main.rs`: `crypto`, `tree`, `args`, `pack`, `chain`, `pipeline`,
  `state`, `config`, `inbox`. No egui/clap dependencies. The 27 existing
  unit tests move with their modules, unchanged.
- **`cli/` (`zkmsg`, bin)** — today's CLI, now a thin consumer of the
  lib. Identical commands, flags and output; users notice nothing.
- **`gui/` (`zkmsg-gui`, bin)** — the egui/eframe app.

## Core API changes (the only behavior-adjacent work)

1. **Progress events replace `println!` in the pipeline.**

   ```rust
   pub enum PipelineEvent {
       StepStarted { index: usize, total: usize, kind: StepKind },
       TxSubmitted { kind: StepKind, tx_hash: String },
       StepCompleted { kind: StepKind, tx_hash: Option<String>, note: Option<String> },
       Completed { fact: String },
   }
   ```

   `Pipeline::run` gains an event sink parameter
   (`&mut dyn FnMut(PipelineEvent)`). The CLI's sink prints exactly
   today's lines (verified by comparing output on a dry state-file
   replay); the GUI's sink forwards over an `std::sync::mpsc` channel.
2. **Blocking stays blocking.** The pipeline keeps its synchronous
   subprocess/receipt-poll structure; the GUI owns a worker thread. No
   async runtime is introduced.
3. Small extractions the GUI needs that the CLI currently inlines:
   `core::identity::init(home, account, store)`,
   `register(home, config, keys, handle)`,
   `status(home) -> StatusReport`, `prepare_send(...) -> SendState`
   (everything `cmd_send` does before `Pipeline::run`), and
   `pending_sends(home) -> Vec<(id, next_step)>`.

## The GUI (v1 scope)

Single window, three tabs, one identity per launch (`--home` flag, same
default `~/.zkmsg` as the CLI). Repaints driven by
`ctx.request_repaint()` from the worker channel — no polling loop.

- **Status tab** — handle, leaf, scan pubkey, account, balances, store/
  registry addresses, message count. Doubles as onboarding: if no
  `keys.json`, an Init panel (account name from the sncast accounts
  file, store defaulted); if keys but no handle, a Register panel with
  live tx progress.
- **Compose tab** — recipient handle (resolved via `get_user` on demand,
  showing leaf/pubkey or a clear "unknown handle" error), message box
  (soft cap 1,000 bytes with a counter), and the money affordances:
  projected cost line, current balance, and a **SEND button behind an
  explicit confirm dialog stating the STRK cost** — a GUI must not make
  a 46-STRK action feel like a chat message. During a send: a step
  checklist (Prove → Wrap → Pack → [Stage…] → Phase 1 → Phase 2 →
  Publish) with spinners, tx hashes as Voyager links as they land, and
  the wrap leg's ~25 GB RAM note shown while it runs.
- **Inbox tab** — decrypted messages (nonce, commitment prefix, text)
  from a manual Refresh button plus an optional 30 s auto-refresh
  toggle; reuses the CLI's `inbox.json` cache.
- **Resume banner** — on launch, `pending_sends` populates a banner per
  incomplete send ("send 1e7560bcf3 stopped at Phase 1 — Resume /
  Dismiss"); Resume runs the same worker path. This is the GUI face of
  the checkpoint system and gets first-class placement, not a menu item.
- **Errors** — a failed step turns its checklist row red with the
  error text in place and a Resume button; no modal error dialogs.

## Threading model

One worker thread at a time (sends are serialized — same as the CLI);
`mpsc::Sender<PipelineEvent>` into the UI; shared `SendState` is NOT
shared — the worker owns it and the UI renders from events plus a
read-only reload of the state file on completion. Balance/status calls
run on short-lived background threads with the same channel pattern
(never block the UI thread on RPC).

## Platform (owner-confirmed 2026-07-07)

**macOS on Apple Silicon only, native builds only** — no cross
compilation, no CI build matrix, no Windows/Linux targets, no
bundling/signing. The GUI is `cargo run -p zkmsg-gui` on the dev
machine, same as the CLI. (The pipeline is macOS-host-bound today
anyway: the local prover checkout, the ~25 GB wrap leg, sncast paths.)
Cross-platform becomes a question only if/when the Tauri product shell
happens.

## Non-goals (v1)

Multi-profile switching in-app, the double-ratchet layer, burner
accounts, watch-mode/event daemon, Tauri shell, mobile, packaging/
signing. Message history for SENT messages beyond the state files.

## Testing

- Core: the 27 tests move unchanged; new unit tests for event emission
  order (fake steps via a state-file fixture) and for the CLI sink's
  line format (string-compare against today's output).
- GUI: the send-flow state machine (events → checklist model) is a pure
  reducer, unit-tested without egui; visual behavior gets a manual
  checklist in the plan (onboarding, compose validation, confirm
  dialog, progress, error+resume, inbox refresh).
- Acceptance: one live Sepolia send driven entirely through the GUI,
  received via the GUI inbox on the second identity.

## Milestones

1. Workspace split + core extraction (CLI output byte-identical, all
   tests green) — commit before any GUI code.
2. Progress events + CLI sink parity.
3. GUI shell: status/onboarding → inbox (read-only value first) →
   compose+send with confirm and progress → resume banner.
4. Live acceptance send + README/docs update.
