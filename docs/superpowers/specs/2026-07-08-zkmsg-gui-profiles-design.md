# zkmsg GUI: in-app profiles + one-click identity creation (2026-07-08)

Approved direction from the 2026-07-08 discussion, immediately after the
GUI shipped (`docs/superpowers/specs/2026-07-07-zkmsg-gui-design.md`):
launch the GUI once and switch identities in-app, and collapse the
manual "new identity" ritual (sncast account create → fund → deploy →
init → register) into a one-confirm wizard. Owner decisions captured
below: root-`.zkmsg` layout, scan-based discovery, switching hard-blocked
while paid work runs, wizard included in this build (not phased).
Cartridge is explicitly NOT wanted (nice UX only); plain accounts
suffice. This wizard is deliberately the mechanical foundation for
burner accounts later.

## Directory layout (owner-specified) + migration

`~/.zkmsg` becomes a **root**, not a profile:

```
~/.zkmsg/
  current              # plain text: name of the last-used profile
  .zkmsg-alice/        # a full home: config.json, keys.json, sends/, inbox.json
  .zkmsg-bob/
```

A **profile** is any `.zkmsg-<name>` child of the root that contains a
`config.json`. Profile names come from directory names — drawing the
picker never touches the network (renaming = renaming a dir). The
migration screen's name *suggestions* come from locally cached
handles in `keys.json`, so migration is offline too.

**Migration is a one-time explicit screen, never silent** — keys are
irreplaceable. On launch, legacy state is detected: a top-level
`config.json` in `~/.zkmsg` itself (today's alice) and any sibling
`~/.zkmsg-*` dirs (today's bob). The screen lists each with an editable
name — pre-filled from the registered handle cached in that home's
`keys.json` (alice, bob), falling back to the dir suffix (empty field
for the legacy root if neither exists) — and one Migrate button. Execution is atomic `rename`s only (entries of
the legacy root move into the new `.zkmsg-<name>` child; sibling dirs
move under the root). Nothing is copied, deleted, or overwritten; a
collision aborts with the error shown in place and keys untouched.

## Discovery, picker, switching

- The profile list = scan the root for `.zkmsg-*` children with a
  `config.json`. Rescanned when the picker opens (cheap, local).
- Picker: a top-bar dropdown next to the tabs showing the active
  profile, plus a `New profile…` entry. The **window title** is
  `zkmsg — <profile>` and updates on switch: it must never be ambiguous
  which identity would pay for a send.
- Switching writes `current`, then drops and rebuilds the session
  (below). Status fetch and the pending-sends resume banner re-run for
  the new home exactly as at launch — alice's pending sends surface
  only under alice.
- **Switching and the picker are disabled while paid work is in
  flight** (a send or a wizard run), with a "work in progress" note.
  The existing `send_in_flight()` generalizes to `work_in_flight()`.
- An empty home (no profiles, no legacy state) → the existing Init
  onboarding renders, not a picker: the wizard needs a funded source
  profile, so a picker over an empty root would be a dead end. A
  `current` naming a missing profile → fall back to the picker, no
  error dialog.

## App structure: session extraction

Every per-identity field of `ZkmsgApp` (config, keys, status, inbox,
compose, send flow, resume banner, and the tab selection — everything
except `repo_root`) moves into a new `ProfileSession` struct constructed
from a `Home`; a fresh session starts on the Status tab, so a switch
lands where the new identity's state is visible. The app owns `Option<ProfileSession>` plus the profile
list and picker state. A switch = drop the session, construct a new
one. This makes cross-identity state leakage impossible by
construction: a field added later is per-profile automatically.
(Rejected: in-place field reset — every future field is a silent leak
footgun; cached multi-session map — no justification once switching
blocks during sends, though session extraction leaves that upgrade
open.)

## New-profile wizard (create → fund → deploy → init → register)

`New profile…` collects: profile name, handle to register (defaults to
the profile name), sncast account name (defaults derived from profile
name), funding amount in STRK (editable, default 60 — one send plus
deploy/register headroom), and the funding **source** = the currently
active profile's account. One confirm dialog states the amount, source
account, and destination before anything moves.

Steps run on a worker thread as a live checklist (same event→reducer
pattern as sends):

1. **CreateAccount** — `sncast account create`; sncast generates the
   keypair and writes the accounts file itself (this is what removes
   the manual copy-paste entirely). Records the precomputed address.
2. **Fund** — STRK ERC-20 transfer of the chosen amount from the
   active profile's account to the new address. Real money movement;
   gated by the confirm dialog above.
3. **Deploy** — `sncast account deploy` for the new account, fees paid
   from the just-transferred funds.
4. **Init** — `zkmsg-core` init into the new `.zkmsg-<name>` dir
   (scan keygen + config with the pinned store/registry defaults).
5. **Register** — the handle, as today's onboarding does.

Like sends, the wizard checkpoints each step (a small state file in the
new profile dir, done-flags written before execution) so a mid-flight
failure (RPC flake, gas spike) shows a red row with a Resume button and
never re-pays a landed step. Fees at stake beyond the retained funding
amount are small (transfer + deploy + register ≈ well under 1 STRK
total). The funded STRK itself remains the user's, on the new account.

## CLI and the new layout

Resolution lives in `zkmsg-core` (new `profiles` module), shared by
both frontends: a `--home` path **containing `config.json` is used
directly** (explicit profile dirs and un-migrated legacy homes work
unchanged); a path that is a root resolves through its `current` file.
Bare `zkmsg status` therefore follows whatever profile the GUI last
used. No CLI flags change; no output line changes. The GUI keeps
`--home <root>` (default `~/.zkmsg`) and gains `--profile <name>` to
bypass `current` for scripting.

## Threading & money safety (unchanged rules)

Pipeline/wizard/status/inbox all stay on worker threads + `mpsc` +
`request_repaint` — the UI thread never blocks on RPC or subprocesses;
no async runtime. Both spend paths (send confirm, wizard confirm) state
the cost explicitly, and `work_in_flight()` guards every entry point to
paid work AND profile switching, closing the class of race the
2026-07-07 whole-branch review found in the send path.

## Testing

- Core (`profiles` module): discovery, home resolution, and the
  migration plan (what-moves-where, collision refusal) are pure
  functions unit-tested against temp-dir fixture trees. No network.
- GUI: the wizard checklist reducer is pure and unit-tested like
  `SendFlow`. Session teardown/rebuild is exercised by the manual
  checklist (switch alice↔bob: status, inbox, banner, title all flip).
- Acceptance: migration of the real alice+bob homes, then free
  switching between them (0 STRK). Wizard acceptance creates one real
  third identity end-to-end (≈1 STRK in fees + a funding transfer the
  user keeps). A paid send FROM the new identity is optional, owner's
  call at acceptance time.

## Non-goals

Burner UX policy (auto-named throwaway profiles, per-send funding) —
next step, built on this wizard. Cartridge integration — rejected by
owner. Cached multi-session switching / sends continuing across a
switch. Importing externally-created keys. Multi-window (one window,
one active profile).
