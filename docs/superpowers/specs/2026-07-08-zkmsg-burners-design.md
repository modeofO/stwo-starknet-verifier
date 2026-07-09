# zkmsg GUI: burner accounts (2026-07-08)

Approved direction from the 2026-07-08 discussion, immediately after
profiles + the identity wizard shipped
(`docs/superpowers/specs/2026-07-08-zkmsg-gui-profiles-design.md`).
Burners are UX policy on top of the shipped wizard: auto-named
throwaway sender identities, externally funded, swept and archived
after use. They address the one honest privacy gap in the README's
"what's public" list — *"public: that YOUR account sent something"* —
by making the sending account a fresh one with **no on-chain edge to
any account you own**.

Owner decisions captured: manual flow (create burner → switch → send;
the chained one-confirm "send as burner" is explicitly deferred),
**external-only funding for burners** (an in-app transfer from the
active profile would be a public funding edge and defeat the point),
sweep+archive offered after the send with an explicit linking warning,
and an optional from-line inside the encrypted plaintext (default on)
so the recipient can reply. Cartridge remains rejected (standing
decision). The wizard's flat 60-STRK funding default is replaced by a
live-price recommendation (the ledger's DEFERRED follow-up from
carol's mid-send stall).

## Threat model, stated honestly

What a burner buys: the send/verify/publish txs are signed by a
fresh account funded from outside the user's account graph, registered
under a random handle. A chain observer sees *a* registered user sent
something, not *which* one you are.

What it does not buy, and the docs must say so:

- The anonymity set is the registered-user count (tiny on Sepolia).
- Timing correlation remains (registration shortly before a send).
- Stwo proofs are not formally ZK (unchanged caveat).
- Reusing a burner links all its sends to each other. The UI states
  "one send per burner" as policy but does not hard-block a second
  send.
- Sweeping leftover STRK back to a profile you own draws the linking
  edge after the fact. The sweep prompt says exactly that; declining
  is a first-class choice.

## Burner mode in the wizard

The picker gains a **New burner…** entry beside **New profile…**,
opening the existing wizard in burner mode:

- **Auto-identity**: profile name and registered handle are both
  `burner-<6 lowercase hex chars>` from OS randomness — the handle is
  public on-chain forever, so it must never derive from the user or
  the machine. Account name `zkmsg-burner-<hex>`. All still editable,
  but prefilled so the default path is zero typing.
- **Burner metadata** in the new profile's `config.json`:
  `burner: true` and `reply_handle: <active profile's handle>` — both
  local-only (no chain trace), both serde-defaulted
  (`false` / `None`) so every existing `config.json` and the CLI load
  unchanged.
- **No source account.** Burner mode never draws from the active
  profile; the confirm dialog states the deposit target and that the
  app will wait for an external deposit, not move money.

The regular (non-burner) wizard path is unchanged apart from the
funding default (below).

## External funding: a second Fund mode

`SetupState` gains

```rust
pub enum FundMode {
    /// STRK transfer from `source_account` (today's behavior).
    Transfer,
    /// Wait until the new address holds >= the target; nothing is sent.
    External,
}
```

serialized with `#[serde(default)]` → `Transfer`, so carol-era
`setup.json` checkpoints load and resume identically.

External Fund step semantics: read the burner's balance (the
`read_balance_fri` / `fund_needed` pair from the resume guard,
reused); if the balance covers `fund_strk`, the step is done
(note "funded externally"); if not, the runner **parks** — it emits a
new `SetupEvent::AwaitingDeposit { address, target_strk, balance_fri }`
and returns `Ok(())` with Fund still pending. Parking is not an
error: the checkpoint file is exactly as valid as after any other
step. (The single app-level wizard slot is unchanged — parked state
lives on disk, not in the slot, so dismissing the card frees the slot
for other work.)

GUI: the wizard checklist renders a waiting card at the Fund row —
the burner address (selectable text), the target amount, the current
balance, and a **Refresh** button that re-spawns the runner (which
re-checks and either parks again or proceeds through
deploy → init → register). Because a parked runner returns `Ok(())`
without finishing, the GUI must key wizard completion on the
`Completed` event (`flow.completed`), never on `Done(Ok)` alone —
`Done(Ok)` + not completed = parked. The waiting card is dismissible
(state lives in `setup.json`); a parked burner appears in the picker
via the existing `setup_incomplete` machinery as
"`<name>` (awaiting funding)" — distinguishable because its loaded
`SetupState` has `FundMode::External` with Fund next pending — and
selecting it reopens the waiting card.

**Locking.** A deposit wait can last hours and must not wedge the
app. Parked means the worker thread has returned and the receiver is
dropped, so `work_in_flight()` is false naturally — the picker,
compose, and a concurrent regular wizard all stay live. The paid
segment (deploy → init → register, about a minute, paid by the
burner's own funds) holds the lock exactly as today. The lattice is
otherwise untouched. Note the pleasant consequence: in burner mode
the user's existing accounts **never sign anything** — create is
local, everything after Fund is paid by the burner itself.

## Live-price funding recommendation

New pure function in `zkmsg_core` (shared constants with
`pipeline::bounds_for` — single definition, not copies):

```rust
/// Recommended funding for one send from a fresh account, in whole
/// STRK, from live (l1, l2, l1_data) gas prices.
pub fn recommended_funding_strk(prices: (u128, u128, u128)) -> u64
```

The binding constraint is sequential worst-case-bounds validation
(carol's stall, measured): the account must hold each tx's bounds
product at submission, so after phase 1's *actual* fee lands it still
needs phase 2's *bounds product*. Model:
`actual(stage) + actual(phase1) + bounds_product(phase2) +
publish + deploy + register + margin`, with actuals from the measured
l2 amounts (~0.87e9 / ~0.80e9) at live prices and bounds products
from `bounds_for`'s numbers (×1.5 prices). Roughly `2.4e9 × l2_price`
plus small terms: ≈70 STRK at 28 fri/gas, ≈108 at carol's 43.9 —
which is why the flat 60 failed. Unit-tested against fixed price
tuples (the two data points above).

Used in two places: the burner wizard's deposit target, and the
regular wizard's funding default (still editable). Computed on the
worker thread (it needs one `gas_prices()` RPC) with a static
fallback if the read fails.

## From-line (reply path)

A burner send carries no sender identity, so the recipient cannot
reply. Compose, when the active profile has `burner: true` and a
`reply_handle`, shows a checkbox **"reveal my handle to the
recipient"**, default on, which prepends `from: <reply_handle>\n` to
the plaintext before encryption. It rides inside AES-GCM — only the
recipient ever sees it; public unlinkability is intact.

Inbox (GUI only): if a decrypted message's first line matches
`from: <handle>` (ASCII, ≤31 chars — the registered-handle shape),
render it as a small sender chip above the body instead of as body
text. Pure function, unit-tested. The CLI inbox output is untouched
(prints raw plaintext, from-line and all) — the byte-parity gate
holds because CLI behavior simply does not change.

No envelope version, no protocol change: a from-line is a plaintext
convention any client may ignore.

## Sweep + archive

After a burner's send pipeline completes (and any time from the
picker via an **Archive…** action on burner entries), a prompt:

> Sweep ~N STRK to `<target>` and archive this burner?

- **Target**: dropdown of the other profiles' accounts (default: the
  profile named by `reply_handle`, else first non-burner). The prompt
  carries the warning verbatim: *"the sweep transfer is a public
  on-chain edge linking this burner to the target."*
- **Sweep** = one STRK transfer of `balance − fee headroom` signed by
  the burner (small tx, default sncast estimation), wait receipt.
- **Archive** = `fs::rename(root/.zkmsg-<name>, root/archive/.zkmsg-<name>)`
  (creating `root/archive/` as needed). Never copy, never delete —
  keys are irreplaceable; un-archiving (moving the dir back) restores
  the profile, including reading late replies addressed to the burner
  handle. `list_profiles` only matches `.zkmsg-*` direct children, so
  `archive/` is invisible to the picker for free. If the archived
  profile was `current`, the app falls back to the picker (existing
  behavior for a dangling `current`).
- All three combinations are legal: sweep+archive, archive only
  (leftover STRK stays on the burner — the unlinkable choice), or
  neither (dismiss; burner remains a normal profile).

Sweeping/archiving is paid+destructive-adjacent work: the sweep runs
on a worker under the `work_in_flight()` lock; archive (a rename)
happens only after the sweep receipt (or immediately if no sweep),
and only when no work is in flight.

## Merkle-tree growth (assessed, no change)

Every burner registration appends one leaf to the depth-20 tree
(~1M capacity — decades of burners) and rotates the root. Sends pin
the root at `prepare_send`; a registration landing between prepare
and publish invalidates that send's proof against the *current* root
only if the store checks recency — this race predates burners and is
unchanged by them. In the manual flow the burner registers first and
prepares after, so it cannot race itself.

## Cleanup wave (DEFERRED minors, folded in)

- **NotNow root-restore edge**: "Not now" on migration when a genuine
  root has a legacy sibling currently wipes the classification-derived
  root (over-restricts; relaunch recovers). Restore it correctly.
- **`--profile` silent fallback**: GUI `--profile <name>` naming a
  missing profile silently falls back to `current`; make it surface
  (picker error), not silently open someone else.
- **`picker_error` has no dismiss**: add one (an ✕ on the error line).
- **`ProfileEntry.handle` loaded but undisplayed**: picker rows become
  `name (handle)` when the handle differs from the name; burner rows
  gain their state suffix ("awaiting funding").

## Testing

- Core: `FundMode` serde back-compat (carol-era setup.json fixture
  string), external-fund park/proceed boundaries (reusing the
  `fund_needed` boundary tests), `recommended_funding_strk` against
  the two measured price points, sweep-amount math, burner-name
  generator shape (6 hex, handle-legal).
- GUI: reducer tests for `AwaitingDeposit` (parked row state,
  Refresh re-entry), from-line prepend + inbox chip parse (pure
  functions), archive-refuses-while-in-flight.
- CLI parity: suite must show zero output changes (burner fields are
  serde-defaulted; CLI never branches on them).
- Acceptance (user-driven, real STRK): create a burner, deposit the
  recommended amount externally, watch park → Refresh → deploy →
  register; switch, send to alice with the from-line on; alice's
  inbox shows the chip; sweep+archive with the warning shown. Funding
  the deposit from alice/bob draws the very link burners avoid —
  acceptable for a testnet rehearsal, owner's call at acceptance
  time.

## Non-goals

Chained one-confirm "send as burner" (deferred by owner — manual flow
is fine for now). In-app transfer funding for burners (defeats the
point). Structured envelope v2 (from-line convention suffices).
Cartridge (standing rejection). Hard-blocking burner reuse. Mixing,
relayers, or any funding-anonymity machinery beyond "the app never
draws the edge".
