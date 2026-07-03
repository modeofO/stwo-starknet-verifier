# How this whole thing works

Three passes over the same machine. Pass 1 is deliberately primitive — get
the shape of the idea. Pass 2 is the honest engineering story. Pass 3 walks
the actual code and transactions in this repository.

---

## Pass 1 — caveman speak

**Og run program. Og want tribe to believe result. Tribe not want to re-run
program — program long, tribe busy.**

Old way: tribe re-runs program, checks answer. Works, but now whole tribe
does Og's work. Bad.

New way: Og does the work **once**, and while working, writes everything on
a huge stone tablet — every step, every scratch mark. Then Og does clever
thing: Og smashes tablet into magic summary. Magic summary is small, but it
has a property: **if even one step on the tablet was a lie, the summary
cannot be made.** Faking the summary is harder than just doing the work
honestly.

Tribe doesn't read whole tablet. Tribe pokes the summary in a few random
spots — "show me step 4,512. Show me step 89,001." If Og lied anywhere,
random pokes catch the lie almost surely, because the magic smearing spread
every lie everywhere. Few pokes, big confidence. This is a **proof**. Og is
the **prover**. Tribe is the **verifier**.

Problem one: the tribe here is a **blockchain**. Blockchain is very
suspicious and very expensive tribe. Every poke costs shells. Og's summary
is still too big and poking it costs too many shells — more shells than the
tribe allows for one sitting (the chain has a per-sitting shell limit).

Problem two: how does suspicious tribe pick the random poke spots? If Og
picks, Og cheats. Trick: the poke spots are chosen by **hashing everything
Og has committed so far**. Og cannot control the hash, so Og cannot know the
poke spots before committing. Self-service randomness that cannot be gamed.

The big trick for problem one: **a proof about checking a proof.** Og gives
the summary to a helper. Helper checks the whole summary — and while
checking, helper writes their OWN tablet ("I checked steps 1 through end,
all good") and smashes THAT into a much smaller summary. Small summary says:
"someone correctly verified Og's proof." Checking the small summary is cheap
enough for the stingy tribe. And the helper **cannot cheat**: if the helper
skips a check or lies, their own summary cannot be made. Helper is not
trusted. Helper is just a strong arm doing squashing work.

Even the small summary needs two sittings with the tribe (shell limit!). So
the tribe's checker pauses halfway, carves a small note of where it stopped
("my dice-state was THIS, my poke list was THIS"), and finishes in the next
sitting. The note makes the two sittings exactly equal to one long sitting.

When the tribe is satisfied, it carves a **mark** into the village rock:
"program with hash X produced output Y. True." Forever. Anyone can look at
rock. Messaging hut checks rock before delivering message. Done.

That's the entire system: work once → magic summary → untrusted squasher →
suspicious tribe pokes cheaply, in two sittings → mark on rock.

---

## Pass 2 — the same story, engineering words

**The statement.** We want the chain to accept: *"Cairo program with hash P,
run on some inputs, produced public outputs O."* The witness (private
inputs) stays with the prover.

**STARK proving.** Running a Cairo program produces an **execution trace** —
a big table where every row is one VM step. Correct execution means the
table satisfies a set of polynomial constraints (the **AIR** — "each row
follows from the previous one per Cairo's rules"). The prover:

1. encodes trace columns as polynomials over a small prime field (Stwo uses
   **M31** = 2³¹−1, extended to QM31; "Circle STARK" refers to doing this
   on a circle group where M31 behaves nicely),
2. **commits** to them with Merkle trees (hash tablets: can't change a cell
   afterward without changing the root),
3. proves the constraints hold via a random linear combination checked at a
   random out-of-domain point (**OODS**), and
4. proves the involved polynomials are actually low-degree — the part that
   makes lying infeasible — with **FRI**: repeatedly fold the polynomial in
   half, commit each layer, then answer random **queries** by opening
   Merkle paths through all layers.

**Fiat-Shamir.** Every "random" choice (the OODS point, FRI folding
coefficients, query positions) is drawn from a hash **channel** fed by
everything committed so far. The prover can't predict challenges before
committing, so a transcript replaces an interactive skeptic. The verifier
re-derives every challenge the same way — which is why verification is
*replaying a conversation*, and why our two-transaction split later just has
to save/restore the channel state faithfully.

**Why not verify the app proof directly on-chain?** We measured it (Spike
2): the general Cairo verifier costs 10–16M Cairo steps — right at or above
Starknet's whole per-transaction budget — and app proofs are 65k–223k felts
against a 5,000-felt calldata cap. Dead end at today's limits (that direct
path is "lane 2", the sovereign lane — possible, but as a multi-transaction
state machine).

**Recursion.** So instead: run a *verifier* off-chain and prove *its*
execution. Concretely, three layers (Spike 3):

1. the app program runs under a small **bootloader** program (gives every
   proof one standard shape and hashes the app program + outputs),
2. that bootloader run is Stwo-proven → the big "app proof",
3. a circuit re-implements the Stwo verifier; running it over the app proof
   and proving *that* yields a **circuit proof** ("this app proof
   verifies"), and a second, fixed-topology **multiverifier** circuit
   verifies two such circuit proofs and hashes their claims together.

Each wrap can't launder a lie: an invalid inner proof makes the outer
witness unsatisfiable. The outermost proof is small (~36k felts) and —
because the multiverifier's topology never changes — costs the *same* to
verify no matter what program is inside. That constant is ~3.8M steps:
affordable.

**On-chain (this repo).** The chain runs a Cairo implementation of the
circuit verifier over that final proof. Practical obstacles and their
solutions, all measured the hard way:

- *Proof (36k felts) > calldata cap (5,000).* Pack 7 little-endian u32
  limbs per felt (proof streams are essentially u32 data) → 5,147 slots;
  put most in one transaction's calldata, stage the remainder in storage.
- *Verification (~1.4e9 gas) > per-invoke cap (1.21e9).* Split at the FRI
  boundary into **phase 1** (transcript replay, OODS check, trace Merkle
  openings, FRI first-layer answers) and **phase 2** (FRI folding +
  decommitment), carrying a ~130-felt checkpoint: channel digest, PoW
  nonce, query positions, first-layer evaluations, fact material. Phase 2
  receives the FRI section via calldata, *bound* to phase 1's transcript:
  any tampering changes the derived query positions, which must equal the
  checkpointed ones.
- *Verifier code (CASM) > 81,920-felt class cap.* Split into two library
  classes + a tiny registry that `library_call`s them; class hashes pinned
  immutably at construction.

**The fact.** On success the registry stores
`fact = poseidon(blake2s(multiverifier_root ‖ output_values))`. Those output
values are themselves a blake2s chain ending in
`[n_tasks, output_len, app_program_hash, app_outputs…]` — so the fact binds
*which program* ran and *what it output*. A consumer contract (messagezk's
`MessageStore`) recomputes the expected chain for its known program hash and
claimed outputs and calls `is_valid(fact)`. One storage read.

**Trust model.** The client proves (witness never leaves). The wrapper
compresses (untrusted — can only refuse, never forge). The chain verifies
(actual cryptography, two transactions). The registry remembers.

---

## Pass 3 — the code, end to end

Follow one real artifact: `poseidon_chain(100)`, whose fact
`0x640299e88691d8a8eaf2c71bcde2c72334ad177e64c4485be069c5f6dcd615c` is live
on Sepolia (registry `0x0194f440…c6aa`).

**0. The app program** — `fixtures/poseidon_chain/src/lib.cairo`. A
`#[executable]` hashing a Poseidon chain of length `n`. Stand-in for the
messagezk circuit.

**1. Prove + wrap** — `tools/privacy-prove-cairo-bridge/src/main.rs`
(installed into StarkWare's `proving-utils` by `scripts/setup-prover.sh`;
one command: `scripts/prove-and-verify.sh`). Its five stages map exactly to
Pass 2's recursion story:

- `[1/5]` `run_privacy_bootloader_task(Task::Cairo1Program(...))` — the app
  executable runs as a bootloader task.
- `[2/5]` `prove_cairo::<Blake2sM31MerkleChannel>` — the big app proof.
- `[3/5]` `build_fixed_cairo_circuit(...)` + `prove_circuit_assignment(...)`
  — the cairo-verifier circuit checks the app proof; proving its wire
  assignment is the first wrap. Note `component_enable_bits` handling: the
  circuit is configured for *this proof's* component set.
- `[4/5]` `build_multiverifier_circuit(input, input, &shared_config)` — the
  fixed-topology outer circuit over two copies of the inner proof, proven
  with the plain `Blake2sMerkleChannel` (the flavor the on-chain verifier
  speaks).
- `[5/5]` `prepare_circuit_proof_for_cairo_verifier(...)` — serialize to
  the felt stream the Cairo verifier deserializes. 36,022 felts.

**2. Pack** — `scripts/pack_proof.py`, mirrored on-chain by
`unpack_proof` in `contracts/stwo_verifier_phases/src/lib.cairo`. 36,022
values → 5,147 slots. (Gas archaeology: unpacking via u256 div-rem cost
6.7e8 gas; the shipped u128 version costs 1.8e8 — see
`docs/lane1-results.md`.)

**3. The three transactions** — interface in
`contracts/stwo_fact_registry/src/lib.cairo` (`IStwoFactRegistry`):

- `stage_proof(proof_id, offset, slots)` — the 156-slot tail into storage,
  keyed by caller (no third-party griefing). Head goes in tx 2's calldata:
  4,991 slots, because the 5,000-felt limit includes the account's
  `__execute__` envelope (~4 felts).
- `verify_phase1(proof_id, head, n_tail_slots, n_values)` — assembles the
  stream and `library_call`s `StwoPhase1`.
- `verify_phase2(proof_id, fri_slots, n_fri_values)` — the FRI section
  (offset 23,130 in this proof's stream, returned by phase 1) as calldata;
  `library_call`s `StwoPhase2`; derives and stores the fact; emits
  `FactRegistered`.

**4. Inside the phases** —
`contracts/stwo_verifier_phases/src/resumable.cairo`, a fork of the
vendored `verify_circuit` (mirror sources noted in the module doc; the
handful of upstream `pub` patches are logged in
`vendor/stwo_cairo_verifier/VENDORED.md`).

- `phase1` deserializes the proof field-by-field (capturing
  `fri_value_offset`), then replays the vendored prologue verbatim: claim
  checks against `privacy_consts` (the hardcoded multiverifier topology —
  PCS config, preprocessed root), channel mixes, interaction PoW, logup
  sum, the OODS composition check
  (`eval_composition_polynomial_at_point` vs
  `try_extract_composition_eval`), Merkle openings for the four trees, and
  `fri_answers` (first-layer evaluations at the query positions).
- The `Checkpoint` struct is the seam: channel digest — captured
  immediately after `mix_sampled_values`, where `n_draws == 0`, so
  `new_channel(digest)` restores the exact Fiat-Shamir state — plus PoW
  nonce, query positions, first-layer evals, fact material, FRI offset.
- `phase2` restores the channel, replays the FRI commitment over the
  calldata-supplied `FriProof`, re-checks PoW, re-derives query positions
  and **asserts they equal the checkpointed ones** (the tamper-binding),
  then runs `fri_verifier.decommit(...)` — the folding walk down to the
  last layer.

**5. The fact** — `fact_from_words` in the registry: `poseidon` over the 8
u32 words of `blake2s(multiverifier_root ‖ outputs)`. The output preimage
for our artifact decodes as `[0x1, 0x3, program_hash, 0x10bd76…721]` — and
`0x10bd76…721` is precisely `poseidon_chain(100)` computed directly. That
equality is what makes the fact *mean something* to a consumer.

**6. The evidence** — tests in
`contracts/stwo_fact_registry/tests/test_fact_registry.cairo`: the full
3-tx flow over the real proof; corrupted-head rejection (phase 1 panics);
tampered-FRI rejection (phase 2's query binding); phase-2-without-phase-1
rejection; per-phase cost probes. On-chain: phase 1
[`0x0681808c…79a0`](https://sepolia.voyager.online/tx/0x0681808ccfaa92f35dfe9ddb44474bf718c07ef0dd40f6f0517e3d22aa3a79a0)
(873,757,120 gas), phase 2
[`0x06b7f69f…8730`](https://sepolia.voyager.online/tx/0x06b7f69fcc931cf1e93cbae5a14e254de539e6f91609fceed60b3f93b8188730)
(815,669,840 gas).

**Where each piece runs today**: proving + wrapping are native Rust
(laptop: ~2–3 minutes). The base proof can already be made in-browser (the
Stwo WASM prover); moving the *wrap* into clients is the open WASM
feasibility question (memory is the risk), and a native client app dodges
that ceiling entirely. The chain does not know or care where a proof was
made — only whether it verifies.

## Pointers for going deeper

- Measurements and decisions: `docs/spike1-results.md` (compile/size),
  `docs/spike2-results.md` (the cost numbers + builtin matrix),
  `docs/spike3-results.md` (recursion end-to-end),
  `docs/lane1-results.md` (registry + Sepolia campaign).
- Architecture and the two-lane plan: `docs/architecture.md`.
- The proof system itself: the Circle STARKs paper
  (eprint.iacr.org/2024/278) and the vendored verifier sources under
  `vendor/stwo_cairo_verifier/crates/` — `verifier_core/src/fri.cairo` and
  `channel/blake2s.cairo` are the most readable entry points.
