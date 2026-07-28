# Companion protocol (Phase B)

This document defines the wire contract between the zkmsg phone client and the
desktop companion daemon. The phone composes a message. The daemon proves,
wraps, and sends it. The daemon holds the sender identity and the funded
account; the phone holds neither.

This is the "desktop is sender, phone drives it" topology. The daemon reuses
the proven Rust pipeline without change. The phone is a compose-and-monitor
remote.

## Transport and trust

- The daemon runs on the sender's own desktop. The phone reaches it over a
  private network, such as Tailscale or a LAN. The daemon binds to that
  interface, not to a public address.
- Every request carries `Authorization: Bearer <token>`. The daemon prints the
  token once at first start. The user enters it on the phone during pairing.
- A request without a valid token gets `401`. The daemon does not fall back to
  an unauthenticated mode.
- The two parties share one trust domain: the same person owns both devices.
  The witness never leaves the desktop, because the phone never sends one.

## Server

- HTTP/1.1, JSON bodies, one base path `/v1`.
- A blocking, threaded server fits the pipeline, which blocks on subprocess
  proving. Use `tiny_http`. Do not add an async runtime.
- Content type is `application/json` for all bodies except the event stream,
  which is `text/event-stream`.

## Endpoints

### GET /v1/health

Reports the daemon identity and readiness. No side effects.

```json
{
  "version": "1",
  "chain_id": "0x534e5f5345504f4c4941",
  "handle": "alice",
  "account_address": "0x0733...600c",
  "store": "0x02d6...91b7",
  "registry": "0x0194...c6aa",
  "ready": true
}
```

`ready` is false when the daemon has no registered handle or no funded account.
The phone shows this state and does not offer to compose.

### GET /v1/resolve?handle=<h>

Resolves a recipient handle to its tree membership. Mirrors
`app::resolve_recipient`.

- `200` → `{ "handle": "bob", "leaf_index": 4, "scan_pub": "0x..." }`
- `404` → `{ "error": "handle not registered" }`

The phone calls this as the user types, to confirm the recipient exists before
a send.

### POST /v1/sends

Starts a send. The daemon resolves the recipient, builds the 46-arg witness
from its own keys, encrypts the message, persists a resumable `SendState`, and
runs the pipeline on a background thread. Mirrors `app::prepare_send` then
`Pipeline::run`.

Request:

```json
{ "recipient_handle": "bob", "message": "the plaintext" }
```

Response `201`:

```json
{
  "send_id": "4535d6880c",
  "recipient_handle": "bob",
  "ciphertext_bytes": 41,
  "steps": [
    { "kind": "Prove", "done": false },
    { "kind": "Wrap", "done": false },
    { "kind": "Pack", "done": false },
    { "kind": "Phase1", "done": false },
    { "kind": "Phase2", "done": false },
    { "kind": "SendMessage", "done": false }
  ]
}
```

The `steps` array is the plan before staging. The daemon appends `Stage` steps
after `Pack`, so the live plan can grow. The phone learns the final plan from
the event stream, not from this response.

Errors:

- `404` → the recipient handle is not registered.
- `409` → the daemon is not ready (no handle or no funds).
- `422` → the message is empty or too long.

### GET /v1/sends

Lists recent sends, newest first.

```json
{ "sends": [ { "send_id": "4535d6880c", "recipient_handle": "bob",
  "state": "running", "fact": null } ] }
```

`state` is one of `running`, `done`, `failed`.

### GET /v1/sends/{id}

Returns a full snapshot for reconnect. The phone calls this when it opens a
send or after the event stream drops.

```json
{
  "send_id": "4535d6880c",
  "recipient_handle": "bob",
  "state": "running",
  "fact": null,
  "error": null,
  "steps": [
    { "kind": "Prove", "done": true, "tx_hash": null,
      "note": "preimage tuple verified" },
    { "kind": "Wrap", "done": true, "tx_hash": null,
      "note": "inner root verified" },
    { "kind": "Pack", "done": true, "tx_hash": null, "note": null },
    { "kind": "Stage", "offset": 0, "done": true, "tx_hash": "0x..." },
    { "kind": "Phase1", "done": false, "tx_hash": null, "note": null }
  ]
}
```

### GET /v1/sends/{id}/events

Streams pipeline progress as Server-Sent Events. Each event `data:` line is one
JSON object. The daemon sends a comment line (`:keep-alive`) every 15 seconds so
the phone can tell a live stall from a dead socket.

The phone may reconnect with `Last-Event-ID`. The daemon replays from that id.
When replay is not possible, the phone falls back to the snapshot endpoint.

Event objects, one `type` each:

```json
{ "type": "step_started", "index": 3, "total": 6, "kind": "Phase1" }
{ "type": "tx_submitted", "kind": "Phase1", "tx_hash": "0x..." }
{ "type": "step_completed", "kind": "Phase1", "tx_hash": "0x...",
  "note": "fri_offset 812" }
{ "type": "failed", "kind": "Phase2", "error": "tx reverted: ..." }
{ "type": "done", "fact": "0x4535..." }
```

`step_started`, `tx_submitted`, and `step_completed` map one to one onto the
existing `PipelineEvent` variants. `failed` and `done` are daemon-level and
close the stream.

### POST /v1/sends/{id}/resume

Re-enters the pipeline at the first incomplete step. Mirrors `cmd_resume`. Safe
to call on a `failed` send after the cause is fixed, such as a funded account or
a recovered network. Returns the same shape as `POST /v1/sends`.

## Step kinds

The `kind` strings are the `StepKind` variants: `Prove`, `Wrap`, `Pack`,
`Stage`, `Phase1`, `Phase2`, `SendMessage`. A `Stage` step also carries an
`offset` integer. The phone renders friendly labels; the wire uses these exact
names.

## What the phone must not expect

- The phone never receives the witness, the proof, or any key. It receives
  progress and the final fact.
- The phone does not submit transactions in this topology. The daemon signs and
  submits. Transaction hashes are for display and Voyager links only.
