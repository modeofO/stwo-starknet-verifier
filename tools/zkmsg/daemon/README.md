# zkmsg companion daemon (`zkmsgd`)

`zkmsgd` lets a phone drive a send while the desktop holds the identity and
does the proving. The phone composes a message and watches progress. The
daemon resolves the recipient, builds the witness from its own keys, proves,
verifies on Starknet, and publishes. The phone never holds a key, a witness,
or a proof.

This is the "desktop is sender, phone drives it" topology. The daemon is a
thin HTTP shell around the same Rust pipeline the CLI runs. The wire contract
is `docs/companion-protocol.md`; read it for the endpoint and event shapes.

## Build

```
cd tools/zkmsg
cargo build --release -p zkmsg-daemon
```

The binary is `target/release/zkmsgd`.

## Start it

The daemon speaks for the same identity `zkmsg` does. Set that identity up
first with `zkmsg init` and `zkmsg register`. Then start the daemon on the
same home.

```
zkmsgd                       # binds 127.0.0.1:8787, home ~/.zkmsg
zkmsgd --addr 127.0.0.1:9000 # a different port
zkmsgd --home ~/.zkmsg/.zkmsg-alice   # a specific profile
```

`--home` accepts a profile directory or a profile root. A root follows its
`current` profile, exactly like the CLI. `ZKMSG_DAEMON_ADDR` overrides
`--addr`.

At first start the daemon mints a bearer token, stores it at
`<home>/daemon-token` (mode 0600), and prints it once with the pairing URL:

```
  PAIRING (shown once)
  base URL : http://127.0.0.1:8787/v1
  token    : 043a28624bb2d63b8...
```

## Pair a phone

1. Put the phone and the desktop on one private network. A Tailscale tailnet
   is the recommended path; a trusted LAN also works.
2. Start the daemon bound to that interface, not to loopback. Pass the
   private address:

   ```
   zkmsgd --addr 100.x.y.z:8787   # the desktop's Tailscale IP
   ```

3. On the phone, enter the base URL and the token from the pairing banner.
4. The phone calls `GET /v1/health`. A `ready: true` response means the
   daemon has a registered handle and a funded account, and the phone offers
   to compose.

To re-pair, delete `<home>/daemon-token` and restart. The daemon mints a new
token. The old token stops working.

## Security posture

- **Bind private.** The default bind is loopback. For a phone, bind a
  Tailscale or LAN interface. Do not bind a public address.
- **Every request needs the token.** The daemon checks `Authorization:
  Bearer <token>` on every route. A missing or wrong token gets `401`. There
  is no unauthenticated mode.
- **The witness never leaves the desktop.** The phone sends a recipient
  handle and a plaintext message. The daemon builds the witness, proves, and
  signs locally. The phone receives progress and the final fact only. It
  never receives a key, a witness, or a proof, and it never signs a
  transaction.
- **One trust domain.** The daemon and the phone assume one owner. The token
  gates network access; it is not a second factor against the desktop's own
  user.

## Concurrency and restarts

- The daemon serves each request on its own thread, so health, resolve,
  snapshot, and the event stream stay responsive while a send proves.
- The daemon runs one pipeline at a time. Proving is RAM-heavy, so a second
  send queues behind the first on a global lock.
- The daemon persists each send through the same checkpoint file the CLI
  uses. A restart lists prior sends and resumes an interrupted one at its
  first incomplete step (`POST /v1/sends/{id}/resume`). No landed
  transaction is re-paid.

## Test

```
cd tools/zkmsg
cargo test -p zkmsg-daemon
```

The tests cover the event-to-JSON mapping, the auth gate, the SSE fan-out and
`Last-Event-ID` replay, the readiness gate, and the resolve handler against a
fake chain. A scripted runner drives a full send with no prove and no chain.
The tests never run a real prove or touch Sepolia.
