# WPA3 Capability — Design Spec

**Date:** 2026-05-30
**Status:** Approved (pending implementation plan)
**Scope:** Make smartdos effective against WPA3 networks — disruption-focused, not password cracking.

## Goal

Add WPA3-aware attack and detection capability to smartdos. The user is interested in
**disruption/DoS**, transition-mode downgrade, PMF-aware targeting, and live awareness of
SAE activity. **Password/handshake cracking is explicitly out of scope** — no PMKID
extraction, no crackable-pcap output for WPA3.

## Background / what already exists

- **Scanner already decodes RSN AKM suites** (`parse_rsn_ie`, `scanner.rs`) and labels
  encryption as `WPA3` (SAE, AKM 8/9), `W2/W3` (SAE+PSK transition), `OWE`, `WPA2`,
  `W2-Ent`, `W2/T`. WPA3 detection per se already works.
- **5/6GHz channel constants** (`CHANNELS_5GHZ`, `CHANNELS_6GHZ`) and band detection
  (`freq_to_band`) exist.
- **Attack thread** uses a clean, extensible pattern: pure `build_*_frame` builders
  (unit-tested) wrapped by `send_*_frame` pcap senders, dispatched by an `AttackType`
  match. The thread is currently **TX-only** (`cap.sendpacket`).
- **CI gate** (`.github/workflows/ci.yml`) runs `cargo test` (pure logic, any OS) +
  `cargo check` for the `cfg(target_os = "linux")` capture/injection glue.

## Key technical framing (why two tiers)

WPA3-SAE has a built-in DoS defense: **anti-clogging tokens** (802.11 §12.4). Under load,
a compliant AP does *not* run the expensive curve math on the first Commit frame — it
replies with `status 76` (ANTI_CLOGGING_TOKEN_REQUIRED) plus a token, and only performs
the costly Password Element (PWE) / confirm derivation when the client resends the Commit
echoing a valid token. Therefore:

- **Tier 1 — stateless flood.** Fire well-formed group-19 Commit frames from spoofed
  source MACs, ignore replies. Forces work on APs where anti-clogging is off, broken, or
  below threshold (Dragonblood found several such firmwares). Cheaply deflected by a
  fully-patched AP.
- **Tier 2 — token round-trip.** Receive the AP's `status 76` + token, resend the Commit
  with the token, forcing the AP through the full PWE/confirm derivation. Effective even
  against hardened APs. **Requires adding an RX path to the attack thread**, which is the
  single largest architectural change in this effort.

Both tiers are in scope.

## Components

### 1. Data model (`types.rs`)

- `enum Pmf { Disabled, Optional, Required }` — 802.11w management-frame-protection state.
- `AccessPoint`: add `pmf: Pmf` and `sae_seen: u64`.
- `AttackType`: add `SaeFlood` variant.
- `ScannerEvent`: add `SaeFrame { bssid: String }` (awareness signal).
- `AttackEvent`: extend with SAE flood counters — `sent`, `tokens_rx`, `completed`
  (e.g. a new `SaeFloodStats { bssid, sent, tokens_rx, completed }` variant).

### 2. SAE Commit builder (`attack.rs`)

`build_sae_commit_frame(bssid: &str, src_mac: &[u8; 6], scalar: &[u8; 32], element: &[u8; 64], token: Option<&[u8]>) -> Vec<u8>`

- 802.11 Auth management frame, subtype 11 (FC `0x00B0`).
- Auth body: algorithm = 3 (SAE), transaction sequence = 1 (Commit), status = 0.
- SAE Commit fields, in order: Finite Cyclic Group (2 bytes LE = 19),
  **[Anti-Clogging Token (variable) — present only on token-retransmit]**, Scalar
  (32 bytes), FFE/element (64 bytes = P-256 x‖y, big-endian).
- Wrapped in the existing radiotap TX header (NOACK).

### 3. EC element generation (new `sae.rs`, dependency `p256`)

- Pure-Rust P-256 (RustCrypto). No OpenSSL.
- At attack start, precompute a pool (~256) of valid `(scalar, element)` pairs where
  `scalar` ∈ [1, n−1] (32 bytes big-endian) and `element = k·G` is a valid on-curve point
  (≠ identity), encoded x‖y (64 bytes). These pass the AP's range + on-curve checks so it
  cannot cheaply reject them.
- Rotate through the pool to keep send rate high (scalar multiplication is costly on our
  side too; precomputation amortizes it).

### 4. Tier 2 — RX path + token state machine (`attack.rs` / `sae.rs`)

- Use a **tracked pool of spoofed source MACs** (e.g. 64) rather than fully-random MACs,
  so AP replies can be matched to a session.
- Open the attack capture **non-blocking** (`setnonblock`), apply a BPF filter
  `subtype auth and wlan src <bssid>`, and poll RX on each loop tick. We are
  channel-locked during the attack and in monitor mode, so the unicast auth replies are
  observable even though the destination MACs aren't really ours.
- Per-MAC `SaeSession { mac, state, last_tx }` with
  `state ∈ { SentCommit, GotToken(token), Completed }`:
  - On `status 76` reply for a MAC → store the token, resend Commit-with-token (forces
    PWE math), advance to `GotToken`.
  - On `status 0` Commit reply → mark `Completed` (AP performed the derivation).
- Emit `AttackEvent` counters: total sent, tokens received, completed round-trips.

### 5. PMF detection (`scanner.rs`)

- Extend `parse_rsn_ie` to read the **RSN Capabilities** field, located after the AKM
  suite list (version 2 + group 4 + pairwise-count 2 + pairwise-suites 4·n + akm-count 2 +
  akm-suites 4·n). Bit 6 = MFPR (required), bit 7 = MFPC (capable):
  - MFPR = 1 → `Pmf::Required`
  - MFPC = 1, MFPR = 0 → `Pmf::Optional`
  - else → `Pmf::Disabled`
- Change `parse_rsn_ie`'s return to carry both encryption string and `Pmf` (small struct
  or tuple). Guard against short/truncated IEs (default `Pmf::Disabled`).

### 6. Active PMF steering (`app.rs` / `ui.rs` / `main.rs`)

- PMF **Required** target + Deauth selected → log a warning ("deauth blocked by PMF —
  switch to SAE flood") and auto-skip the ineffective deauth, steering toward `SaeFlood`.
- PMF **Optional** (transition) target → allow deauth as the downgrade path, labeled as
  such.
- UI: PMF marker in the AP table (e.g. `WPA3*` for required) and a live `SAE seen: N`
  counter in the attack panel for feedback.

### 7. SAE awareness (`scanner.rs`)

- Recognize captured management auth frames with auth algorithm = 3 (SAE) → emit
  `ScannerEvent::SaeFrame { bssid }`. `app` increments `AccessPoint.sae_seen` and a global
  counter. No BPF change needed (management frames are already captured). Provides live
  confirmation that clients are re-authenticating while an attack runs.

## Data flow (additions)

```
scanner thread
  ├─ beacon → parse_rsn_ie → {encryption, pmf} → AccessPoint (ApDiscovered/ApUpdated)
  └─ auth(algo=3) → ScannerEvent::SaeFrame{bssid} → app: sae_seen++

attack thread (SaeFlood)
  ├─ TX: rotate (scalar,element) pool + spoofed-MAC pool → build_sae_commit_frame → sendpacket
  └─ RX (non-blocking poll): auth replies from BSSID
        status 76 → store token, resend Commit+token
        status 0  → session Completed
     → AttackEvent::SaeFloodStats{bssid, sent, tokens_rx, completed} → app/ui
```

## Testing

Pure-logic unit tests (the CI gate, OS-independent):

- `build_sae_commit_frame` byte layout — with and without anti-clogging token; correct
  algo/seq/status; correct field ordering and lengths.
- `p256` pair validity — scalar in [1, n−1]; element decodes as a valid on-curve point and
  is not the identity.
- `parse_rsn_ie` PMF extraction — fixtures for Required (MFPR), Optional (MFPC only),
  Disabled (neither), plus truncated-IE safety.
- SAE auth-frame recognition — algo=3 detection vs Open System (algo=0) negative case.

The Linux RX/pcap glue (non-blocking capture, BPF filter, session loop) is covered by
`cargo check` only, per existing CI policy. Real-target verification requires a Linux box
with a monitor-mode NIC.

## New dependency

`p256` (RustCrypto, pure Rust, no OpenSSL) — fits the existing dependency-light style.

## Out of scope

- Password / handshake cracking, PMKID extraction, crackable WPA3 pcap output.
- DPP (Wi-Fi Easy Connect) and WPA3-Enterprise (192-bit / EAP) attacks.
- Non-group-19 SAE groups (group 19 / P-256 only; other ECC/FFC groups are a later
  extension — the builder takes a group parameter so this is structurally open).

## Authorization note

All attack capability remains behind the existing startup authorization-consent gate
(`--yes` / `SMARTDOS_AUTHORIZED=1`). No change to the consent model.
