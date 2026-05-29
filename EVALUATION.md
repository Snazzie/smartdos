# smartdos — Codebase Evaluation

**Date:** 2026-05-29
**Scope:** Full source review (`src/*.rs`, ~5,360 LOC), Cargo manifest, architecture.
**Method:** Static inspection. The Linux `cfg(target_os = "linux")` path cannot be
compiled on this macOS dev host (pcap), so Linux-specific findings are by inspection.

---

## What the tool is

Single-binary Rust TUI (ratatui + crossterm) for authorized wireless pentesting:
802.11 management-frame scanning (APs + clients), target management, and frame
injection (deauth / auth-flood / beacon-flood). 3-thread model (main TUI + scanner
+ attack) over `mpsc`. macOS gets a fake-data stub; Linux is the real target.

**Genuinely solid:** RSN/WPA IE decoding (WPA/WPA2/WPA3/OWE/Ent/TKIP), radiotap
offset+signal parsing, multi-band channel plan (2.4/5/6 GHz), client-roaming
"follow" + pursuit sweep, single-adapter channel-lock to stop scanner/attack
fighting over the radio, app-side EMA `traffic_rate` and confirmed-disconnect
counting, file logging, saved target/client lists, friendly-name persistence.

---

## Resolution status (2026-05-29)

All 10 items addressed and **verified on real Linux** (Debian container with
`libpcap-dev`): `cargo check --all-targets` clean (0 errors) and `cargo test` =
**18 passing, 0 failed**, including the Linux-gated scanner parser tests. Also
verified on the macOS stub (12 passing) and via `cargo check --target
x86_64-unknown-linux-gnu`.

| # | Item | Status |
|---|------|--------|
| 1 | Linux build break + CI | **Fixed** — `friendly_name` added to all 6 `Client` literals; `.github/workflows/ci.yml` runs Linux `cargo check`/`clippy`/`test` |
| 2 | No tests | **Fixed** — unit tests for frame builders, radiotap header, EAPOL parser, pcap writer, RSN/WPA IE decode |
| 3 | No handshake/PMKID capture | **Fixed** — `handshake.rs` writes a crackable session `.pcap`; scanner filter widened to capture EAPOL |
| 4 | `iw` on hot path | **Partial** — channel-set failures now surfaced to the log instead of swallowed. Full nl80211/netlink migration **deferred** (requires Wi-Fi hardware to validate; a broken netlink path would be worse than working `iw`) |
| 5 | Beacon flood ignores band | **Fixed** — band-aware rates IE; DS-Parameter tag only on 2.4 GHz |
| 6 | `send_interval_ms` ignored in RR | **Fixed** — round-robin now paces bursts by the configured interval |
| 7 | Bare radiotap TX header | **Fixed** — TX-flags field with NOACK |
| 8 | `static mut` counters | **Fixed** — `AtomicU16`/`AtomicU64` |
| 9 | Unbounded session log | **Fixed** — rotates to `session.log.1` at 5 MB |
| 10 | No authorization gate | **Fixed** — consent prompt on startup (`-y`/`--yes`/`SMARTDOS_AUTHORIZED` bypass) |

**Remaining follow-up:** item 4's netlink migration. The current `iw`-per-hop
approach works but forks a process every 250 ms; replacing it with nl80211 is a
hardware-gated task.

## Top 10 critical items (ranked by severity)

### P0 — Ship-blocking

**1. The Linux build does not compile — and nothing catches it.**
`Client` (types.rs:84) has a required `friendly_name: Option<String>` field and
derives only `Debug, Clone` (no `Default`). The Linux `parse_client_frame_raw`
builds `Client` struct literals at scanner.rs **505, 522, 539, 556, 581, 593**,
each listing 5 fields with no `friendly_name` and no `..` spread → hard compile
error on the *only* supported platform. The macOS stub (scanner.rs:832/850) sets
the field, so dev builds stay green and hide it.
Root cause is process, not just this field: **the Linux target has not been
compiled since `friendly_name` landed**, because dev is macOS-only and there is
no Linux CI. The compiler stops at the first error — assume more Linux-only breaks
may sit behind this one.
*Fix:* add `friendly_name: None` to all 6 literals (blast radius confirmed limited
to scanner.rs — main/ui only read the field), **and** add a Linux `cargo check`
(or `cross check --target x86_64-unknown-linux-gnu`) to CI so this never reaches
main again. This single CI job is the highest-leverage change in the repo.

### High

**2. No automated tests anywhere.**
The riskiest code is pure and trivially testable: `parse_rsn_ie` / `parse_wpa_ie`
(byte-offset cipher/AKM walks), `parse_radiotap_offset` / `parse_radiotap_signal`
(presence-bitmap field skipping), and the frame builders (deauth/auth/beacon byte
layout). A one-bit offset error silently corrupts every parsed AP or every
injected frame with zero signal. Add unit tests with captured byte fixtures.

**3. No handshake / PMKID capture — deauth has no pentest payoff.**
The standard workflow is: deauth a client → it reconnects → capture the WPA
4-way handshake (or PMKID from the first EAPOL) → crack offline. smartdos sends
the deauth but never captures EAPOL or writes a `.pcap`/`.hccapx`. Without this
the deauth is disruption-only. This is the biggest capability gap vs airgeddon
(already noted in COMPARISON.md) and the main reason to use the tool at all.

### Medium — correctness / robustness

**4. Channel changes shell out to `iw` on a hot path.**
`set_channel` does `Command::new("iw")…set freq` — fork+exec **every 250 ms**
during scan hopping (scanner.rs:176) and on every target switch in round-robin
(attack.rs:321). High-rate process spawning is slow, racy, and silently swallows
errors (`let _ =`). Move to nl80211 netlink (e.g. a maintained `nl80211`/`neli`
crate) for in-process, checked channel control.

**5. Beacon-flood ignores the band.**
`send_beacon_flood_frame` (attack.rs:482) always emits the 2.4 GHz
supported-rates IE (`82 84 8B 96 …`) and a DS-Parameter (channel) tag regardless
of band. On 5/6 GHz the rates are wrong and the DS tag is meaningless, so flooded
beacons look malformed off 2.4 GHz. Branch the IE set on `Band`.

**6. `send_interval_ms` is silently ignored in RoundRobin mode.**
In RR the loop uses a hardcoded `rr_interval` (20 ms) plus a 1 ms per-frame
sleep; `burst_interval` (derived from `send_interval_ms`) is assigned and only
read in Parallel mode (attack.rs:113–114, 150–153). The user's burst-rate
setting does nothing in RR — honor it or document the asymmetry in the UI.

**7. Radiotap TX header is bare.**
`build_radiotap_header` (attack.rs:524) sets only the Flags field (no FCS). Many
drivers want TX flags (e.g. "don't wait for ACK", "no retry") for reliable
injection; without them frames may be retried or dropped. Inject is fragile and
driver-dependent. Add a TX-flags field.

### Quality / hardening

**8. `static mut` mutable statics for sequence counters.**
`SEQ` / `AUTH_COUNTER` in attack.rs (361, 392, 438, 486) are `static mut` behind
`unsafe`. Edition 2021 → `static_mut_refs` warning only, and each is touched by
the single attack thread so there's no live race — but it's a footgun and a hard
error under edition 2024. Replace with `AtomicU16`/`AtomicU64`.

**9. Unbounded session log; no rotation.**
`init_log_file` (app.rs:284) opens `~/.smartdos/session.log` in append mode and
`add_log` writes every event forever. Long runs grow it without limit. Add size-
based rotation or a max line cap (the in-memory buffer is already capped at 100).

**10. No authorization gate for an injection tool.**
There is a root check but no explicit "you are authorized to test this network"
confirmation, no max-runtime / kill-switch, and no per-target rate ceiling.
For a tool that injects deauth/auth/beacon floods, a one-time consent prompt and
an attack-duration cap are cheap, meaningful safety rails (and reduce legal/
collateral risk from a stray broadcast deauth).

---

## Quick wins (low effort, high payoff)

- Item **1** field fix + Linux CI check — unblocks the whole platform.
- Item **2** parser unit tests — guards the most fragile code.
- Item **6** honor `send_interval_ms` in RR — one-line behavior fix.
- Item **8** `static mut` → atomics — removes `unsafe` and future-proofs edition.

## Not bugs (verified, for the record)

- `traffic_rate` and `disconnect_count` ARE wired (computed app-side at
  app.rs:91 and app.rs:171) — not dead fields.
- Stale-AP removal absent **by design** — `ApGone` is ignored; APs persist until
  the user clears with `r` (app.rs:139).
- Scanner/attack do not fight over the radio on a single adapter — the scanner is
  channel-locked to the attack channel on start (app.rs:359).
