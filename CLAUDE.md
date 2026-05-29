# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build & Run

```bash
# Build release binary
cargo build --release
# Binary: target/release/smartdos

# Debug build
cargo build

# Check compilation without producing a binary
cargo check

# Lint
cargo clippy

# Run (requires root + Linux + monitor-capable wireless NIC)
sudo ./target/release/smartdos [interface]   # e.g. sudo ./target/release/smartdos wlan0
```

No test suite exists. Verify changes with `cargo check` and `cargo clippy`.

## System Dependencies

```bash
# Debian/Ubuntu
sudo apt install libpcap-dev aircrack-ng

# Arch
sudo pacman -S libpcap aircrack-ng

# Fedora
sudo dnf install libpcap-devel aircrack-ng
```

Requires Linux, root privileges, and a wireless NIC that supports monitor mode.

## Architecture

Single-binary Rust TUI. Concurrency model: three threads communicating via `std::sync::mpsc` channels.

```
main thread (TUI event loop + key handling)
  ├─ scanner thread  → ScannerEvent → main (AP/client discovery, channel hopping)
  └─ attack thread   → AttackEvent  → main (deauth frame injection)
```

### Module Overview

| Module | Responsibility |
|---|---|
| `types.rs` | All shared structs/enums: `App`, `AccessPoint`, `Target`, `Client`, `ScannerEvent`, `AttackEvent`, `AttackMode`, `DeauthScope` |
| `interface.rs` | Wireless interface discovery (`iw dev`), monitor mode via `airmon-ng` with `iw` fallback |
| `scanner.rs` | Background pcap capture of 802.11 management frames; channel hops across `CHANNELS_2GHZ` every `CHANNEL_HOP_MS` (250ms); sends `ScannerEvent` to main |
| `attack.rs` | Deauth frame injection; supports `RoundRobin` (cycle targets) and `Parallel` (all simultaneously); sends `AttackEvent` to main |
| `app.rs` | `App` state mutations: processes incoming `ScannerEvent`/`AttackEvent`, manages AP/target/client lists |
| `ui.rs` | Ratatui rendering: 4-region layout (top bar → body → logs → footer) |
| `main.rs` | Entry point: root check, CLI arg parsing, monitor mode setup, terminal init, main event loop |

### UI Layout

```
┌─ top bar ─────────────────────────────────────────────┐  3 rows
│ [iface ch:N]  SCAN/ATTACK  APs:N Clients:N Deauth:N   │
├─ body (60%) ──────────┬─ right panel (40%) ───────────┤  min 10
│  AP list table        │  Targets or Clients panel      │
├─ logs (60%) ──────────┬─ attack controls (40%) ────────┤  7 rows
│  Event log            │  Mode/Status/Counters          │
├─ footer ──────────────────────────────────────────────┤  3 rows
│  keybindings                                           │
└────────────────────────────────────────────────────────┘
```

### Key Data Flow

- pcap BPF filter: `wlan[0] & 0x0C == 0x00` (802.11 management frames only)
- AP stale cleanup: every 30s, remove APs not seen in 120s
- `App.running: Arc<AtomicBool>` — shared shutdown flag across all threads
- Attack thread receives targets via `mpsc::Sender<AttackCommand>` stored in `App.attack_tx`
- `DeauthScope::Broadcast` vs `DeauthScope::Client { client_mac }` controls deauth target
