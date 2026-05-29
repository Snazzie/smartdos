# smartdos v0.1

**Wireless AP scanner + deauth attack orchestrator with terminal UI**

`smartdos` is an interactive TUI tool for ethical wireless penetration testing. It discovers nearby access points via beacon frame capture, lets you select targets, and orchestrates deauthentication attacks in round-robin or parallel mode — all from a keyboard-driven terminal interface.

---

## ⚠️ LEGAL & ETHICAL DISCLAIMER

**This tool is for authorized security testing and educational purposes ONLY.**

- Only use this software on networks you **own** or have **explicit written permission** to test.
- Deauthenticating stations from an access point is an **active denial-of-service attack**.
- Unauthorized use of deauth attacks violates:
  - **US 18 U.S.C. § 1030** (Computer Fraud and Abuse Act)
  - **EU Directive 2013/40/EU** (Attacks against information systems)
  - **UK Computer Misuse Act 1990**
  - Similar laws in other jurisdictions
- **Penalties** include fines and imprisonment.
- The authors assume **no liability** for misuse. You are responsible for your own actions.

---

## Features

| Feature                  | Description                                                          |
| ------------------------ | -------------------------------------------------------------------- |
| **AP Scanning**          | Live 802.11 beacon/probe-response capture via pcap                   |
| **Signal Display**       | dBm + percentage for each AP, color-coded (green/yellow/red)         |
| **Channel Detection**    | Automatically reads channel from DS Parameter Set tag                |
| **Encryption Detection** | Identifies OPEN / WPA / WPA2                                         |
| **Target Management**    | Add/remove targets from AP list, enable/disable individual targets   |
| **Attack Modes**         | Round-Robin (cycle targets) or Parallel (all targets simultaneously) |
| **Deauth Injection**     | Raw 802.11 deauth frames with radiotap header                        |
| **Monitor Mode**         | Auto-enables via `airmon-ng` or `iw`                                 |
| **Live Counters**        | Real-time deauth frame counters per target                           |
| **Event Log**            | Scrollable log panel showing actions and errors                      |

---

## Requirements

- **Linux** with wireless networking hardware
- **Root privileges** (for monitor mode and packet injection)
- **libpcap** development headers (`libpcap-dev` on Debian/Ubuntu)
- **aircrack-ng** suite (`airmon-ng` for monitor mode setup) — optional, falls back to `iw`
- Rust toolchain (for building from source)

### Install system dependencies

```bash
# Debian/Ubuntu
sudo apt install libpcap-dev aircrack-ng

# Arch
sudo pacman -S libpcap aircrack-ng

# Fedora
sudo dnf install libpcap-devel aircrack-ng
```

---

## Build

```bash
# Clone
git clone <repo-url> && cd smartdos

# Build release
cargo build --release

# Binary is at: target/release/smartdos
```

---

## Usage

```bash
# Run with auto-detected interface:
sudo ./target/release/smartdos

# Run with specific interface:
sudo ./target/release/smartdos wlan0

# If you already have a monitor interface:
sudo ./target/release/smartdos wlan0mon
```

### Controls

| Key         | Action                                      |
| ----------- | ------------------------------------------- |
| `↑` / `↓`   | Navigate list                               |
| `Tab`       | Switch between AP list / Target list        |
| `t`         | Toggle target (add/remove selected AP)      |
| `d`         | Remove selected target                      |
| `Space`     | Enable/disable selected target              |
| `M`         | Toggle attack mode (Round-Robin ↔ Parallel) |
| `S`         | Start / Stop deauth attack                  |
| `Q` / `Esc` | Quit                                        |

### Layout

```
┌────────────── smartdos v0.1 — Wireless Deauth Toolkit ──────────────┐
│ [wlan0mon] SCANNING               APs:23 | Targets:3 | Deauth:1427  │
├───────────────────────────┬──────────────────────────────────────────┤
│      Access Points        │         Targets (3)                     │
│ ┌──────┬──────────┬──┬───┬┐│┌──────┬──────────┬──┬────────┬───────┐│
│ │SSID  │BSSID     │CH│dBm│││││SSID  │BSSID     │CH│Status  │Sent   ││
│ ├──────┼──────────┼──┼───┤│││├──────┼──────────┼──┼────────┼───────┤│
│ │MyNet │AA:BB:CC..│ 6│-45│││││Target│AA:BB:CC..│ 6│ ACTIVE │ 527   ││
│ │Office│DD:EE:FF..│11│-62│││││...   │...       │..│ OFF    │ 0     ││
│ │...   │...       │..│...││││└──────┴──────────┴──┴────────┴───────┘│
│ └──────┴──────────┴──┴───┘││                                        │
├───────────────────────────┴──────────────────────────────────────────┤
│  Events                           │  Attack Controls                │
│  Scanner started on wlan0mon      │  Mode: Round-Robin              │
│  Target added: MyNet (AA:BB:CC..) │  Status: RUNNING                │
│  Attack started: 3 targets        │  Targets: 3                     │
│  Deauth sent to MyNet: 527        │  Deauth Sent: 1427              │
├──────────────────────────────────────────────────────────────────────┤
│  ↑↓ nav  TAB switch  t target  d untarget  M mode  S start/stop Q  │
└──────────────────────────────────────────────────────────────────────┘
```

---

## How It Works

### Scanning

1. Opens a pcap capture on the monitor-mode interface
2. Filters for 802.11 management frames (beacon + probe response)
3. Parses the radiotap header for signal strength (dBm)
4. Parses the 802.11 frame header for BSSID, SSID, and tagged parameters (channel, encryption)
5. Sends AP updates to the main thread via an mpsc channel

### Deauth Attack

1. Constructs raw 802.11 deauth management frames (Frame Control `0xC0`)
2. Prepends a minimal radiotap header for proper driver injection
3. Sends via pcap `sendpacket()` — 5-frame bursts per cycle
4. **Round-robin**: cycles through targets one at a time (20ms between targets)
5. **Parallel**: blasts all targets simultaneously (50ms between cycles)

### Interface Management

- Uses `airmon-ng start/stop` to enable/disable monitor mode
- Falls back to `iw dev set monitor none` if airmon-ng isn't available
- Restores interface state on exit

---

## License

MIT — see [LICENSE](LICENSE)

---

## Acknowledgments

- [aircrack-ng](https://www.aircrack-ng.org/) for the foundational wireless security tools
- [pcap](https://www.tcpdump.org/) for packet capture capabilities
- [ratatui](https://ratatui.rs/) for the terminal UI framework
