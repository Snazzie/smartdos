# Harvest Mode Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add "harvest" mode — mark an AP so every client seen on it is auto-added to `followed_clients` and tracked across roams; existing clients on the AP are backfilled immediately.

**Architecture:** Add `harvested_aps: Vec<String>` to `App`. `toggle_ap_harvest` backfills current clients and toggles the BSSID. `ClientDiscovered` handler in `app.rs` auto-adds clients from harvested APs. Keybinding `H` on AP list, badge `◆` in AP rows, footer hint.

**Tech Stack:** Rust, ratatui

---

### Task 1: Add `harvested_aps` field + methods to `App`

**Files:**
- Modify: `src/types.rs`

- [ ] **Step 1: Add field to `App` struct**

In `src/types.rs`, add the field after `followed_clients` (line ~297):

```rust
pub followed_clients: Vec<(String, Option<String>)>,
pub harvested_aps: Vec<String>,   // BSSIDs whose clients are auto-followed
```

- [ ] **Step 2: Init field in `App::new()`**

In `App::new()` (line ~382), add after `followed_clients: Vec::new(),`:

```rust
harvested_aps: Vec::new(),
```

- [ ] **Step 3: Add `is_ap_harvested` helper**

After `rebuild_follow_targets` (around line ~560), add:

```rust
pub fn is_ap_harvested(&self, bssid: &str) -> bool {
    self.harvested_aps.iter().any(|b| b == bssid)
}
```

- [ ] **Step 4: Add `toggle_ap_harvest` method**

Directly after `is_ap_harvested`:

```rust
/// Toggle harvest mode for an AP. Returns true if now harvesting, false if removed.
/// On enable: immediately backfills all currently known clients of that AP.
pub fn toggle_ap_harvest(&mut self, bssid: &str) -> bool {
    if let Some(pos) = self.harvested_aps.iter().position(|b| b == bssid) {
        self.harvested_aps.remove(pos);
        return false;
    }
    self.harvested_aps.push(bssid.to_string());

    // Backfill existing clients
    let client_macs: Vec<String> = self.ap_list
        .iter()
        .find(|ap| ap.bssid == bssid)
        .map(|ap| ap.clients.iter().map(|c| c.mac.clone()).collect())
        .unwrap_or_default();

    for mac in &client_macs {
        if !self.followed_clients.iter().any(|(m, _)| m == mac) {
            self.followed_clients.push((mac.clone(), Some(bssid.to_string())));
        }
    }
    if !client_macs.is_empty() {
        self.rebuild_follow_targets();
    }
    true
}
```

- [ ] **Step 5: Verify compile**

```bash
rtk cargo check
```
Expected: no errors.

- [ ] **Step 6: Write unit tests**

Add at the bottom of `src/types.rs` inside the existing `#[cfg(test)]` block (or create one):

```rust
#[cfg(test)]
mod harvest_tests {
    use super::*;

    fn make_app_with_ap_and_clients() -> App {
        let (mut app, _tx) = App::new();
        let mut ap = AccessPoint {
            bssid: "AA:BB:CC:DD:EE:FF".to_string(),
            ssid: "TestNet".to_string(),
            channel: 6,
            band: Band::TwoGHz,
            signal_dbm: -60,
            encryption: "WPA2".to_string(),
            clients: vec![
                Client {
                    mac: "11:22:33:44:55:66".to_string(),
                    signal_dbm: -65,
                    packets: 1,
                    last_seen: std::time::Instant::now(),
                    associated: true,
                    friendly_name: None,
                },
                Client {
                    mac: "AA:BB:CC:DD:EE:11".to_string(),
                    signal_dbm: -70,
                    packets: 1,
                    last_seen: std::time::Instant::now(),
                    associated: true,
                    friendly_name: None,
                },
            ],
            last_seen: std::time::Instant::now(),
            information_elements: vec![],
            pmkids: vec![],
        };
        app.ap_list.push(ap);
        app
    }

    #[test]
    fn toggle_harvest_on_backfills_existing_clients() {
        let mut app = make_app_with_ap_and_clients();
        let result = app.toggle_ap_harvest("AA:BB:CC:DD:EE:FF");
        assert!(result);
        assert_eq!(app.followed_clients.len(), 2);
        assert!(app.followed_clients.iter().any(|(m, _)| m == "11:22:33:44:55:66"));
        assert!(app.followed_clients.iter().any(|(m, _)| m == "AA:BB:CC:DD:EE:11"));
    }

    #[test]
    fn toggle_harvest_off_removes_from_harvested_aps() {
        let mut app = make_app_with_ap_and_clients();
        app.toggle_ap_harvest("AA:BB:CC:DD:EE:FF");
        let result = app.toggle_ap_harvest("AA:BB:CC:DD:EE:FF");
        assert!(!result);
        assert!(!app.is_ap_harvested("AA:BB:CC:DD:EE:FF"));
    }

    #[test]
    fn toggle_harvest_no_duplicate_in_followed_clients() {
        let mut app = make_app_with_ap_and_clients();
        // Pre-add one client
        app.followed_clients.push(("11:22:33:44:55:66".to_string(), None));
        app.toggle_ap_harvest("AA:BB:CC:DD:EE:FF");
        let count = app.followed_clients.iter().filter(|(m, _)| m == "11:22:33:44:55:66").count();
        assert_eq!(count, 1);
    }

    #[test]
    fn is_ap_harvested_returns_correct_state() {
        let mut app = make_app_with_ap_and_clients();
        assert!(!app.is_ap_harvested("AA:BB:CC:DD:EE:FF"));
        app.toggle_ap_harvest("AA:BB:CC:DD:EE:FF");
        assert!(app.is_ap_harvested("AA:BB:CC:DD:EE:FF"));
    }
}
```

- [ ] **Step 7: Run tests**

```bash
rtk cargo test harvest
```
Expected: 4 tests pass.

- [ ] **Step 8: Commit**

```bash
rtk git add src/types.rs
rtk git commit -m "feat(harvest): add harvested_aps field + toggle_ap_harvest + is_ap_harvested"
```

---

### Task 2: Auto-add clients from harvested APs in `app.rs`

**Files:**
- Modify: `src/app.rs`

- [ ] **Step 1: Add harvest check in `ClientDiscovered` handler**

In `src/app.rs`, in the `ClientDiscovered` arm (around line 155), after the `handle_sweep_match` call, add:

```rust
maybe_update_follow(app, &client.mac, &ap_bssid);
handle_sweep_match(app, &client.mac, &ap_bssid);
// Harvest: auto-follow any new client seen on a harvested AP
if app.is_ap_harvested(&ap_bssid) {
    if !app.followed_clients.iter().any(|(m, _)| m == &client.mac) {
        let ssid = app.ap_list.iter()
            .find(|a| a.bssid == ap_bssid)
            .map(|a| a.ssid.clone())
            .unwrap_or_else(|| ap_bssid.clone());
        app.followed_clients.push((client.mac.clone(), Some(ap_bssid.clone())));
        app.rebuild_follow_targets();
        app.add_log(format!("Harvested: {} from {}", client.mac, ssid));
        if app.attack_running {
            let targets = app.targets.clone();
            if let Some(tx) = &app.attack_cmd_tx {
                let _ = tx.send(AttackCommand::UpdateTargets(targets));
            }
        }
    }
}
```

- [ ] **Step 2: Verify compile**

```bash
rtk cargo check
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
rtk git add src/app.rs
rtk git commit -m "feat(harvest): auto-follow new clients on harvested APs in ClientDiscovered handler"
```

---

### Task 3: Keybinding `H` in `main.rs`

**Files:**
- Modify: `src/main.rs`

- [ ] **Step 1: Add `H` handler on AP list**

In `src/main.rs`, find the `KeyCode::Char('t') | KeyCode::Char('T')` arm. Add a new arm before or after it (keep alphabetical with other single-char keys):

```rust
KeyCode::Char('h') | KeyCode::Char('H') => {
    if app.tab_selection == TabSelection::ApList && !app.ap_list.is_empty() {
        let idx = app.selected_ap_idx.min(app.ap_list.len() - 1);
        let bssid = app.ap_list[idx].bssid.clone();
        let ssid = app.ap_list[idx].ssid.clone();
        let now_harvesting = app.toggle_ap_harvest(&bssid);
        if now_harvesting {
            let n = app.followed_clients.iter()
                .filter(|(_, ap)| ap.as_deref() == Some(&bssid))
                .count();
            app.add_log(format!(
                "Harvest ON: {} ({} clients auto-followed)",
                if ssid.is_empty() { &bssid } else { &ssid },
                n
            ));
        } else {
            app.add_log(format!(
                "Harvest OFF: {}",
                if ssid.is_empty() { &bssid } else { &ssid }
            ));
        }
        // Push updated targets to attack thread so harvest takes effect immediately
        if app.attack_running {
            let targets = app.targets.clone();
            if let Some(tx) = &app.attack_cmd_tx {
                let _ = tx.send(types::AttackCommand::UpdateTargets(targets));
            }
        }
    }
}
```

- [ ] **Step 2: Verify compile**

```bash
rtk cargo check
```
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
rtk git add src/main.rs
rtk git commit -m "feat(harvest): add H keybinding to toggle AP harvest mode"
```

---

### Task 4: UI indicator in `ui.rs`

**Files:**
- Modify: `src/ui.rs`

- [ ] **Step 1: Add `is_harvested` variable in AP row rendering**

In `src/ui.rs`, in the AP list row map (around line 200), after the `is_followed` line, add:

```rust
let is_harvested = app.is_ap_harvested(&ap.bssid);
```

- [ ] **Step 2: Add harvest marker to SSID display**

In the same block, find the `ssid_display` definition (around line 228). Replace the marker logic:

```rust
let ssid_display = if ap.ssid.is_empty() || ap.ssid == "<Hidden>" {
    Span::styled("<Hidden>", Style::default().fg(Color::DarkGray))
} else {
    let marker = if is_harvested { "◆" } else if is_followed { "▶" } else { " " };
    Span::styled(
        format!("{}{}", marker, truncate_str(&ap.ssid, 14)),
        Style::default(),
    )
};
```

- [ ] **Step 3: Add harvest style to row_style**

Find the `row_style` block (around line 214). Add a harvest branch before `is_followed`:

```rust
let row_style = if is_selected {
    Style::default()
        .bg(Color::Rgb(40, 40, 80))
        .add_modifier(Modifier::BOLD)
} else if is_harvested {
    Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD)
} else if is_followed {
    Style::default()
        .bg(Color::Rgb(50, 20, 20))
        .add_modifier(Modifier::BOLD)
} else if is_target {
    Style::default().fg(Color::Red)
} else {
    Style::default()
};
```

- [ ] **Step 4: Add `H` to footer ApList hints**

In `render_footer`, in the `TabSelection::ApList` arm (around line 981), add harvest hint:

```rust
TabSelection::ApList => {
    add(&mut spans, "↑↓", "nav");
    add(&mut spans, "t", "target");
    add(&mut spans, "h", "harvest");
    add(&mut spans, "c", "clients+focus");
    add(&mut spans, "/", "filter");
    add(&mut spans, "r", "clear scan");
}
```

- [ ] **Step 5: Verify compile**

```bash
rtk cargo check
```
Expected: no errors.

- [ ] **Step 6: Commit**

```bash
rtk git add src/ui.rs
rtk git commit -m "feat(harvest): add harvest AP indicator (◆ marker + yellow row) and footer hint"
```

---

### Task 5: Full build + test verification

- [ ] **Step 1: Run all tests**

```bash
rtk cargo test
```
Expected: all tests pass including the 4 new harvest tests.

- [ ] **Step 2: Build release**

```bash
rtk cargo build --release
```
Expected: clean build, no warnings about unused fields.

- [ ] **Step 3: Smoke test in demo mode**

```bash
./target/release/smartdos --demo
```

Verify:
- Press `H` on a selected AP → log shows "Harvest ON: ..."
- AP row shows `◆` marker and yellow style
- Press `H` again → log shows "Harvest OFF: ..."
- Marker and yellow style removed
- Footer shows `h harvest` hint
