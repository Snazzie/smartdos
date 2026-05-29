# Client Roaming Simulation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Simulate clients hopping to a different AP or channel after being deauthed, exercising the pursuit sweep machinery in the macOS stub.

**Architecture:** All changes are inside the `#[cfg(not(target_os = "linux"))]` scanner stub in `scanner.rs`. Per-second tick: each client has a ~5% chance of roaming. 60% of roams are hard (move to different AP → exercises silence timer + `SweepFor` + `handle_sweep_match`). 40% are band steers (AP channel change → exercises `ApUpdated` pursuit `UpdateTargetChannel` path). No production-path code touched.

**Tech Stack:** Rust, `rand 0.8` (already in Cargo.toml), `std::collections::HashMap`

---

### Task 1: Convert `ap_clients` to owned-key HashMap and add `ap_channels`

**Files:**
- Modify: `src/scanner.rs:969-981`

- [ ] **Step 1: Replace the `ap_clients` init block**

Replace lines 969–981:
```rust
// Build per-AP client list — mutable so we can apply churn each tick
let mut ap_clients: std::collections::HashMap<&str, Vec<Client>> =
    std::collections::HashMap::new();
for (ap_bssid, mac, dbm, assoc) in FAKE_CLIENTS {
    ap_clients.entry(ap_bssid).or_default().push(Client {
        mac: mac.to_string(),
        signal_dbm: *dbm,
        packets: 1,
        last_seen: Instant::now(),
        associated: *assoc,
        friendly_name: None,
    });
}
```

With:
```rust
// Build per-AP client list (owned keys so clients can move between APs)
let mut ap_clients: std::collections::HashMap<String, Vec<Client>> =
    std::collections::HashMap::new();
for (ap_bssid, mac, dbm, assoc) in FAKE_CLIENTS {
    ap_clients.entry(ap_bssid.to_string()).or_default().push(Client {
        mac: mac.to_string(),
        signal_dbm: *dbm,
        packets: 1,
        last_seen: Instant::now(),
        associated: *assoc,
        friendly_name: None,
    });
}

// Track mutable channel per simulated AP (band steering can shift these)
let mut ap_channels: std::collections::HashMap<String, u8> =
    FAKE_APS.iter().map(|(bssid, _, ch, _, _, _)| (bssid.to_string(), *ch)).collect();
```

- [ ] **Step 2: Verify compilation**

```bash
docker run --rm -v $PWD:/src -w /src rust:latest bash -c \
  'apt-get update -qq && apt-get install -y -qq libpcap-dev && cargo check --all-targets'
```

Expected: 0 errors. (The `for (ap_bssid, clients) in &mut ap_clients` loop at line 1013 now iterates `String` keys — no type change needed for iteration, but the `ap_bssid.to_string()` call in the event send becomes a clone. Rust will flag any borrow issues.)

- [ ] **Step 3: Commit**

```bash
rtk git add src/scanner.rs && rtk git commit -m "refactor(stub): owned-key ap_clients + ap_channels map"
```

---

### Task 2: Add roam helper — `stub_roam_clients`

**Files:**
- Modify: `src/scanner.rs` — add new `#[cfg(not(target_os = "linux"))]` fn just above `start_scanner`

- [ ] **Step 1: Add the helper function**

Insert this function immediately before the `#[cfg(not(target_os = "linux"))]` `pub fn start_scanner(` line (~line 914):

```rust
/// Probabilistic client roaming for the macOS stub.
/// Called once per second. Each client has a ~5% chance of roaming.
/// - 60%: hard roam — client moves to a different simulated AP
/// - 40%: band steer — client's current AP shifts to a different channel
#[cfg(not(target_os = "linux"))]
fn stub_roam_clients(
    ap_clients: &mut std::collections::HashMap<String, Vec<Client>>,
    ap_channels: &mut std::collections::HashMap<String, u8>,
    event_tx: &std::sync::mpsc::Sender<ScannerEvent>,
    supports_5ghz: bool,
    supports_6ghz: bool,
) {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    // Collect bssids visible in this scan (filtered to enabled bands)
    let visible_bssids: Vec<String> = FAKE_APS
        .iter()
        .filter(|(_, _, _, _, _, band)| match band {
            Band::FiveGHz => supports_5ghz,
            Band::SixGHz  => supports_6ghz,
            Band::TwoGHz  => true,
        })
        .map(|(bssid, _, _, _, _, _)| bssid.to_string())
        .collect();

    if visible_bssids.len() < 2 {
        return;
    }

    // Collect (bssid, mac) pairs for clients that will roam this tick
    let roam_candidates: Vec<(String, String)> = ap_clients
        .iter()
        .flat_map(|(bssid, clients)| {
            clients.iter().map(move |c| (bssid.clone(), c.mac.clone()))
        })
        .filter(|_| rng.gen_bool(0.05))
        .collect();

    for (old_bssid, mac) in roam_candidates {
        let is_hard_roam = rng.gen_bool(0.60);

        if is_hard_roam {
            // Pick a different AP
            let other_bssids: Vec<&String> = visible_bssids
                .iter()
                .filter(|b| *b != &old_bssid)
                .collect();
            if other_bssids.is_empty() {
                continue;
            }
            let new_bssid = other_bssids[rng.gen_range(0..other_bssids.len())].clone();

            // Move client from old AP vec to new AP vec
            let client_opt = ap_clients
                .get_mut(&old_bssid)
                .and_then(|v| {
                    v.iter().position(|c| c.mac == mac).map(|i| v.remove(i))
                });
            if let Some(mut client) = client_opt {
                client.last_seen = Instant::now();
                client.associated = true;
                let new_ch = ap_channels.get(&new_bssid).copied().unwrap_or(6);
                let _ = event_tx.send(ScannerEvent::ClientDiscovered {
                    ap_bssid: new_bssid.clone(),
                    client: client.clone(),
                });
                let _ = event_tx.send(ScannerEvent::Error(format!(
                    "[stub] {} roamed {}→{} ch{}",
                    mac, old_bssid, new_bssid, new_ch
                )));
                ap_clients.entry(new_bssid).or_default().push(client);
            }
        } else {
            // Band steer: shift the AP to a different channel in the same band
            let ap_meta = FAKE_APS.iter().find(|(b, _, _, _, _, _)| *b == old_bssid);
            if let Some((bssid, ssid, base_ch, base_dbm, enc, band)) = ap_meta {
                let skip = match band {
                    Band::FiveGHz => !supports_5ghz,
                    Band::SixGHz  => !supports_6ghz,
                    Band::TwoGHz  => false,
                };
                if skip {
                    continue;
                }
                let old_ch = ap_channels.get(&old_bssid).copied().unwrap_or(*base_ch);
                // Rotate through a short set of channels per band
                let new_ch = match band {
                    Band::TwoGHz  => if old_ch == 1 { 6 } else if old_ch == 6 { 11 } else { 1 },
                    Band::FiveGHz => if old_ch == 36 { 40 } else if old_ch == 40 { 44 } else { 36 },
                    Band::SixGHz  => if old_ch == 5 { 37 } else if old_ch == 37 { 69 } else { 5 },
                };
                ap_channels.insert(old_bssid.clone(), new_ch);
                let ap = make_ap(bssid, ssid, new_ch, *base_dbm, enc, *band);
                let _ = event_tx.send(ScannerEvent::ApUpdated(ap));
                let _ = event_tx.send(ScannerEvent::Error(format!(
                    "[stub] {} band-steered ch{}→ch{}",
                    old_bssid, old_ch, new_ch
                )));
            }
        }
    }
}
```

- [ ] **Step 2: Verify compilation**

```bash
docker run --rm -v $PWD:/src -w /src rust:latest bash -c \
  'apt-get update -qq && apt-get install -y -qq libpcap-dev && cargo check --all-targets'
```

Expected: 0 errors.

- [ ] **Step 3: Commit**

```bash
rtk git add src/scanner.rs && rtk git commit -m "feat(stub): add stub_roam_clients helper"
```

---

### Task 3: Call `stub_roam_clients` once per second in the tick loop

**Files:**
- Modify: `src/scanner.rs:1028` (the `Traffic` send line, inside `if tick % 4 == 0`)

- [ ] **Step 1: Add the call inside the per-second block**

Find the line (inside `if tick % 4 == 0 {`):
```rust
                    let _ = event_tx.send(ScannerEvent::Traffic(tick * 4 + 1));
```

Replace with:
```rust
                    stub_roam_clients(
                        &mut ap_clients,
                        &mut ap_channels,
                        &event_tx,
                        supports_5ghz,
                        supports_6ghz,
                    );

                    let _ = event_tx.send(ScannerEvent::Traffic(tick * 4 + 1));
```

- [ ] **Step 2: Fix the `ClientUpdated` loop — use `ap_channels` for current channel**

The existing client update loop at ~line 1013 needs to use `ap_channels` for correct channel after band steering. Find:

```rust
                    // Emit ClientUpdated for each client with jittered signal + ticking packets
                    for (ap_bssid, clients) in &mut ap_clients {
                        for (ci, client) in clients.iter_mut().enumerate() {
                            let jitter = ((sec + ci as u64) % 7) as i16 - 3;
                            client.signal_dbm = (client.signal_dbm + jitter).clamp(-90, -20);
                            client.packets += 1;
                            client.last_seen = Instant::now();
                            // Every 30s briefly disassociate then reassociate (simulates roam/reconnect)
                            client.associated = (sec + ci as u64) % 30 != 0;
                            let _ = event_tx.send(ScannerEvent::ClientUpdated {
                                ap_bssid: ap_bssid.to_string(),
                                client: client.clone(),
                            });
                        }
                    }
```

Replace with (no logic change, just `ap_bssid` is now `String` so `.clone()` instead of `.to_string()`):

```rust
                    // Emit ClientUpdated for each client with jittered signal + ticking packets
                    for (ap_bssid, clients) in &mut ap_clients {
                        for (ci, client) in clients.iter_mut().enumerate() {
                            let jitter = ((sec + ci as u64) % 7) as i16 - 3;
                            client.signal_dbm = (client.signal_dbm + jitter).clamp(-90, -20);
                            client.packets += 1;
                            client.last_seen = Instant::now();
                            // Every 30s briefly disassociate then reassociate (simulates roam/reconnect)
                            client.associated = (sec + ci as u64) % 30 != 0;
                            let _ = event_tx.send(ScannerEvent::ClientUpdated {
                                ap_bssid: ap_bssid.clone(),
                                client: client.clone(),
                            });
                        }
                    }
```

- [ ] **Step 3: Full build + test**

```bash
docker run --rm -v $PWD:/src -w /src rust:latest bash -c \
  'apt-get update -qq && apt-get install -y -qq libpcap-dev && cargo check --all-targets && cargo test'
```

Expected: 0 errors, all tests pass.

- [ ] **Step 4: Commit**

```bash
rtk git add src/scanner.rs && rtk git commit -m "feat(stub): probabilistic client roaming — hard roam + band steer"
```

---

## Verification

Run the macOS stub and enable pursuit mode (`P`), follow a client (`f`), then watch the log panel. Within ~20–40 seconds you should see:

- `[stub] DE:AD:BE:EF:00:01 roamed AA:BB:CC:11:22:33→AA:BB:CC:44:55:66 ch11` (hard roam)
- `[stub] AA:BB:CC:11:22:33 band-steered ch6→ch11` (band steer)
- `Pursuit sweep: DE:AD:BE:EF:00:01 silent, scanning all channels` (silence timer triggered)
- `Pursuit: DE:AD:BE:EF:00:01 found on ch 11 (2.4GHz), locked` (sweep match)
