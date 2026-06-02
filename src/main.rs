mod app;
mod attack;
mod handshake;
mod interface;
mod oui;
mod persist;
mod saved_lists;
mod scanner;
mod settings;
mod setup;
mod types;
mod ui;

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    execute,
    terminal::{self, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::{Backend, CrosstermBackend},
    Terminal,
};
use std::io::{self};

use std::sync::{atomic::Ordering, Arc};
use std::sync::atomic::AtomicBool;
use signal_hook::{consts::{SIGINT, SIGTERM}, iterator::Signals};
use types::{App, InputMode, PageView, TabSelection, TargetSubSection, WirelessInterface};

/// Global indices of targets belonging to the active sub-section
fn target_sub_indices(app: &App) -> Vec<usize> {
    app.targets.iter().enumerate()
        .filter(|(_, t)| match app.target_sub_section {
            TargetSubSection::Clients => !t.client_filter.is_empty(),
            TargetSubSection::Aps => t.client_filter.is_empty(),
        })
        .map(|(i, _)| i)
        .collect()
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let demo = args.iter().any(|a| a == "--demo");

    // Demo mode uses a stub interface and never touches hardware, so it does
    // not need root. Live mode requires root for monitor mode + injection.
    if !demo && !interface::check_root() {
        eprintln!("⚠  smartdos requires root privileges for monitor mode and packet injection.");
        eprintln!("   Run with: sudo smartdos\n");
        std::process::exit(1);
    }

    let ifaces = if demo {
        interface::discover_interfaces_demo()?
    } else {
        interface::discover_interfaces()?
    };
    if ifaces.is_empty() {
        eprintln!("No wireless interfaces found.");
        std::process::exit(1);
    }

    terminal::enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;
    terminal.clear()?;

    let (listen_name, attack_name, txpower) = setup::run_setup(&mut terminal, ifaces.clone())?;

    let listen_phy = ifaces.iter()
        .find(|i| i.name == listen_name)
        .map(|i| i.phy.clone())
        .unwrap_or_default();
    let (supports_5ghz, supports_6ghz) = interface::detect_band_capabilities(&listen_phy);

    // ifaces ownership moves into run_setup — phy lookup must happen before this line
    let listen_mon = activate_monitor(&listen_name);
    let attack_mon = if attack_name != listen_name {
        activate_monitor(&attack_name)
    } else {
        listen_mon.clone()
    };

    let (mut app, _scanner_tx) = App::new();
    app.current_interface = Some(WirelessInterface {
        name: listen_name.clone(),
        phy: String::new(),
        monitor_name: Some(listen_mon.clone()),
        is_monitor: false,
    });
    app.monitor_interface = Some(listen_mon.clone());
    app.listen_interface = Some(listen_mon.clone());
    app.attack_interface = Some(attack_mon.clone());
    if attack_name != listen_name {
        app.attack_physical = Some(attack_name.clone());
    }

    // Switch to an unrestricted regulatory domain before applying TX power so
    // the requested level isn't clamped by the local cap. System-wide and
    // best-effort (self-managed cards ignore it); restored on exit.
    if !demo {
        app.original_reg_domain = interface::get_reg_domain();
        match interface::set_reg_domain(interface::UNRESTRICTED_REG) {
            Ok(()) => {
                std::thread::sleep(std::time::Duration::from_millis(300));
                let was = match &app.original_reg_domain {
                    Some(cc) => format!(", was {}", cc),
                    None => String::new(),
                };
                app.add_log(format!(
                    "Regulatory domain → {} (unrestricted){}",
                    interface::UNRESTRICTED_REG, was
                ));
            }
            Err(e) => app.add_log(format!("Regdomain set failed (TX power may be capped): {}", e)),
        }
    }

    if let Some(dbm) = txpower {
        match interface::set_txpower(&attack_mon, Some(dbm)) {
            Ok(()) => app.txpower_dbm = Some(dbm),
            Err(e) => eprintln!("TX power error: {}", e),
        }
    } else {
        app.txpower_dbm = interface::get_txpower(&attack_mon);
    }

    let client_names = saved_lists::load_client_names();
    if !client_names.is_empty() {
        let count = client_names.len();
        app.client_names = client_names;
        app.add_log(format!("Loaded {} client name{}", count, if count == 1 { "" } else { "s" }));
    }

    if let Some(s) = persist::load_attack_settings() {
        app.attack_type = s.attack_type;
        app.attack_mode = s.attack_mode;
        app.burst_size = s.burst_size;
        app.send_interval_ms = s.send_interval_ms;
        app.pursuit_mode = s.pursuit_mode;
        app.deauth_scope = s.deauth_scope;
    }

    let loaded_aps = persist::load_ap_list();
    if !loaded_aps.is_empty() {
        let count = loaded_aps.len();
        app.ap_list = loaded_aps;
        app.add_log(format!("Loaded {} persisted APs (press 'r' to clear)", count));
    }

    match app::init_scanner(&mut app, &listen_mon, supports_5ghz, supports_6ghz) {
        Ok(_) => {}
        Err(e) => {
            let _ = terminal::disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            eprintln!("Scanner init failed: {}", e);
            std::process::exit(1);
        }
    }

    app::init_log_file(&mut app);

    if attack_name != listen_name {
        app.add_log(format!(
            "Dual-adapter: listen={} ({}), attack={} ({})",
            listen_name, listen_mon, attack_name, attack_mon
        ));
    } else {
        app.add_log(format!(
            "smartdos initialized on {} (mon: {})",
            listen_name, listen_mon
        ));
    }
    let band_str = match (supports_5ghz, supports_6ghz) {
        (true, true)  => "2.4/5/6 GHz",
        (true, false) => "2.4/5 GHz",
        _             => "2.4 GHz only",
    };
    app.add_log(format!("Band support: {}", band_str));
    app.add_log("↑↓ nav | t target/client | c clients | r clear scan | I ifaces | Tab events | ←→ switch | M mode | S start/stop | Q quit".to_string());

    // Offer saved list at startup; user picks one or presses Esc to start fresh
    app::open_list_picker(&mut app);

    {
        let running = Arc::clone(&app.running);
        let mut signals = Signals::new([SIGINT, SIGTERM]).expect("failed to register signal handler");
        std::thread::spawn(move || {
            for _ in signals.forever() {
                running.store(false, Ordering::Relaxed);
            }
        });
    }

    let res = run_tui(&mut terminal, &mut app);
    shutdown(&mut terminal, &app);
    res
}


fn activate_monitor(iface: &str) -> String {
    if iface.ends_with("mon") {
        return iface.to_string();
    }
    match interface::enable_monitor_mode(iface) {
        Ok(mon) => mon,
        Err(e) => {
            let _ = terminal::disable_raw_mode();
            let _ = execute!(io::stdout(), LeaveAlternateScreen);
            eprintln!("Failed to enable monitor mode on {}: {}", iface, e);
            eprintln!("Try: airmon-ng start {}", iface);
            std::process::exit(1);
        }
    }
}

/// Diagnostic: when `SMARTDOS_TRACE` is set, overwrite ~/.smartdos/trace.log
/// with the name of the main-loop phase we're about to enter. If the UI freezes,
/// the file's contents name the phase that hung (the loop never reached the next
/// marker). No-op unless the env var is set, so it costs nothing in normal runs.
/// Inspect live with `watch -n0.2 cat ~/.smartdos/trace.log` while reproducing.
fn trace_phase(phase: &str) {
    if std::env::var_os("SMARTDOS_TRACE").is_none() {
        return;
    }
    if let Some(home) = std::env::var_os("HOME") {
        let dir = std::path::Path::new(&home).join(".smartdos");
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(dir.join("trace.log"), phase);
    }
}

fn run_tui<B: Backend>(terminal: &mut Terminal<B>, app: &mut App) -> Result<()>
where
    B::Error: Send + Sync + 'static,
{
    let tick_rate = std::time::Duration::from_millis(50);

    loop {
        trace_phase("draw");
        terminal.draw(|f| {
            ui::render(f, app);
        })?;

        trace_phase("update");
        app::update(app);

        trace_phase("poll");
        if event::poll(tick_rate)? {
            if let Event::Key(key) = event::read()? {
                trace_phase("handle_key");
                handle_key_event(app, key);
            }
        }

        trace_phase("overlays");
        if app.wants_setup {
            app.wants_setup = false;
            if app.attack_running {
                app::stop_attack(app);
            }
            let ifaces = interface::discover_interfaces().unwrap_or_default();
            // Pre-fill the overlay from the live config so reopening retains the
            // current roles + TX power instead of resetting to "auto".
            let listen_base = app.current_interface.as_ref().map(|i| i.name.clone());
            let attack_base = app.attack_physical.clone().or_else(|| listen_base.clone());
            let seed = setup::SetupSeed {
                listen_name: listen_base,
                attack_name: attack_base,
                txpower_dbm: app.txpower_dbm,
            };
            if let Ok(Some((listen, attack, txpower))) =
                setup::run_setup_overlay(terminal, ifaces, Some(seed))
            {
                reconfigure_adapters(app, listen, attack, txpower);
            }
        }

        if app.wants_settings {
            app.wants_settings = false;
            if let Ok(Some(result)) = settings::run_settings_overlay(
                terminal,
                app.burst_size,
                app.send_interval_ms,
                app.band_2ghz_enabled,
                app.band_5ghz_enabled,
                app.band_6ghz_enabled,
            ) {
                app.burst_size = result.burst_size;
                app.send_interval_ms = result.send_interval_ms;
                app.band_2ghz_enabled = result.band_2ghz;
                app.band_5ghz_enabled = result.band_5ghz;
                app.band_6ghz_enabled = result.band_6ghz;
                app.add_log(format!(
                    "Settings: burst={} interval={}ms bands={}{}{}",
                    result.burst_size,
                    result.send_interval_ms,
                    if result.band_2ghz { "2G" } else { "" },
                    if result.band_5ghz { " 5G" } else { "" },
                    if result.band_6ghz { " 6G" } else { "" },
                ));
                let _ = persist::save_attack_settings(&persist::AttackSettings {
                    attack_type: app.attack_type,
                    attack_mode: app.attack_mode,
                    burst_size: result.burst_size,
                    send_interval_ms: result.send_interval_ms,
                    pursuit_mode: app.pursuit_mode,
                    deauth_scope: app.deauth_scope.clone(),
                });
                if app.attack_running {
                    if let Some(ref tx) = app.attack_cmd_tx {
                        let _ = tx.send(types::AttackCommand::UpdateSettings {
                            burst_size: result.burst_size,
                            send_interval_ms: result.send_interval_ms,
                        });
                    }
                }
                if let Some(ref tx) = app.scanner_cmd_tx {
                    let _ = tx.send(types::ScannerCommand::UpdateBands {
                        band_2ghz: result.band_2ghz,
                        band_5ghz: result.band_5ghz,
                        band_6ghz: result.band_6ghz,
                    });
                }
            }
        }

        if !app.running.load(Ordering::Relaxed) {
            break;
        }
    }

    Ok(())
}

fn reconfigure_adapters(app: &mut App, listen: String, attack: String, txpower: Option<i32>) {
    // Fast path: roles unchanged → only TX power may have changed. Apply it
    // directly instead of tearing down/rebuilding monitor mode and restarting
    // the scanner (which would needlessly interrupt the live capture).
    let cur_listen = app.current_interface.as_ref().map(|i| i.name.clone());
    let cur_attack = app.attack_physical.clone().or_else(|| cur_listen.clone());
    let roles_unchanged =
        cur_listen.as_deref() == Some(listen.as_str()) && cur_attack.as_deref() == Some(attack.as_str());
    if roles_unchanged {
        if let Some(atk_mon) = app.attack_interface.clone() {
            match txpower {
                Some(dbm) => match interface::set_txpower(&atk_mon, Some(dbm)) {
                    Ok(()) => {
                        app.txpower_dbm = Some(dbm);
                        app.add_log(format!("TX power set to {}dBm", dbm));
                    }
                    Err(e) => app.add_log(format!("TX power error: {}", e)),
                },
                None => {
                    let _ = interface::set_txpower(&atk_mon, None);
                    app.txpower_dbm = interface::get_txpower(&atk_mon);
                    app.add_log("TX power set to auto".to_string());
                }
            }
        }
        return;
    }

    let listen_changed = app.listen_interface.as_deref() != Some(&listen);

    // Disable old attack adapter if distinct from listen
    if let Some(old_atk_mon) = app.attack_interface.clone() {
        let old_listen_mon = app.monitor_interface.as_deref().unwrap_or("");
        if old_atk_mon != old_listen_mon {
            let atk_phys = app.attack_physical.as_deref().unwrap_or(old_atk_mon.as_str());
            let _ = interface::disable_monitor_mode(atk_phys, &old_atk_mon);
        }
    }

    // Disable old listen adapter if it's changing
    if listen_changed {
        if let (Some(phys), Some(mon)) = (&app.current_interface, &app.monitor_interface) {
            let _ = interface::disable_monitor_mode(&phys.name.clone(), mon);
        }
    }

    let listen_mon = activate_monitor(&listen);
    let attack_mon = if attack != listen {
        activate_monitor(&attack)
    } else {
        listen_mon.clone()
    };

    app.current_interface = Some(WirelessInterface {
        name: listen.clone(),
        phy: String::new(),
        monitor_name: Some(listen_mon.clone()),
        is_monitor: false,
    });
    app.monitor_interface = Some(listen_mon.clone());
    app.listen_interface = Some(listen_mon.clone());
    app.attack_interface = Some(attack_mon.clone());
    app.attack_physical = if attack != listen { Some(attack.clone()) } else { None };

    if let Some(dbm) = txpower {
        match interface::set_txpower(&attack_mon, Some(dbm)) {
            Ok(()) => app.txpower_dbm = Some(dbm),
            Err(e) => app.add_log(format!("TX power error: {}", e)),
        }
    } else {
        app.txpower_dbm = interface::get_txpower(&attack_mon);
    }

    if listen_changed {
        // Kill old scanner, start fresh one
        app.scanner_running.store(false, Ordering::Relaxed);
        std::thread::sleep(std::time::Duration::from_millis(400));
        app.scanner_running = Arc::new(AtomicBool::new(true));
        // Re-detect band capabilities for newly selected interface
        let listen_phy = interface::discover_interfaces().ok()
            .and_then(|ifaces| ifaces.into_iter().find(|i| i.name == listen))
            .map(|i| i.phy)
            .unwrap_or_default();
        let (s5, s6) = interface::detect_band_capabilities(&listen_phy);
        let _ = app::init_scanner(app, &listen_mon, s5, s6);
    }

    if attack != listen {
        app.add_log(format!(
            "Reconfigured: listen={} ({}), attack={} ({})",
            listen, listen_mon, attack, attack_mon
        ));
    } else {
        app.add_log(format!(
            "Reconfigured: {} (mon: {})",
            listen, listen_mon
        ));
    }
}

fn handle_key_event(app: &mut App, key: KeyEvent) {
    // Some terminals / remote-control layers (e.g. macOS screen sharing, VNC) emit the
    // Delete/Backspace key as ^H (byte 0x08) instead of ^? (0x7F). crossterm parses 0x08
    // as Char('h')+CONTROL, so without this it lands in the generic Char(c) arm and types
    // an 'h'. Normalize Ctrl+H to Backspace so deletion works through remote control.
    let key = if key.code == KeyCode::Char('h') && key.modifiers.contains(KeyModifiers::CONTROL) {
        KeyEvent { code: KeyCode::Backspace, ..key }
    } else {
        key
    };

    // AP filter mode — intercept typing; Up/Down still navigate the filtered list
    if app.input_mode == InputMode::ApFilter {
        match key.code {
            KeyCode::Char(c) => {
                app.ap_filter.push(c);
                // snap selection to first visible AP
                let vis = app.visible_ap_indices();
                app.selected_ap_idx = vis.first().copied().unwrap_or(0);
                app.scroll_offset = app.selected_ap_idx;
            }
            KeyCode::Backspace => {
                app.ap_filter.pop();
                let vis = app.visible_ap_indices();
                app.selected_ap_idx = vis.first().copied().unwrap_or(0);
                app.scroll_offset = app.selected_ap_idx;
            }
            KeyCode::Up => {
                let vis = app.visible_ap_indices();
                if let Some(pos) = vis.iter().position(|&i| i == app.selected_ap_idx) {
                    if pos > 0 {
                        app.selected_ap_idx = vis[pos - 1];
                        app.scroll_offset = app.scroll_offset.min(app.selected_ap_idx);
                    }
                }
            }
            KeyCode::Down => {
                let vis = app.visible_ap_indices();
                if let Some(pos) = vis.iter().position(|&i| i == app.selected_ap_idx) {
                    if pos + 1 < vis.len() {
                        app.selected_ap_idx = vis[pos + 1];
                    }
                }
            }
            KeyCode::Enter => {
                // keep filter, exit typing mode
                app.input_mode = InputMode::Normal;
            }
            KeyCode::Esc => {
                app.ap_filter.clear();
                app.input_mode = InputMode::Normal;
                app.selected_ap_idx = 0;
                app.scroll_offset = 0;
            }
            _ => {}
        }
        return;
    }

    // Text input mode — intercept all keys
    if app.input_mode != InputMode::Normal {
        match key.code {
            KeyCode::Char(c) => { app.input_buffer.push(c); }
            KeyCode::Backspace => { app.input_buffer.pop(); }
            KeyCode::Enter => {
                let buf = app.input_buffer.trim().to_string();
                let mode = app.input_mode;
                app.input_mode = InputMode::Normal;
                app.input_buffer.clear();
                match mode {
                    InputMode::SaveListName => {
                        if app.tab_selection == TabSelection::ClientList {
                            app::save_client_list_named(app, &buf);
                        } else {
                            app::save_ap_list_named(app, &buf);
                        }
                    }
                    InputMode::ClientRename => {
                        if let Some(mac) = app.input_context.take() {
                            app::set_client_friendly_name(app, &mac, buf);
                        }
                    }
                    InputMode::Normal | InputMode::ApFilter => {}
                }
            }
            KeyCode::Esc => {
                app.input_mode = InputMode::Normal;
                app.input_buffer.clear();
                app.input_context = None;
            }
            _ => {}
        }
        return;
    }

    // List picker navigation
    if app.list_picker_open {
        match key.code {
            KeyCode::Up => {
                app.list_picker_idx = app.list_picker_idx.saturating_sub(1);
            }
            KeyCode::Down => {
                if app.list_picker_idx + 1 < app.list_picker_slots.len() {
                    app.list_picker_idx += 1;
                }
            }
            KeyCode::Enter => {
                let name = app.list_picker_slots.get(app.list_picker_idx).cloned();
                app.list_picker_open = false;
                if let Some(n) = name {
                    app::load_saved_list(app, &n);
                }
            }
            KeyCode::Esc => { app.list_picker_open = false; }
            _ => {}
        }
        return;
    }

    // Full-screen Events page — read-only viewer: scroll + exit only.
    // (events_scroll is counted from the newest line; render clamps to viewport.)
    if app.page_view == PageView::Events {
        let max_scroll = app.log_messages.len().saturating_sub(1);
        match key.code {
            KeyCode::Tab | KeyCode::Esc => app.page_view = PageView::Dashboard,
            KeyCode::Up => app.events_scroll = (app.events_scroll + 1).min(max_scroll),
            KeyCode::Down => app.events_scroll = app.events_scroll.saturating_sub(1),
            KeyCode::PageUp => app.events_scroll = (app.events_scroll + 10).min(max_scroll),
            KeyCode::PageDown => app.events_scroll = app.events_scroll.saturating_sub(10),
            KeyCode::Home => app.events_scroll = max_scroll,
            KeyCode::End => app.events_scroll = 0,
            KeyCode::Char('q') | KeyCode::Char('Q') => {
                if app.attack_running {
                    app::stop_attack(app);
                }
                app.running.store(false, std::sync::atomic::Ordering::Relaxed);
            }
            _ => {}
        }
        return;
    }

    match key.code {
        KeyCode::Char('q') | KeyCode::Char('Q') => {
            if app.attack_running {
                app::stop_attack(app);
            }
            app.running
                .store(false, std::sync::atomic::Ordering::Relaxed);
        }
        KeyCode::Up => match app.tab_selection {
            TabSelection::ApList => {
                if app.selected_ap_idx > 0 {
                    app.selected_ap_idx -= 1;
                    if app.selected_ap_idx < app.scroll_offset {
                        app.scroll_offset = app.selected_ap_idx;
                    }
                }
            }
            TabSelection::TargetList => {
                let sub_indices = target_sub_indices(&app);
                if !sub_indices.is_empty() {
                    let cur = app.selected_target_idx
                        .and_then(|i| sub_indices.iter().position(|&x| x == i))
                        .unwrap_or(0);
                    if cur > 0 {
                        app.selected_target_idx = Some(sub_indices[cur - 1]);
                    }
                }
            }
            TabSelection::ClientList => {
                if let Some(idx) = app.selected_client_idx {
                    if idx > 0 {
                        app.selected_client_idx = Some(idx - 1);
                    }
                } else {
                    app.selected_client_idx = Some(0);
                }
            }
        },
        KeyCode::Down => match app.tab_selection {
            TabSelection::ApList => {
                if app.selected_ap_idx + 1 < app.ap_list.len() {
                    app.selected_ap_idx += 1;
                    let visible: usize = 20;
                    if app.selected_ap_idx >= app.scroll_offset + visible {
                        app.scroll_offset = app.selected_ap_idx - visible + 1;
                    }
                }
            }
            TabSelection::TargetList => {
                let sub_indices = target_sub_indices(&app);
                if !sub_indices.is_empty() {
                    let cur = app.selected_target_idx
                        .and_then(|i| sub_indices.iter().position(|&x| x == i))
                        .unwrap_or(0);
                    if cur + 1 < sub_indices.len() {
                        app.selected_target_idx = Some(sub_indices[cur + 1]);
                    }
                }
            }
            TabSelection::ClientList => {
                let client_count = if app.selected_ap_idx < app.ap_list.len() {
                    app.ap_list[app.selected_ap_idx].clients.len()
                } else {
                    0
                };
                let idx = app.selected_client_idx.unwrap_or(0);
                if client_count > 0 && idx + 1 < client_count {
                    app.selected_client_idx = Some(idx + 1);
                }
            }
        },
        KeyCode::Tab => {
            // Tab opens the full-screen Events page (Tab/Esc returns).
            app.page_view = PageView::Events;
            app.events_scroll = 0;
        }
        KeyCode::Right => {
            // Cycle: ApList → TargetList(Clients) → TargetList(Aps) → ApList
            match app.tab_selection {
                TabSelection::ApList => {
                    app.tab_selection = TabSelection::TargetList;
                    app.target_sub_section = TargetSubSection::Clients;
                    let sub_indices = target_sub_indices(&app);
                    app.selected_target_idx = sub_indices.first().copied();
                }
                TabSelection::TargetList if app.target_sub_section == TargetSubSection::Clients => {
                    app.target_sub_section = TargetSubSection::Aps;
                    let sub_indices = target_sub_indices(&app);
                    app.selected_target_idx = sub_indices.first().copied();
                }
                TabSelection::TargetList => {
                    app.tab_selection = TabSelection::ApList;
                }
                TabSelection::ClientList => {}
            }
        }
        KeyCode::Left => {
            // Cycle: ApList → TargetList(Aps) → TargetList(Clients) → ApList
            match app.tab_selection {
                TabSelection::ApList => {
                    app.tab_selection = TabSelection::TargetList;
                    app.target_sub_section = TargetSubSection::Aps;
                    let sub_indices = target_sub_indices(&app);
                    app.selected_target_idx = sub_indices.first().copied();
                }
                TabSelection::TargetList if app.target_sub_section == TargetSubSection::Aps => {
                    app.target_sub_section = TargetSubSection::Clients;
                    let sub_indices = target_sub_indices(&app);
                    app.selected_target_idx = sub_indices.first().copied();
                }
                TabSelection::TargetList => {
                    app.tab_selection = TabSelection::ApList;
                }
                TabSelection::ClientList => {}
            }
        }
        KeyCode::Char('c') | KeyCode::Char('C') => {
            match app.tab_selection {
                TabSelection::ClientList => {
                    // Leave client list — resume broad scanning
                    app.tab_selection = TabSelection::ApList;
                    if app.channel_focused {
                        app.channel_focused = false;
                        if let Some(ref tx) = app.scanner_cmd_tx {
                            let _ = tx.send(types::ScannerCommand::FreeHop);
                        }
                        app.add_log("Focus mode off — resuming channel scan".to_string());
                    }
                }
                _ => {
                    // Open client list and lock scanner to AP's channel
                    app.tab_selection = TabSelection::ClientList;
                    app.selected_client_idx = Some(0);
                    if let Some(ap) = app.ap_list.get(app.selected_ap_idx) {
                        let ch = ap.channel;
                        let band = ap.band;
                        if ch != 0 {
                            app.channel_focused = true;
                            if let Some(ref tx) = app.scanner_cmd_tx {
                                let _ = tx.send(types::ScannerCommand::LockChannel(ch, band));
                            }
                            app.add_log(format!(
                                "Focus mode: locked to ch{} ({}) for client discovery",
                                ch, band.label()
                            ));
                        }
                    }
                }
            }
        }
        KeyCode::Char('t') | KeyCode::Char('T') => {
            if app.tab_selection == TabSelection::ClientList {
                // Target selected client (follow/unfollow)
                let client_mac = if app.selected_ap_idx < app.ap_list.len() {
                    let clients = &app.ap_list[app.selected_ap_idx].clients;
                    let idx = app.selected_client_idx.unwrap_or(0);
                    clients.get(idx).map(|c| c.mac.clone())
                } else {
                    None
                };
                if let Some(mac) = client_mac {
                    let result = app.toggle_follow_client(&mac.clone());
                    let still_following = app.followed_clients.iter().any(|(m, _)| m == &mac);
                    if still_following {
                        app.add_log(format!(
                            "Client targeted: {} ({} total)",
                            mac,
                            app.followed_clients.len()
                        ));
                        if let Some(ap_bssid) = result {
                            app.add_log(format!("Auto-targeted AP: {}", ap_bssid));
                        }
                    } else {
                        app.add_log(format!("Client target removed: {}", mac));
                    }
                    if app.attack_running {
                        let targets = app.targets.clone();
                        if let Some(tx) = &app.attack_cmd_tx {
                            let _ = tx.send(types::AttackCommand::UpdateTargets(targets));
                        }
                    }
                }
            } else if !app.ap_list.is_empty() {
                let idx = app.selected_ap_idx.min(app.ap_list.len() - 1);
                let bssid = app.ap_list[idx].bssid.clone();
                let ssid = app.ap_list[idx].ssid.clone();
                app.toggle_target(&bssid);
                if app.is_target(&bssid) {
                    app.add_log(format!("Target added: {} ({})", ssid, bssid));
                } else {
                    app.add_log(format!("Target removed: {} ({})", ssid, bssid));
                }
            }
        }
        KeyCode::Char('d') | KeyCode::Char('D') => {
            if app.tab_selection == TabSelection::TargetList {
                if let Some(idx) = app.selected_target_idx {
                    if idx < app.targets.len() {
                        let bssid = app.targets[idx].bssid.clone();
                        app.remove_target(idx);
                        app.add_log(format!("Target removed: {}", bssid));
                    }
                }
            } else if !app.ap_list.is_empty() {
                let idx = app.selected_ap_idx.min(app.ap_list.len() - 1);
                let bssid = app.ap_list[idx].bssid.clone();
                if app.is_target(&bssid) {
                    app.toggle_target(&bssid);
                    app.add_log(format!("Target removed: {}", bssid));
                }
            }
        }
        KeyCode::Char('g') | KeyCode::Char('G') => {
            app.wants_settings = true;
        }
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
                if app.attack_running {
                    let targets = app.targets.clone();
                    if let Some(tx) = &app.attack_cmd_tx {
                        let _ = tx.send(types::AttackCommand::UpdateTargets(targets));
                    }
                }
            }
        }
        KeyCode::Char('a') | KeyCode::Char('A') => {
            app::toggle_attack_type(app);
            if app.attack_type.is_destructive() {
                app.add_log(
                    "⚠ Auth-DoS: auth-floods AP association table — can crash AP firmware"
                        .to_string(),
                );
            }
            let _ = persist::save_attack_settings(&persist::AttackSettings {
                attack_type: app.attack_type,
                attack_mode: app.attack_mode,
                burst_size: app.burst_size,
                send_interval_ms: app.send_interval_ms,
                pursuit_mode: app.pursuit_mode,
                deauth_scope: app.deauth_scope.clone(),
            });
        }
        KeyCode::Char('m') | KeyCode::Char('M') => {
            app::toggle_attack_mode(app);
            let _ = persist::save_attack_settings(&persist::AttackSettings {
                attack_type: app.attack_type,
                attack_mode: app.attack_mode,
                burst_size: app.burst_size,
                send_interval_ms: app.send_interval_ms,
                pursuit_mode: app.pursuit_mode,
                deauth_scope: app.deauth_scope.clone(),
            });
        }
        KeyCode::Char('p') | KeyCode::Char('P') => {
            app::toggle_pursuit_mode(app);
            let _ = persist::save_attack_settings(&persist::AttackSettings {
                attack_type: app.attack_type,
                attack_mode: app.attack_mode,
                burst_size: app.burst_size,
                send_interval_ms: app.send_interval_ms,
                pursuit_mode: app.pursuit_mode,
                deauth_scope: app.deauth_scope.clone(),
            });
        }
        KeyCode::Char('s') | KeyCode::Char('S') => {
            if app.attack_running {
                app::stop_attack(app);
            } else {
                app::start_attack(app);
            }
        }
        KeyCode::Char(' ') => {
            if app.tab_selection == TabSelection::TargetList {
                if let Some(idx) = app.selected_target_idx {
                    if idx < app.targets.len() {
                        app.targets[idx].active = !app.targets[idx].active;
                        app.add_log(format!(
                            "Target {} {}",
                            app.targets[idx].ssid,
                            if app.targets[idx].active {
                                "activated"
                            } else {
                                "deactivated"
                            }
                        ));
                    }
                }
            }
        }
        KeyCode::Char('r') | KeyCode::Char('R') => {
            app::clear_scan_results(app);
            app.ap_filter.clear();
        }
        KeyCode::Char('/') => {
            if app.tab_selection == TabSelection::ApList {
                app.input_mode = InputMode::ApFilter;
            }
        }
        KeyCode::Char('w') | KeyCode::Char('W') => {
            app.input_mode = InputMode::SaveListName;
            app.input_buffer.clear();
        }
        KeyCode::Char('l') | KeyCode::Char('L') => {
            app::open_list_picker(app);
        }
        KeyCode::Char('n') | KeyCode::Char('N') => {
            if app.tab_selection == TabSelection::ClientList {
                let client_mac = if app.selected_ap_idx < app.ap_list.len() {
                    let clients = &app.ap_list[app.selected_ap_idx].clients;
                    let idx = app.selected_client_idx.unwrap_or(0);
                    clients.get(idx).map(|c| c.mac.clone())
                } else {
                    None
                };
                if let Some(mac) = client_mac {
                    app.input_context = Some(mac);
                    app.input_mode = InputMode::ClientRename;
                    app.input_buffer.clear();
                }
            }
        }
        KeyCode::Char('i') | KeyCode::Char('I') => {
            app.wants_setup = true;
        }
        KeyCode::Esc => {
            if app.tab_selection == TabSelection::ClientList {
                app.tab_selection = TabSelection::ApList;
                if app.channel_focused {
                    app.channel_focused = false;
                    if let Some(ref tx) = app.scanner_cmd_tx {
                        let _ = tx.send(types::ScannerCommand::FreeHop);
                    }
                    app.add_log("Focus mode off — resuming channel scan".to_string());
                }
            } else {
                if app.attack_running {
                    app::stop_attack(app);
                }
                app.running
                    .store(false, std::sync::atomic::Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

fn shutdown<B: Backend>(_terminal: &mut Terminal<B>, app: &App) {
    // Stop listen adapter monitor mode
    if let (Some(iface), Some(mon)) = (&app.current_interface, &app.monitor_interface) {
        let _ = interface::disable_monitor_mode(&iface.name, mon);
    } else if let Some(mon) = &app.monitor_interface {
        let _ = interface::disable_monitor_mode(mon, mon);
    }

    // Stop attack adapter if it's a distinct physical adapter
    if let Some(atk_mon) = &app.attack_interface {
        let listen_mon = app.monitor_interface.as_deref().unwrap_or("");
        if atk_mon != listen_mon {
            let atk_phys = app.attack_physical.as_deref().unwrap_or(atk_mon.as_str());
            let _ = interface::disable_monitor_mode(atk_phys, atk_mon);
        }
    }

    // Restore the regulatory domain we changed for max TX power
    if let Some(cc) = &app.original_reg_domain {
        let _ = interface::set_reg_domain(cc);
    }

    let _ = persist::save_ap_list(&app.ap_list);
    let _ = saved_lists::save_client_names(&app.client_names);

    let _ = terminal::disable_raw_mode();
    let _ = execute!(io::stdout(), LeaveAlternateScreen);

    println!("smartdos shutdown complete.");
    println!(
        "Total deauth frames sent: {}",
        app.targets.iter().map(|t| t.deauth_count).sum::<u64>()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    // Remote-control / VNC sends Delete as ^H (0x08), which crossterm reports as
    // Char('h')+CONTROL. It must delete a character from the AP filter, not type 'h'.
    #[test]
    fn ctrl_h_deletes_in_ap_filter() {
        let (mut app, _tx) = App::new();
        app.input_mode = InputMode::ApFilter;
        app.ap_filter = "abc".to_string();

        let ctrl_h = KeyEvent::new(KeyCode::Char('h'), KeyModifiers::CONTROL);
        handle_key_event(&mut app, ctrl_h);

        assert_eq!(app.ap_filter, "ab", "Ctrl+H should delete, not insert 'h'");
    }

    // A plain 'h' keystroke must still type into the filter.
    #[test]
    fn plain_h_types_in_ap_filter() {
        let (mut app, _tx) = App::new();
        app.input_mode = InputMode::ApFilter;
        app.ap_filter = "ab".to_string();

        let h = KeyEvent::new(KeyCode::Char('h'), KeyModifiers::NONE);
        handle_key_event(&mut app, h);

        assert_eq!(app.ap_filter, "abh");
    }
}
