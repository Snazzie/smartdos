use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table},
    Frame,
};

use crate::oui;
use crate::types::{App, AttackMode, AttackType, Band, DeauthScope, InputMode, TabSelection};

pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    let main_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(7),
            Constraint::Length(3),
        ])
        .split(area);

    render_top_bar(frame, app, main_layout[0]);
    render_body(frame, app, main_layout[1]);
    render_logs(frame, app, main_layout[2]);
    render_footer(frame, app, main_layout[3]);

    if app.list_picker_open {
        render_list_picker(frame, app, area);
    }
}

/// Top bar: title, interface info, attack status, channel, stats
fn render_top_bar(frame: &mut Frame, app: &App, area: Rect) {
    let title_str = match app.followed_clients.len() {
        0 => " smartdos v0.1 — Wireless Deauth Toolkit ".to_string(),
        1 => format!(" smartdos — FOLLOW CLIENT {} ", app.followed_clients[0].0),
        n => format!(" smartdos — FOLLOWING {} CLIENTS ", n),
    };

    let iface_info = match (&app.listen_interface, &app.attack_interface) {
        (Some(l), Some(a)) if l != a => format!(" [L:{} A:{}", l, a),
        (Some(mon), _) | (_, Some(mon)) => format!(" [{}", mon),
        _ => " [no iface".to_string(),
    };
    let ch_info = format!(" ch:{}/{}] ", app.current_channel, app.current_band.label());

    let mode_str = match app.state {
        crate::types::AppState::Scanning => " SCAN ",
        crate::types::AppState::Attacking => " ATTACK ",
    };

    let ap_count = app.ap_list.len();
    let client_count: usize = app.ap_list.iter().map(|a| a.clients.len()).sum();
    let target_count = app.targets.len();
    let total_deauth: u64 = app.targets.iter().map(|t| t.deauth_count).sum();

    let stats = format!(
        " APs:{} | Clients:{} | Targets:{} | Deauth:{} ",
        ap_count, client_count, target_count, total_deauth
    );

    let title_style = if app.attack_running {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    };

    let block = Block::default()
        .border_type(BorderType::Rounded)
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Line::from(Span::styled(&title_str, title_style)));

    let inner = block.inner(area);
    frame.render_widget(block, area);

    let left = Span::styled(iface_info + &ch_info, Style::default().fg(Color::Green));
    let center = Span::styled(
        mode_str,
        if app.attack_running {
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Yellow)
        },
    );
    let right = Span::styled(stats, Style::default().fg(Color::Gray));
    let sep = Span::raw("  │  ");

    let text = Text::from(Line::from(vec![left, sep.clone(), center, sep, right]));
    frame.render_widget(Paragraph::new(text).style(Style::default()), inner);
}

/// Body: AP list (left) + Target/Client panel (right)
fn render_body(frame: &mut Frame, app: &App, area: Rect) {
    let body_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    render_ap_list(frame, app, body_layout[0]);

    match app.tab_selection {
        TabSelection::TargetList => render_targets_panel(frame, app, body_layout[1]),
        TabSelection::ClientList => render_clients_panel(frame, app, body_layout[1]),
        TabSelection::ApList => render_targets_panel(frame, app, body_layout[1]),
    }
}

/// AP list table (left panel) — SSID / BSSID / CH / dBm / Enc / Cli / Rate
fn render_ap_list(frame: &mut Frame, app: &App, area: Rect) {
    let border_style = if app.tab_selection == TabSelection::ApList {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::default()
        .title(" Access Points ")
        .title_alignment(Alignment::Left)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style);

    let inner = block.inner(area);
    let visible_height = (inner.height as usize).saturating_sub(2);
    let scroll_offset = app.scroll_offset;

    let header_cells = ["SSID", "BSSID", "CH", "dBm", "Enc", "Cli", "Rate"]
        .iter()
        .map(|h| {
            Cell::from(*h).style(
                Style::default()
                    .fg(Color::White)
                    .add_modifier(Modifier::BOLD),
            )
        });
    let header = Row::new(header_cells)
        .height(1)
        .style(Style::default().bg(Color::Blue));

    let rows: Vec<Row> = app
        .ap_list
        .iter()
        .skip(scroll_offset)
        .take(visible_height)
        .enumerate()
        .map(|(display_idx, ap)| {
            let global_idx = scroll_offset + display_idx;
            let is_target = app.is_target(&ap.bssid);
            let is_selected =
                global_idx == app.selected_ap_idx && app.tab_selection == TabSelection::ApList;
            let is_followed = app.followed_clients.iter()
                .any(|(_, maybe_ap)| maybe_ap.as_deref() == Some(&ap.bssid));

            let signal_color = if ap.signal_dbm >= -50 {
                Color::Green
            } else if ap.signal_dbm >= -70 {
                Color::Yellow
            } else {
                Color::Red
            };

            let row_style = if is_selected {
                Style::default()
                    .bg(Color::Rgb(40, 40, 80))
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

            let ssid_display = if ap.ssid.is_empty() || ap.ssid == "<Hidden>" {
                Span::styled("<Hidden>", Style::default().fg(Color::DarkGray))
            } else {
                let marker = if is_followed { "▶" } else { " " };
                Span::styled(
                    format!("{}{}", marker, truncate_str(&ap.ssid, 14)),
                    Style::default(),
                )
            };

            let enc_color = match ap.encryption.as_str() {
                "OPEN" => Color::Red,
                "WEP" => Color::Red,
                "OWE" | "WPA" | "WPA/C" | "WPA-E" | "W2/T" => Color::Yellow,
                "WPA3" | "W2/W3" => Color::Cyan,
                _ => Color::Green, // WPA2, W2-Ent
            };

            let rate_str = if ap.traffic_rate < 0.5 {
                "  --  ".to_string()
            } else {
                format!("{:>4.0}p/s", ap.traffic_rate)
            };

            Row::new(vec![
                Cell::from(ssid_display),
                Cell::from(truncate_str(&ap.bssid, 17)),
                Cell::from(Span::styled(
                    format!("{}{:>3}", ap.band.label(), ap.channel),
                    Style::default().fg(match ap.band {
                        Band::TwoGHz  => Color::White,
                        Band::FiveGHz => Color::Cyan,
                        Band::SixGHz  => Color::Magenta,
                    }),
                )),
                Cell::from(Span::styled(
                    format!("{:>4}", ap.signal_dbm),
                    Style::default().fg(signal_color),
                )),
                Cell::from(Span::styled(
                    truncate_str(&ap.encryption, 6),
                    Style::default().fg(enc_color),
                )),
                Cell::from(Span::styled(
                    format!("{:>3}", ap.clients.len()),
                    Style::default().fg(if ap.clients.is_empty() {
                        Color::DarkGray
                    } else {
                        Color::Cyan
                    }),
                )),
                Cell::from(Span::styled(
                    rate_str,
                    Style::default().fg(Color::Magenta),
                )),
            ])
            .style(row_style)
            .height(1)
        })
        .collect();

    // SSID(25) BSSID(21) CH(5) dBm(7) Enc(9) Cli(6) Rate(27) = 100%
    let table_widths = [
        Constraint::Percentage(25),
        Constraint::Percentage(21),
        Constraint::Percentage(5),
        Constraint::Percentage(7),
        Constraint::Percentage(9),
        Constraint::Percentage(6),
        Constraint::Percentage(27),
    ];

    let table = Table::new(rows, table_widths)
        .header(header)
        .column_spacing(1);

    frame.render_widget(table, inner);
    frame.render_widget(block, area);
}

/// Target list panel (right, shown in TargetList tab)
fn render_targets_panel(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.tab_selection == TabSelection::TargetList;
    let style = if is_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let block = Block::default()
        .title(format!(" Targets ({}) ", app.targets.len()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style);

    let inner = block.inner(area);

    if app.targets.is_empty() {
        let empty_text = Paragraph::new(Text::from(vec![
            Line::from(""),
            Line::from("  No targets added."),
            Line::from("  't' to add selected AP"),
            Line::from("  'c' to view AP clients"),
            Line::from("  'f' to follow a client"),
        ]))
        .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty_text, inner);
        frame.render_widget(block, area);
        return;
    }

    let visible_height = (inner.height as usize).saturating_sub(2);
    let scroll_offset = app.target_scroll_offset;

    let rows: Vec<Row> = app
        .targets
        .iter()
        .skip(scroll_offset)
        .take(visible_height)
        .enumerate()
        .map(|(display_idx, target)| {
            let global_idx = scroll_offset + display_idx;
            let is_selected = is_active && app.selected_target_idx == Some(global_idx);

            let status = if target.active { " ACTIVE " } else { "OFF" };
            let row_style = if is_selected {
                Style::default()
                    .bg(Color::Rgb(50, 30, 30))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let disc_cell = if target.disconnect_count > 0 {
                Cell::from(Span::styled(
                    format!("{:>5}", target.disconnect_count),
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ))
            } else {
                Cell::from(Span::styled("    -", Style::default().fg(Color::DarkGray)))
            };

            Row::new(vec![
                Cell::from(truncate_str(&target.ssid, 14)),
                Cell::from(truncate_str(&target.bssid, 17)),
                Cell::from(format!("{:>3}", target.channel)),
                Cell::from(Span::styled(
                    status,
                    Style::default().fg(if target.active {
                        Color::Red
                    } else {
                        Color::DarkGray
                    }),
                )),
                Cell::from(format!("{:>6}", target.deauth_count)),
                disc_cell,
            ])
            .style(row_style)
            .height(1)
        })
        .collect();

    let header = Row::new(["SSID", "BSSID", "CH", "Status", "Sent", "Disc"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
    }))
    .height(1)
    .style(Style::default().bg(Color::Rgb(100, 0, 0)));

    let table_widths = [
        Constraint::Percentage(22),
        Constraint::Percentage(26),
        Constraint::Percentage(7),
        Constraint::Percentage(14),
        Constraint::Percentage(18),
        Constraint::Percentage(13),
    ];

    let table = Table::new(rows, table_widths)
        .header(header)
        .column_spacing(1);

    frame.render_widget(table, inner);
    frame.render_widget(block, area);
}

/// Client list panel (right, shown in ClientList tab) — MAC / Vendor / dBm / Status / Pkts
fn render_clients_panel(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.tab_selection == TabSelection::ClientList;
    let style = if is_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let ap_label = if app.selected_ap_idx < app.ap_list.len() {
        let ap = &app.ap_list[app.selected_ap_idx];
        let name = if ap.ssid.is_empty() || ap.ssid == "<Hidden>" {
            ap.bssid.clone()
        } else {
            ap.ssid.clone()
        };
        format!(" Clients — {} ", truncate_str(&name, 20))
    } else {
        " Clients ".to_string()
    };

    let block = Block::default()
        .title(ap_label)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(style);

    let inner = block.inner(area);

    static EMPTY_CLIENTS: Vec<crate::types::Client> = Vec::new();
    let clients: &[crate::types::Client] = if app.selected_ap_idx < app.ap_list.len() {
        &app.ap_list[app.selected_ap_idx].clients
    } else {
        &EMPTY_CLIENTS
    };

    if clients.is_empty() {
        let empty_text = Paragraph::new(Text::from(vec![
            Line::from(""),
            Line::from("  No clients detected."),
            Line::from(""),
            Line::from("  Clients appear when they"),
            Line::from("  probe, associate, or send"),
            Line::from("  data frames."),
            Line::from(""),
            Line::from("  'f' follow  Tab back"),
        ]))
        .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty_text, inner);
        frame.render_widget(block, area);
        return;
    }

    // Leave bottom row for hint
    let visible_height = (inner.height as usize).saturating_sub(3);
    let rows: Vec<Row> = clients
        .iter()
        .take(visible_height)
        .enumerate()
        .map(|(i, client)| {
            let is_selected = is_active && app.selected_client_idx == Some(i);
            let is_followed = app.followed_clients.iter().any(|(m, _)| m == &client.mac);

            let row_style = if is_selected && is_followed {
                Style::default()
                    .bg(Color::Rgb(80, 20, 20))
                    .add_modifier(Modifier::BOLD)
            } else if is_selected {
                Style::default()
                    .bg(Color::Rgb(40, 40, 80))
                    .add_modifier(Modifier::BOLD)
            } else if is_followed {
                Style::default()
                    .bg(Color::Rgb(50, 20, 20))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };

            let mac_display = if is_followed {
                format!("▶{}", &client.mac)
            } else {
                client.mac.clone()
            };

            let vendor = oui::lookup(&client.mac);
            let vendor_display = if vendor.is_empty() {
                "Unknown".to_string()
            } else {
                vendor.to_string()
            };

            let status = if client.associated { "ASSOC" } else { "probe" };
            let signal_color = if client.signal_dbm >= -50 {
                Color::Green
            } else if client.signal_dbm >= -70 {
                Color::Yellow
            } else {
                Color::Red
            };

            let name_display = client
                .friendly_name
                .as_deref()
                .unwrap_or("")
                .to_string();

            Row::new(vec![
                Cell::from(Span::styled(truncate_str(&mac_display, 17), Style::default())),
                Cell::from(Span::styled(
                    truncate_str(&name_display, 10),
                    Style::default().fg(Color::Yellow),
                )),
                Cell::from(Span::styled(
                    truncate_str(&vendor_display, 9),
                    Style::default().fg(Color::Cyan),
                )),
                Cell::from(Span::styled(
                    format!("{:>4}", client.signal_dbm),
                    Style::default().fg(signal_color),
                )),
                Cell::from(Span::styled(
                    status,
                    Style::default().fg(if client.associated {
                        Color::Green
                    } else {
                        Color::DarkGray
                    }),
                )),
                Cell::from(format!("{:>5}", client.packets)),
            ])
            .style(row_style)
            .height(1)
        })
        .collect();

    let header = Row::new(["MAC", "Name", "Vendor", "dBm", "St", "Pkts"].iter().map(|h| {
        Cell::from(*h).style(
            Style::default()
                .fg(Color::White)
                .add_modifier(Modifier::BOLD),
        )
    }))
    .height(1)
    .style(Style::default().bg(Color::Rgb(0, 60, 60)));

    // MAC(27%) Name(17%) Vendor(17%) dBm(10%) St(11%) Pkts(18%) = 100%
    let table_widths = [
        Constraint::Percentage(27),
        Constraint::Percentage(17),
        Constraint::Percentage(17),
        Constraint::Percentage(10),
        Constraint::Percentage(11),
        Constraint::Percentage(18),
    ];

    // Split inner to leave space for hint
    let panel_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let table = Table::new(rows, table_widths)
        .header(header)
        .column_spacing(1);

    frame.render_widget(table, panel_layout[0]);

    if is_active {
        let hint = Paragraph::new(Line::from(vec![
            Span::styled(" f ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("follow  "),
            Span::styled(" n ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("rename  "),
            Span::styled(" Tab ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("back"),
        ]));
        frame.render_widget(hint, panel_layout[1]);
    }

    frame.render_widget(block, area);
}

/// Log panel + attack controls
fn render_logs(frame: &mut Frame, app: &App, area: Rect) {
    let log_layout = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(60), Constraint::Percentage(40)])
        .split(area);

    let log_block = Block::default()
        .title(" Events ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));

    let log_inner = log_block.inner(log_layout[0]);
    let max_log_lines = (log_inner.height as usize).saturating_sub(1);

    let log_entries: Vec<Line> = app
        .log_messages
        .iter()
        .rev()
        .take(max_log_lines)
        .map(|msg| {
            let color = if msg.contains("Error") || msg.contains("error") || msg.contains("Failed")
            {
                Color::Red
            } else if msg.starts_with("✓") {
                Color::Green
            } else if msg.contains("start") || msg.contains("Start") {
                Color::Green
            } else if msg.contains("Target")
                || msg.contains("deauth")
                || msg.contains("Follow")
                || msg.contains("follow")
            {
                Color::Yellow
            } else {
                Color::Gray
            };
            Line::from(Span::styled(msg, Style::default().fg(color)))
        })
        .collect();

    frame.render_widget(Paragraph::new(Text::from(log_entries)), log_inner);
    frame.render_widget(log_block, log_layout[0]);

    // Attack controls (right)
    let ctrl_block = Block::default()
        .title(" Attack Controls ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));

    let ctrl_inner = ctrl_block.inner(log_layout[1]);

    let type_txt = format!("Type: {}", app.attack_type.label());

    let mode_txt = format!(
        "Mode: {}",
        if app.attack_mode == AttackMode::RoundRobin {
            "Round-Robin"
        } else {
            "Parallel"
        }
    );

    let burst_txt = format!("Burst: {}/target  {}ms", app.burst_size, app.send_interval_ms);

    let status_txt = if app.attack_running { "RUNNING" } else { "IDLE" };

    let scope_txt = match &app.deauth_scope {
        DeauthScope::Broadcast => "Scope: Broadcast".to_string(),
        DeauthScope::Client { client_mac } => {
            format!("Scope: Client {}", truncate_str(client_mac, 14))
        }
    };

    let follow_txt = match app.followed_clients.len() {
        0 => "Follow: off".to_string(),
        1 => format!("Follow: {}", truncate_str(&app.followed_clients[0].0, 14)),
        n => format!("Follow: {} clients", n),
    };

    let total_deauth: u64 = app.targets.iter().map(|t| t.deauth_count).sum();

    let ctrl_text = Text::from(vec![
        Line::from(Span::styled(
            type_txt,
            Style::default().fg(if app.attack_type == AttackType::AuthDos || app.attack_type == AttackType::BeaconFlood {
                Color::Magenta
            } else {
                Color::Cyan
            }),
        )),
        Line::from(Span::styled(mode_txt, Style::default().fg(Color::Cyan))),
        Line::from(Span::styled(burst_txt, Style::default().fg(Color::White))),
        Line::from(Span::styled(
            format!("Status: {}", status_txt),
            Style::default().fg(if app.attack_running {
                Color::Red
            } else {
                Color::Green
            }),
        )),
        Line::from(Span::styled(scope_txt, Style::default().fg(Color::Magenta))),
        Line::from(Span::styled(follow_txt, Style::default().fg(Color::Yellow))),
        Line::from(Span::styled(
            format!("Pursuit: {}", if app.pursuit_mode { "ON" } else { "off" }),
            Style::default().fg(if app.pursuit_mode { Color::Yellow } else { Color::DarkGray }),
        )),
        Line::from(format!(
            "Targets: {}  Deauth: {}",
            app.targets.len(),
            total_deauth
        )),
        Line::from(""),
        Line::from(Span::styled(
            "  A:type  M:mode  G:settings  S:start/stop",
            Style::default().fg(Color::DarkGray),
        )),
    ]);

    frame.render_widget(Paragraph::new(ctrl_text), ctrl_inner);
    frame.render_widget(ctrl_block, log_layout[1]);
}

/// Footer: keybindings (or input prompt when in text-entry mode)
fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    if app.input_mode != InputMode::Normal {
        let label = match app.input_mode {
            InputMode::SaveListName => "Save list name: ",
            InputMode::ClientRename => "Rename client:  ",
            InputMode::Normal => unreachable!(),
        };
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Cyan));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let line = Line::from(vec![
            Span::styled(label, Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::styled(app.input_buffer.clone(), Style::default().fg(Color::White)),
            Span::styled("█", Style::default().fg(Color::White)),
            Span::raw("   "),
            Span::styled(" Esc ", Style::default().fg(Color::DarkGray)),
            Span::raw("cancel"),
        ]);
        frame.render_widget(Paragraph::new(Text::from(line)), inner);
        return;
    }

    let mut spans = Vec::new();

    let add = |v: &mut Vec<Span>, key: &str, label: &str| {
        v.push(Span::styled(
            format!(" {} ", key),
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(ratatui::style::Modifier::BOLD),
        ));
        v.push(Span::raw(format!("{} ", label)));
    };

    match app.tab_selection {
        TabSelection::ApList => {
            add(&mut spans, "↑↓", "nav");
            add(&mut spans, "t", "target");
            add(&mut spans, "c", "clients");
            add(&mut spans, "f", "follow");
            add(&mut spans, "r", "clear scan");
        }
        TabSelection::TargetList => {
            add(&mut spans, "↑↓", "nav");
            add(&mut spans, "Space", "toggle");
            add(&mut spans, "d", "remove");
        }
        TabSelection::ClientList => {
            add(&mut spans, "↑↓", "select");
            add(&mut spans, "f", "follow");
            add(&mut spans, "n", "rename");
            add(&mut spans, "c/Esc", "back");
        }
    }

    add(&mut spans, "W", "save list");
    add(&mut spans, "L", "load list");
    add(&mut spans, "I", "ifaces");
    add(&mut spans, "G", "settings");
    add(&mut spans, "Tab", "switch");
    add(&mut spans, "A", "type");
    add(&mut spans, "M", "mode");
    add(&mut spans, "P", "pursuit");
    add(&mut spans, "S", "st/stop");
    add(&mut spans, "Q", "quit");

    let block = Block::default()
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::DarkGray));

    let inner = block.inner(area);
    frame.render_widget(
        Paragraph::new(Text::from(Line::from(spans))).style(Style::default()),
        inner,
    );
    frame.render_widget(block, area);
}

/// Centered popup overlay for loading saved lists
fn render_list_picker(frame: &mut Frame, app: &App, area: Rect) {
    let popup = centered_rect(50, 60, area);
    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(" Load Saved List ")
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    if app.list_picker_slots.is_empty() {
        frame.render_widget(
            Paragraph::new("  No saved lists found.")
                .style(Style::default().fg(Color::DarkGray)),
            inner,
        );
        return;
    }

    let layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let rows: Vec<Row> = app
        .list_picker_slots
        .iter()
        .enumerate()
        .map(|(i, name)| {
            let style = if i == app.list_picker_idx {
                Style::default()
                    .bg(Color::Rgb(40, 40, 80))
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default()
            };
            Row::new(vec![Cell::from(format!("  {}", name))]).style(style)
        })
        .collect();

    let table = Table::new(rows, [Constraint::Percentage(100)]);
    frame.render_widget(table, layout[0]);

    let hint = Paragraph::new(Line::from(vec![
        Span::styled(" ↑↓ ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("select  "),
        Span::styled(" Enter ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("load  "),
        Span::styled(" Esc ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
        Span::raw("cancel"),
    ]));
    frame.render_widget(hint, layout[1]);
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vert = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vert[1])[1]
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}…", &s[..max_len.saturating_sub(1)])
    }
}
