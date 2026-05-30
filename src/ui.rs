use ratatui::{
    layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span, Text},
    widgets::{
        Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Scrollbar,
        ScrollbarOrientation, ScrollbarState, Table,
    },
    Frame,
};

use crate::oui;
use crate::types::{App, AttackMode, AttackType, Band, DeauthScope, InputMode, PageView, TabSelection, TargetSubSection};

pub fn render(frame: &mut Frame, app: &mut App) {
    let area = frame.area();

    match app.page_view {
        PageView::Dashboard => {
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
        }
        PageView::Events => {
            let layout = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(3),
                    Constraint::Min(1),
                    Constraint::Length(3),
                ])
                .split(area);

            render_top_bar(frame, app, layout[0]);
            render_events_fullscreen(frame, app, layout[1]);
            render_footer(frame, app, layout[2]);
        }
    }

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
    let tx_str = match app.txpower_dbm {
        Some(dbm) => format!(" TX:{}dBm", dbm),
        None => " TX:auto".to_string(),
    };
    let focus_str = if app.channel_focused { " [FOCUS]" } else { "" };
    let ch_info = format!(" ch:{}/{}{}{tx_str}] ", app.current_channel, app.current_band.label(), focus_str);

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

    let cpu_str = format!(" CPU:{:.0}% ", app.cpu_usage);
    let cpu_color = if app.cpu_usage >= 90.0 {
        Color::Red
    } else if app.cpu_usage >= 70.0 {
        Color::Yellow
    } else {
        Color::Gray
    };

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
    let cpu = Span::styled(cpu_str, Style::default().fg(cpu_color));
    let sep = Span::raw("  │  ");

    let text = Text::from(Line::from(vec![left, sep.clone(), center, sep.clone(), right, sep, cpu]));
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

    let filter_title = if !app.ap_filter.is_empty() {
        format!(" Access Points [/{}] ", app.ap_filter)
    } else if app.input_mode == crate::types::InputMode::ApFilter {
        " Access Points [/] ".to_string()
    } else {
        " Access Points ".to_string()
    };

    let block = Block::default()
        .title(filter_title)
        .title_alignment(Alignment::Left)
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style);

    let inner = block.inner(area);
    let visible_height = (inner.height as usize).saturating_sub(2);
    let scroll_offset = app.scroll_offset;

    // Apply SSID/BSSID filter
    let visible_indices = app.visible_ap_indices();

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

    // Scroll offset maps into the filtered list, not the full ap_list
    let rows: Vec<Row> = visible_indices
        .iter()
        .skip(scroll_offset)
        .take(visible_height)
        .map(|&global_idx| {
            let ap = &app.ap_list[global_idx];
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

/// Target list panel (right, shown in TargetList tab) — split: clients top, APs bottom
fn render_targets_panel(frame: &mut Frame, app: &App, area: Rect) {
    let is_active = app.tab_selection == TabSelection::TargetList;
    let border_style = if is_active {
        Style::default().fg(Color::Yellow)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    let client_targets: Vec<_> = app.targets.iter().enumerate()
        .filter(|(_, t)| !t.client_filter.is_empty())
        .collect();
    let ap_targets: Vec<_> = app.targets.iter().enumerate().collect();

    let outer_block = Block::default()
        .title(format!(" Targets ({}) ", app.targets.len()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(border_style);

    let outer_inner = outer_block.inner(area);

    if app.targets.is_empty() {
        let empty_text = Paragraph::new(Text::from(vec![
            Line::from(""),
            Line::from("  No targets added."),
            Line::from("  't' to add selected AP"),
            Line::from("  'c' to view AP clients"),
            Line::from("  'c' → clients → 't' to target"),
        ]))
        .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(empty_text, outer_inner);
        frame.render_widget(outer_block, area);
        return;
    }

    frame.render_widget(outer_block, area);

    let client_rows_needed = (client_targets.len() + 2).max(3) as u16; // header + rows + min
    let ap_rows_needed = (ap_targets.len() + 2).max(3) as u16;
    let split = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Min(client_rows_needed.min(outer_inner.height / 2)),
            Constraint::Min(ap_rows_needed.min(outer_inner.height / 2)),
        ])
        .split(outer_inner);

    // ── Client targets (top) ──────────────────────────────────────────────
    let client_focused = is_active && app.target_sub_section == TargetSubSection::Clients;
    let client_block = Block::default()
        .title(format!(" Clients ({}) ", client_targets.len()))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(if client_focused { Color::Yellow } else { Color::Cyan }));
    let client_inner = client_block.inner(split[0]);
    frame.render_widget(client_block, split[0]);

    let client_col_widths = [
        Constraint::Percentage(28),
        Constraint::Percentage(20),
        Constraint::Percentage(12),
        Constraint::Percentage(20),
        Constraint::Percentage(20),
    ];
    let client_header = Row::new(["Client MAC", "AP BSSID", "Status", "Sent", "Disc"].iter().map(|h| {
        Cell::from(*h).style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
    }))
    .height(1)
    .style(Style::default().bg(Color::Rgb(0, 60, 80)));

    let client_rows: Vec<Row> = client_targets.iter()
        .map(|(global_idx, target)| {
            let is_selected = is_active && app.selected_target_idx == Some(*global_idx);
            let status = if target.active { "ACTIVE" } else { "OFF" };
            let row_style = if is_selected {
                Style::default().bg(Color::Rgb(30, 50, 70)).add_modifier(Modifier::BOLD)
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
            let client_label = if target.client_filter.len() == 1 {
                truncate_str(&target.client_filter[0], 17)
            } else {
                format!("{} macs", target.client_filter.len())
            };
            Row::new(vec![
                Cell::from(Span::styled(client_label, Style::default().fg(Color::Cyan))),
                Cell::from(truncate_str(&target.bssid, 17)),
                Cell::from(Span::styled(
                    status,
                    Style::default().fg(if target.active { Color::Red } else { Color::DarkGray }),
                )),
                Cell::from(format!("{:>5}", target.deauth_count)),
                disc_cell,
            ])
            .style(row_style)
            .height(1)
        })
        .collect();

    if client_rows.is_empty() {
        let hint = Paragraph::new("  No client targets  ('c' → clients → 't')")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint, client_inner);
    } else {
        let sel_pos = app.selected_target_idx
            .and_then(|g| client_targets.iter().position(|(gi, _)| *gi == g));
        render_scrollable_table(
            frame, split[0], client_inner, client_header, &client_col_widths, client_rows, sel_pos,
        );
    }

    // ── AP targets (bottom) ───────────────────────────────────────────────
    let ap_focused = is_active && app.target_sub_section == TargetSubSection::Aps;
    let ap_block = Block::default()
        .title(format!(" APs ({}) ", ap_targets.len()))
        .borders(Borders::ALL)
        .border_type(BorderType::Plain)
        .border_style(Style::default().fg(if ap_focused { Color::Yellow } else { Color::Red }));
    let ap_inner = ap_block.inner(split[1]);
    frame.render_widget(ap_block, split[1]);

    let ap_col_widths = [
        Constraint::Percentage(18),
        Constraint::Percentage(22),
        Constraint::Percentage(5),
        Constraint::Percentage(12),
        Constraint::Percentage(13),
        Constraint::Percentage(13),
        Constraint::Percentage(17),
    ];
    let ap_header = Row::new(["SSID", "BSSID", "CH", "Status", "Sent", "Disc", "Via"].iter().map(|h| {
        Cell::from(*h).style(Style::default().fg(Color::White).add_modifier(Modifier::BOLD))
    }))
    .height(1)
    .style(Style::default().bg(Color::Rgb(80, 0, 0)));

    let ap_rows: Vec<Row> = ap_targets.iter()
        .map(|(global_idx, target)| {
            let is_selected = is_active && app.selected_target_idx == Some(*global_idx);
            let status = if target.active { " ACTIVE " } else { "OFF" };
            let row_style = if is_selected {
                Style::default().bg(Color::Rgb(50, 30, 30)).add_modifier(Modifier::BOLD)
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
            let via_cell = if target.client_filter.is_empty() {
                Cell::from(Span::styled("DIRECT", Style::default().fg(Color::Red)))
            } else {
                Cell::from(Span::styled("CLIENT", Style::default().fg(Color::Cyan)))
            };
            Row::new(vec![
                Cell::from(truncate_str(&target.ssid, 12)),
                Cell::from(truncate_str(&target.bssid, 17)),
                Cell::from(format!("{:>2}", target.channel)),
                Cell::from(Span::styled(
                    status,
                    Style::default().fg(if target.active { Color::Red } else { Color::DarkGray }),
                )),
                Cell::from(format!("{:>5}", target.deauth_count)),
                disc_cell,
                via_cell,
            ])
            .style(row_style)
            .height(1)
        })
        .collect();

    if ap_rows.is_empty() {
        let hint = Paragraph::new("  No AP targets  ('t' to add)")
            .style(Style::default().fg(Color::DarkGray));
        frame.render_widget(hint, ap_inner);
    } else {
        let sel_pos = app.selected_target_idx
            .and_then(|g| ap_targets.iter().position(|(gi, _)| *gi == g));
        render_scrollable_table(
            frame, split[1], ap_inner, ap_header, &ap_col_widths, ap_rows, sel_pos,
        );
    }
}

/// First row to display so that `selected_pos` stays within a `viewport`-row
/// window. Returns 0 when nothing is selected or the selection already fits.
fn scroll_offset(selected_pos: Option<usize>, viewport: usize) -> usize {
    match selected_pos {
        Some(p) if viewport > 0 && p >= viewport => p + 1 - viewport,
        _ => 0,
    }
}

/// Render a table that scrolls to keep the selected row visible, drawing a
/// vertical scrollbar on the block's right border when the content overflows.
/// `outer` is the bordered block area; `inner` is its content area.
fn render_scrollable_table<'a>(
    frame: &mut Frame,
    outer: Rect,
    inner: Rect,
    header: Row<'a>,
    widths: &[Constraint],
    rows: Vec<Row<'a>>,
    selected_pos: Option<usize>,
) {
    let total = rows.len();
    let viewport = (inner.height as usize).saturating_sub(1); // header consumes one row
    let offset = scroll_offset(selected_pos, viewport);
    let visible: Vec<Row> = rows.into_iter().skip(offset).take(viewport.max(1)).collect();
    let table = Table::new(visible, widths.to_vec())
        .header(header)
        .column_spacing(1);
    frame.render_widget(table, inner);

    if total > viewport && viewport > 0 {
        let mut state = ScrollbarState::new(total).position(offset);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some("│"))
            .thumb_symbol("█");
        let sb_area = outer.inner(Margin { vertical: 1, horizontal: 0 });
        frame.render_stateful_widget(scrollbar, sb_area, &mut state);
    }
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
            Line::from("  't' target  Tab back"),
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
            Span::styled(" t ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
            Span::raw("target  "),
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
        .map(|msg| Line::from(Span::styled(msg, Style::default().fg(event_color(msg)))))
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

/// Map an event-log message to its display color. Shared by the dashboard log
/// panel and the full-screen Events page.
fn event_color(msg: &str) -> Color {
    if msg.contains("Error") || msg.contains("error") || msg.contains("Failed") {
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
    }
}

/// Full-screen Events page: the whole body is one scrollable event log, newest
/// at the bottom (tail-style). `events_scroll` counts lines up from the newest.
fn render_events_fullscreen(frame: &mut Frame, app: &mut App, area: Rect) {
    let block = Block::default()
        .title(format!(" Events ({}) ", app.log_messages.len()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let total = app.log_messages.len();
    let viewport = inner.height as usize;
    if total == 0 || viewport == 0 {
        return;
    }

    // Clamp the scroll so the window never runs past the start of history.
    app.events_scroll = app.events_scroll.min(total.saturating_sub(viewport));
    let end = total.saturating_sub(app.events_scroll);
    let start = end.saturating_sub(viewport);

    let lines: Vec<Line> = app.log_messages[start..end]
        .iter()
        .map(|msg| Line::from(Span::styled(msg.as_str(), Style::default().fg(event_color(msg)))))
        .collect();
    frame.render_widget(Paragraph::new(Text::from(lines)), inner);

    if total > viewport {
        // Scrollbar position is the window's TOP index (`start`), not the
        // bottom-counted `events_scroll`, which would invert the thumb.
        let mut state = ScrollbarState::new(total).position(start);
        let scrollbar = Scrollbar::new(ScrollbarOrientation::VerticalRight)
            .begin_symbol(None)
            .end_symbol(None)
            .track_symbol(Some("│"))
            .thumb_symbol("█");
        let sb_area = area.inner(Margin { vertical: 1, horizontal: 0 });
        frame.render_stateful_widget(scrollbar, sb_area, &mut state);
    }
}

/// Footer: keybindings (or input prompt when in text-entry mode)
fn render_footer(frame: &mut Frame, app: &App, area: Rect) {
    if app.input_mode == InputMode::ApFilter {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(BorderType::Rounded)
            .border_style(Style::default().fg(Color::Yellow));
        let inner = block.inner(area);
        frame.render_widget(block, area);
        let line = Line::from(vec![
            Span::styled(" Filter: ", Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
            Span::styled(app.ap_filter.clone(), Style::default().fg(Color::White)),
            Span::styled("█", Style::default().fg(Color::Yellow)),
            Span::raw("   "),
            Span::styled(" Enter ", Style::default().fg(Color::DarkGray)),
            Span::raw("keep  "),
            Span::styled(" Esc ", Style::default().fg(Color::DarkGray)),
            Span::raw("clear"),
        ]);
        frame.render_widget(Paragraph::new(Text::from(line)), inner);
        return;
    }

    if app.input_mode != InputMode::Normal {
        let label = match app.input_mode {
            InputMode::SaveListName => "Save list name: ",
            InputMode::ClientRename => "Rename client:  ",
            InputMode::Normal | InputMode::ApFilter => unreachable!(),
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

    // Full-screen Events page has its own (scroll-oriented) keybinding hints.
    if app.page_view == PageView::Events {
        add(&mut spans, "↑↓", "scroll");
        add(&mut spans, "PgUp/PgDn", "page");
        add(&mut spans, "Home/End", "ends");
        add(&mut spans, "Tab/Esc", "back");
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
        return;
    }

    match app.tab_selection {
        TabSelection::ApList => {
            add(&mut spans, "↑↓", "nav");
            add(&mut spans, "t", "target");
            add(&mut spans, "c", "clients+focus");
            add(&mut spans, "/", "filter");
            add(&mut spans, "r", "clear scan");
        }
        TabSelection::TargetList => {
            add(&mut spans, "↑↓", "nav");
            add(&mut spans, "←→", "switch section");
            add(&mut spans, "Space", "toggle");
            add(&mut spans, "d", "remove");
        }
        TabSelection::ClientList => {
            add(&mut spans, "↑↓", "select");
            add(&mut spans, "t", "target");
            add(&mut spans, "n", "rename");
            add(&mut spans, "c/Esc", "back+unfocus");
        }
    }

    add(&mut spans, "W", "save list");
    add(&mut spans, "L", "load list");
    add(&mut spans, "I", "ifaces");
    add(&mut spans, "G", "settings");
    add(&mut spans, "Tab", "events");
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
        .title(" Load Saved List — Esc to start fresh ")
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
    if s.chars().count() <= max_len {
        s.to_string()
    } else {
        let kept: String = s.chars().take(max_len.saturating_sub(1)).collect();
        format!("{}…", kept)
    }
}

#[cfg(test)]
mod tests {
    use super::scroll_offset;
    use super::truncate_str;

    #[test]
    fn truncate_str_short_string_unchanged() {
        assert_eq!(truncate_str("CleanAP", 14), "CleanAP");
        assert_eq!(truncate_str("", 14), "");
    }

    #[test]
    fn truncate_str_truncates_by_char_count_with_ellipsis() {
        assert_eq!(truncate_str("abcdef", 4), "abc…");
        // exactly max_len chars → unchanged
        assert_eq!(truncate_str("abcd", 4), "abcd");
    }

    #[test]
    fn truncate_str_multibyte_does_not_panic() {
        // Regression: the old byte-slice impl panicked here ("byte index N is
        // not a char boundary"). Multibyte SSIDs must truncate by char, safely.
        let s = "日本語ネットワーク"; // 8 chars, 24 bytes
        let out = truncate_str(s, 4);
        assert_eq!(out, "日本語…");
        // emoji are multi-byte too
        assert_eq!(truncate_str("📶📶📶📶📶", 3), "📶📶…");
    }

    #[test]
    fn scroll_offset_no_scroll_when_selection_fits() {
        assert_eq!(scroll_offset(Some(0), 4), 0);
        assert_eq!(scroll_offset(Some(3), 4), 0); // last row still in window
        assert_eq!(scroll_offset(None, 4), 0); // nothing selected → top
    }

    #[test]
    fn scroll_offset_pins_selection_to_bottom_row() {
        assert_eq!(scroll_offset(Some(4), 4), 1); // first row that overflows
        assert_eq!(scroll_offset(Some(9), 4), 6); // skip 6 → window 6..10 shows 9
    }

    #[test]
    fn scroll_offset_zero_viewport_never_underflows() {
        assert_eq!(scroll_offset(Some(5), 0), 0);
    }
}
