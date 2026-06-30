use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use ratatui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table},
    Frame, Terminal,
};

pub struct SettingsState {
    pub burst_size: u16,
    pub send_interval_ms: u64,
    pub band_2ghz: bool,
    pub band_5ghz: bool,
    pub band_6ghz: bool,
    pub cursor: usize,
}

impl SettingsState {
    pub fn new(burst_size: u16, send_interval_ms: u64, band_2ghz: bool, band_5ghz: bool, band_6ghz: bool) -> Self {
        Self { burst_size, send_interval_ms, band_2ghz, band_5ghz, band_6ghz, cursor: 0 }
    }
}

pub struct SettingsResult {
    pub burst_size: u16,
    pub send_interval_ms: u64,
    pub band_2ghz: bool,
    pub band_5ghz: bool,
    pub band_6ghz: bool,
}

pub fn run_settings_overlay<B: Backend>(
    terminal: &mut Terminal<B>,
    burst_size: u16,
    send_interval_ms: u64,
    band_2ghz: bool,
    band_5ghz: bool,
    band_6ghz: bool,
) -> Result<Option<SettingsResult>>
where
    B::Error: Send + Sync + 'static,
{
    let mut state = SettingsState::new(burst_size, send_interval_ms, band_2ghz, band_5ghz, band_6ghz);

    loop {
        terminal.draw(|f| render_settings(f, &state))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Up => {
                        if state.cursor > 0 {
                            state.cursor -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if state.cursor < 4 {
                            state.cursor += 1;
                        }
                    }
                    KeyCode::Left | KeyCode::Right if state.cursor >= 2 => {
                        match state.cursor {
                            2 => state.band_2ghz = !state.band_2ghz,
                            3 => state.band_5ghz = !state.band_5ghz,
                            4 => state.band_6ghz = !state.band_6ghz,
                            _ => {}
                        }
                    }
                    KeyCode::Left => {
                        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
                        match state.cursor {
                            0 => {
                                let step = if shift { 2000 } else { 200 };
                                state.burst_size = state.burst_size.saturating_sub(step).max(1);
                            }
                            1 => {
                                let step = if shift { 30000 } else { 10 };
                                state.send_interval_ms = state.send_interval_ms.saturating_sub(step).max(1);
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Right => {
                        let shift = key.modifiers.contains(KeyModifiers::SHIFT);
                        match state.cursor {
                            0 => {
                                let step = if shift { 2000 } else { 200 };
                                state.burst_size = state.burst_size.saturating_add(step).min(10000);
                            }
                            1 => {
                                let step = if shift { 30000 } else { 10 };
                                state.send_interval_ms = state.send_interval_ms.saturating_add(step).min(900_000);
                            }
                            _ => {}
                        }
                    }
                    KeyCode::Enter => {
                        return Ok(Some(SettingsResult {
                            burst_size: state.burst_size,
                            send_interval_ms: state.send_interval_ms,
                            band_2ghz: state.band_2ghz,
                            band_5ghz: state.band_5ghz,
                            band_6ghz: state.band_6ghz,
                        }));
                    }
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(None),
                    _ => {}
                }
            }
        }
    }
}

fn render_settings(frame: &mut Frame, state: &SettingsState) {
    let area = frame.area();
    let popup = centered_rect(52, 11, area);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Line::from(" smartdos — Settings "))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let mut rows: Vec<Row> = Vec::new();

    // Row 0: Burst Size
    {
        let is_sel = state.cursor == 0;
        let label_style = sel_style(is_sel, Color::White);
        let value_style = sel_style(is_sel, Color::Gray);
        let arrow = if is_sel { "◄ ►" } else { "   " };
        rows.push(Row::new(vec![
            Cell::from(Span::styled(format!("{}Burst Size", if is_sel { "▶ " } else { "  " }), label_style)),
            Cell::from(Span::styled(format!("{:>6}", state.burst_size), value_style)),
            Cell::from(Span::styled("frames/target  (1–10000, ⇧ big step)", Style::default().fg(Color::DarkGray))),
            Cell::from(Span::styled(arrow, Style::default().fg(Color::Cyan))),
        ]));
    }

    // Row 1: Send Interval
    {
        let is_sel = state.cursor == 1;
        let label_style = sel_style(is_sel, Color::White);
        let value_style = sel_style(is_sel, Color::Gray);
        let arrow = if is_sel { "◄ ►" } else { "   " };
        rows.push(Row::new(vec![
            Cell::from(Span::styled(format!("{}Send Interval", if is_sel { "▶ " } else { "  " }), label_style)),
            Cell::from(Span::styled(format!("{:>6}", fmt_duration(state.send_interval_ms)), value_style)),
            Cell::from(Span::styled("(1ms–15m, ⇧ big step)", Style::default().fg(Color::DarkGray))),
            Cell::from(Span::styled(arrow, Style::default().fg(Color::Cyan))),
        ]));
    }

    // Rows 2–4: band toggles
    let bands: [(usize, &str, bool); 3] = [
        (2, "2.4 GHz band", state.band_2ghz),
        (3, "5 GHz band",   state.band_5ghz),
        (4, "6 GHz band",   state.band_6ghz),
    ];
    for (idx, label, enabled) in bands {
        let is_sel = state.cursor == idx;
        let label_style = sel_style(is_sel, Color::White);
        let (toggle_text, toggle_color) = if enabled {
            (" ON ", Color::Green)
        } else {
            ("OFF ", Color::Red)
        };
        rows.push(Row::new(vec![
            Cell::from(Span::styled(format!("{}{}", if is_sel { "▶ " } else { "  " }, label), label_style)),
            Cell::from(Span::styled(format!("{:>5}", ""), Style::default())),
            Cell::from(Span::styled("◄► to toggle", Style::default().fg(Color::DarkGray))),
            Cell::from(Span::styled(toggle_text, Style::default().fg(toggle_color).add_modifier(Modifier::BOLD))),
        ]));
    }

    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(7),
            Constraint::Min(22),
            Constraint::Length(4),
        ],
    );

    frame.render_widget(table, chunks[0]);

    let hint = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::default().fg(Color::Cyan)),
        Span::raw(" field  "),
        Span::styled("◄►", Style::default().fg(Color::Cyan)),
        Span::raw(" adjust  "),
        Span::styled("◄►", Style::default().fg(Color::Cyan)),
        Span::raw(" toggle  "),
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" save  "),
        Span::styled("Esc", Style::default().fg(Color::Red)),
        Span::raw(" cancel"),
    ]))
    .alignment(Alignment::Center);
    frame.render_widget(hint, chunks[1]);
}

/// Human-friendly duration: ms under 1s, else s / m+s.
fn fmt_duration(ms: u64) -> String {
    if ms < 1000 {
        format!("{}ms", ms)
    } else if ms < 60_000 {
        if ms % 1000 == 0 {
            format!("{}s", ms / 1000)
        } else {
            format!("{:.1}s", ms as f64 / 1000.0)
        }
    } else {
        let mins = ms / 60_000;
        let secs = (ms % 60_000) / 1000;
        if secs == 0 {
            format!("{}m", mins)
        } else {
            format!("{}m{}s", mins, secs)
        }
    }
}

fn sel_style(is_sel: bool, base: Color) -> Style {
    if is_sel {
        Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(base)
    }
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect {
        x,
        y,
        width: width.min(area.width),
        height: height.min(area.height),
    }
}
