use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
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
    pub cursor: usize,
}

impl SettingsState {
    pub fn new(burst_size: u16, send_interval_ms: u64) -> Self {
        Self { burst_size, send_interval_ms, cursor: 0 }
    }
}

pub fn run_settings_overlay<B: Backend>(
    terminal: &mut Terminal<B>,
    burst_size: u16,
    send_interval_ms: u64,
) -> Result<Option<(u16, u64)>> {
    let mut state = SettingsState::new(burst_size, send_interval_ms);

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
                        if state.cursor < 1 {
                            state.cursor += 1;
                        }
                    }
                    KeyCode::Left => match state.cursor {
                        0 => {
                            state.burst_size = state.burst_size.saturating_sub(200).max(200);
                        }
                        _ => {
                            if state.send_interval_ms > 10 {
                                state.send_interval_ms -= 10;
                            }
                        }
                    },
                    KeyCode::Right => match state.cursor {
                        0 => {
                            state.burst_size = state.burst_size.saturating_add(200).min(10000);
                        }
                        _ => {
                            if state.send_interval_ms < 2000 {
                                state.send_interval_ms += 10;
                            }
                        }
                    },
                    KeyCode::Enter => {
                        return Ok(Some((state.burst_size, state.send_interval_ms)));
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
    let popup = centered_rect(46, 8, area);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Line::from(" smartdos — Attack Settings "))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Yellow));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1)])
        .split(inner);

    let fields: [(& str, String, &str, usize); 2] = [
        ("Burst Size", format!("{}", state.burst_size), "frames/target  (200–10000, step 200)", 0),
        ("Send Interval", format!("{}", state.send_interval_ms), "ms  (10–2000)", 1),
    ];

    let rows: Vec<Row> = fields.iter().map(|(label, value, unit, idx)| {
        let is_sel = state.cursor == *idx;
        let label_style = if is_sel {
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::White)
        };
        let value_style = if is_sel {
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        let arrow = if is_sel { "◄ ►" } else { "   " };
        Row::new(vec![
            Cell::from(Span::styled(format!("{}{}", if is_sel { "▶ " } else { "  " }, label), label_style)),
            Cell::from(Span::styled(format!("{:>5}", value), value_style)),
            Cell::from(Span::styled(unit.to_string(), Style::default().fg(Color::DarkGray))),
            Cell::from(Span::styled(arrow, Style::default().fg(Color::Cyan))),
        ])
    }).collect();

    let table = Table::new(
        rows,
        [
            Constraint::Length(16),
            Constraint::Length(6),
            Constraint::Min(16),
            Constraint::Length(3),
        ],
    );

    frame.render_widget(table, chunks[0]);

    let hint = Paragraph::new(Line::from(vec![
        Span::styled("↑↓", Style::default().fg(Color::Cyan)),
        Span::raw(" field  "),
        Span::styled("◄►", Style::default().fg(Color::Cyan)),
        Span::raw(" adjust  "),
        Span::styled("Enter", Style::default().fg(Color::Green)),
        Span::raw(" confirm  "),
        Span::styled("Esc", Style::default().fg(Color::Red)),
        Span::raw(" cancel"),
    ]))
    .alignment(Alignment::Center);
    frame.render_widget(hint, chunks[1]);
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
