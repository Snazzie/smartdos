use anyhow::Result;
use crossterm::event::{self, Event, KeyCode};
use ratatui::{
    backend::Backend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::Line,
    widgets::{Block, BorderType, Borders, Cell, Clear, Paragraph, Row, Table},
    Frame, Terminal,
};

use crate::types::WirelessInterface;

pub struct SetupState {
    pub interfaces: Vec<WirelessInterface>,
    pub listen_idx: Option<usize>,
    pub attack_idx: Option<usize>,
    pub cursor: usize,
    pub txpower_dbm: Option<i32>,
}

impl SetupState {
    pub fn new(interfaces: Vec<WirelessInterface>) -> Self {
        Self {
            interfaces,
            listen_idx: None,
            attack_idx: None,
            cursor: 0,
            txpower_dbm: None,
        }
    }

    fn can_confirm(&self) -> bool {
        self.listen_idx.is_some() && self.attack_idx.is_some()
    }
}

/// Startup: run interactive interface selection. Exits process on q/Esc.
/// If only one interface, returns it for both roles without rendering.
pub fn run_setup<B: Backend>(
    terminal: &mut Terminal<B>,
    interfaces: Vec<WirelessInterface>,
) -> Result<(String, String, Option<i32>)>
where
    B::Error: Send + Sync + 'static,
{
    if interfaces.len() == 1 {
        return Ok((interfaces[0].name.clone(), interfaces[0].name.clone(), None));
    }
    match run_setup_overlay(terminal, interfaces)? {
        Some(triple) => Ok(triple),
        None => std::process::exit(0),
    }
}

/// Mid-session: run setup overlay, return None if cancelled (Esc).
pub fn run_setup_overlay<B: Backend>(
    terminal: &mut Terminal<B>,
    interfaces: Vec<WirelessInterface>,
) -> Result<Option<(String, String, Option<i32>)>>
where
    B::Error: Send + Sync + 'static,
{
    if interfaces.is_empty() {
        return Ok(None);
    }

    let mut state = SetupState::new(interfaces);

    loop {
        terminal.draw(|f| render_setup(f, &state))?;

        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match key.code {
                    KeyCode::Up => {
                        if state.cursor > 0 {
                            state.cursor -= 1;
                        }
                    }
                    KeyCode::Down => {
                        if state.cursor + 1 < state.interfaces.len() {
                            state.cursor += 1;
                        }
                    }
                    KeyCode::Char('l') | KeyCode::Char('L') => {
                        if state.listen_idx == Some(state.cursor) {
                            state.listen_idx = None;
                        } else {
                            state.listen_idx = Some(state.cursor);
                        }
                    }
                    KeyCode::Char('a') | KeyCode::Char('A') => {
                        if state.attack_idx == Some(state.cursor) {
                            state.attack_idx = None;
                        } else {
                            state.attack_idx = Some(state.cursor);
                        }
                    }
                    KeyCode::Char('+') | KeyCode::Char('=') => {
                        let cur = state.txpower_dbm.unwrap_or(0);
                        state.txpower_dbm = Some((cur + 1).min(30));
                    }
                    KeyCode::Char('-') => {
                        match state.txpower_dbm {
                            None => {}
                            Some(v) if v <= 1 => state.txpower_dbm = None,
                            Some(v) => state.txpower_dbm = Some(v - 1),
                        }
                    }
                    KeyCode::Enter => {
                        if state.can_confirm() {
                            let listen =
                                state.interfaces[state.listen_idx.unwrap()].name.clone();
                            let attack =
                                state.interfaces[state.attack_idx.unwrap()].name.clone();
                            return Ok(Some((listen, attack, state.txpower_dbm)));
                        }
                    }
                    KeyCode::Char('q') | KeyCode::Esc => return Ok(None),
                    _ => {}
                }
            }
        }
    }
}

fn render_setup(frame: &mut Frame, state: &SetupState) {
    let area = frame.area();

    let n = state.interfaces.len() as u16;
    // border(2) + header row(1) + separator(1) + rows(n) + txpower(1) + hint(1) + padding(1)
    let height = 7 + n;
    let width = 58u16;
    let popup = centered_rect(width, height, area);

    frame.render_widget(Clear, popup);

    let block = Block::default()
        .title(Line::from(" smartdos — Interface Setup "))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(Color::Cyan));

    let inner = block.inner(popup);
    frame.render_widget(block, popup);

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(1), Constraint::Length(1)])
        .split(inner);

    let rows: Vec<Row> = state
        .interfaces
        .iter()
        .enumerate()
        .map(|(i, iface)| {
            let (role_str, role_style) = match (state.listen_idx, state.attack_idx) {
                (Some(l), Some(a)) if l == i && a == i => (
                    "[LISTEN+ATTACK]",
                    Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
                ),
                (Some(l), _) if l == i => (
                    "[LISTEN]",
                    Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
                ),
                (_, Some(a)) if a == i => (
                    "[ATTACK]",
                    Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                ),
                _ => ("—", Style::default().fg(Color::DarkGray)),
            };

            let row_bg = if i == state.cursor {
                Style::default().bg(Color::DarkGray)
            } else {
                Style::default()
            };

            Row::new(vec![
                Cell::from(iface.name.as_str())
                    .style(Style::default().fg(Color::White)),
                Cell::from(iface.phy.as_str())
                    .style(Style::default().fg(Color::Gray)),
                Cell::from(role_str).style(role_style),
            ])
            .style(row_bg)
        })
        .collect();

    let header = Row::new(vec!["Name", "PHY", "Role"]).style(
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD),
    );

    let table = Table::new(
        rows,
        [
            Constraint::Length(18),
            Constraint::Length(8),
            Constraint::Min(10),
        ],
    )
    .header(header);

    frame.render_widget(table, chunks[0]);

    let tx_str = match state.txpower_dbm {
        Some(dbm) => format!("TX Power: {}dBm", dbm),
        None => "TX Power: auto".to_string(),
    };
    frame.render_widget(
        Paragraph::new(format!("  {}   [+ / -]", tx_str))
            .style(Style::default().fg(Color::Yellow))
            .alignment(Alignment::Left),
        chunks[1],
    );

    let can_confirm = state.can_confirm();
    let hint = if can_confirm {
        "↑↓ Move  L=Listen  A=Attack  +/-=TXpwr  Enter=Confirm  q=Quit"
    } else {
        "↑↓ Move  L=Listen  A=Attack  +/-=TXpwr  (assign both roles to confirm)"
    };
    let hint_style = if can_confirm {
        Style::default().fg(Color::Green)
    } else {
        Style::default().fg(Color::DarkGray)
    };

    frame.render_widget(
        Paragraph::new(hint)
            .style(hint_style)
            .alignment(Alignment::Center),
        chunks[2],
    );
}

fn centered_rect(width: u16, height: u16, area: Rect) -> Rect {
    let x = area.x + area.width.saturating_sub(width) / 2;
    let y = area.y + area.height.saturating_sub(height) / 2;
    Rect::new(x, y, width.min(area.width), height.min(area.height))
}
