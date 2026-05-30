use std::collections::HashMap;
use std::fs::File;
use std::io::Write;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;
use std::sync::Arc;
use std::time::Instant;
use sysinfo::System;

/// Channel hopping config
pub const CHANNELS_2GHZ: &[u8] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11];
/// 5 GHz non-DFS channels only (UNII-1 + UNII-3).
/// DFS channels 52-144 require radar detection (CAC) and block iw indefinitely.
pub const CHANNELS_5GHZ: &[u8] = &[36, 40, 44, 48, 149, 153, 157, 161, 165];
/// 6 GHz: every 4th channel (all 20 MHz primaries, 1–233)
pub const CHANNELS_6GHZ: &[u8] = &[
    1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77,
    81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125, 129, 133, 137, 141, 145,
    149, 153, 157, 161, 165, 169, 173, 177, 181, 185, 189, 193, 197, 201, 205, 209,
    213, 217, 221, 225, 229, 233,
];
pub const CHANNEL_HOP_MS: u64 = 250;

/// Wi-Fi band
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum Band {
    TwoGHz,
    FiveGHz,
    SixGHz,
}

impl Band {
    pub fn label(self) -> &'static str {
        match self {
            Band::TwoGHz => "2G",
            Band::FiveGHz => "5G",
            Band::SixGHz => "6G",
        }
    }
}

/// Returns frequency in MHz for a channel on a given band.
pub fn channel_to_freq_mhz(channel: u8, band: Band) -> u32 {
    match band {
        Band::TwoGHz => 2407 + channel as u32 * 5,
        Band::FiveGHz => 5000 + channel as u32 * 5,
        Band::SixGHz  => 5950 + channel as u32 * 5,
    }
}

/// Infer band from radiotap-reported frequency.
pub fn freq_to_band(freq_mhz: u32) -> Band {
    match freq_mhz {
        2412..=2484 => Band::TwoGHz,
        5180..=5825 => Band::FiveGHz,
        5925..=7125 => Band::SixGHz,
        _ => Band::TwoGHz,
    }
}

/// Build the full scan channel list filtered to bands the interface supports.
pub fn scan_channels_for(supports_5ghz: bool, supports_6ghz: bool) -> Vec<(u8, Band)> {
    let mut v = Vec::new();
    for &ch in CHANNELS_2GHZ { v.push((ch, Band::TwoGHz)); }
    if supports_5ghz {
        for &ch in CHANNELS_5GHZ { v.push((ch, Band::FiveGHz)); }
    }
    if supports_6ghz {
        for &ch in CHANNELS_6GHZ { v.push((ch, Band::SixGHz)); }
    }
    v
}

/// A client/station detected via management frames
#[derive(Debug, Clone)]
pub struct Client {
    pub mac: String,
    pub signal_dbm: i16,
    pub packets: u64,
    pub last_seen: Instant,
    pub associated: bool,
    pub friendly_name: Option<String>,
}

/// A single Access Point discovered via beacon frame capture
#[derive(Debug, Clone)]
pub struct AccessPoint {
    pub bssid: String,
    pub ssid: String,
    pub band: Band,
    pub channel: u8,
    pub signal_dbm: i16,
    pub signal_percent: u8,
    pub packets: u64,
    pub last_seen: Instant,
    pub encryption: String,
    pub clients: Vec<Client>,
    pub traffic_rate: f64, // beacons/sec rolling average
}

/// A target for deauth attack
#[derive(Debug, Clone)]
pub struct Target {
    pub bssid: String,
    pub ssid: String,
    pub band: Band,
    pub channel: u8,
    pub active: bool,
    pub deauth_count: u64,
    pub disconnect_count: u64,
    pub client_filter: Vec<String>,
    pub follow_managed: bool,
}

/// Deauth scope: broadcast all clients, or target a specific client
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum DeauthScope {
    Broadcast,
    Client { client_mac: String },
}

/// Attack orchestration mode
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AttackMode {
    RoundRobin,
    Parallel,
}

impl AttackMode {
    pub fn toggle(&self) -> Self {
        match self {
            AttackMode::RoundRobin => AttackMode::Parallel,
            AttackMode::Parallel => AttackMode::RoundRobin,
        }
    }
}

/// Attack type: deauth frames, auth-flood DoS, or beacon flood
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum AttackType {
    Deauth,
    AuthDos,
    BeaconFlood,
}

impl AttackType {
    pub fn toggle(&self) -> Self {
        match self {
            AttackType::Deauth => AttackType::AuthDos,
            AttackType::AuthDos => AttackType::BeaconFlood,
            AttackType::BeaconFlood => AttackType::Deauth,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            AttackType::Deauth => "Deauth",
            AttackType::AuthDos => "AuthDos",
            AttackType::BeaconFlood => "BeaconFlood",
        }
    }
}

/// TUI text input mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum InputMode {
    Normal,
    SaveListName,
    ClientRename,
}

/// Application UI state
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AppState {
    Scanning,
    Attacking,
}

/// Which whole-page view is shown: the normal dashboard or full-screen Events
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum PageView {
    Dashboard,
    Events,
}

/// Commands from the scanner thread to the main thread
#[derive(Debug, Clone)]
pub enum ScannerEvent {
    ApDiscovered(AccessPoint),
    ApUpdated(AccessPoint),
    ApGone(String), // BSSID
    ClientDiscovered { ap_bssid: String, client: Client },
    ClientUpdated { ap_bssid: String, client: Client },
    Error(String),
    Traffic(u64),       // total packets in last interval
    ChannelChanged { channel: u8, band: Band }, // current channel + band
}

/// Commands from the attack thread
#[derive(Debug, Clone)]
pub enum AttackEvent {
    DeauthSent { bssid: String, count: u64 },
    Error(String),
}

/// Commands to the attack thread (hot updates while running)
#[derive(Debug, Clone)]
pub enum AttackCommand {
    UpdateTargets(Vec<Target>),
    UpdateScope(DeauthScope),
    UpdateTargetChannel { bssid: String, channel: u8, band: Band },
    UpdateSettings { burst_size: u16, send_interval_ms: u64 },
}

/// Commands to the scanner thread (channel lock / sweep control)
#[derive(Debug, Clone)]
pub enum ScannerCommand {
    LockChannel(u8, Band),
    SweepFor { client_mac: String },
    FreeHop,
}

/// Wireless interface info
#[derive(Debug, Clone)]
pub struct WirelessInterface {
    pub name: String,
    pub phy: String,
    pub monitor_name: Option<String>,
    #[allow(dead_code)]
    pub is_monitor: bool,
}

/// The main application state
pub struct App {
    pub state: AppState,
    pub ap_list: Vec<AccessPoint>,
    pub targets: Vec<Target>,
    pub selected_ap_idx: usize,
    pub selected_target_idx: Option<usize>,
    pub selected_client_idx: Option<usize>,
    pub show_clients: bool,
    pub current_interface: Option<WirelessInterface>,
    pub monitor_interface: Option<String>,
    pub listen_interface: Option<String>,
    pub attack_interface: Option<String>,
    pub attack_physical: Option<String>,
    pub attack_mode: AttackMode,
    pub attack_type: AttackType,
    pub burst_size: u16,
    pub send_interval_ms: u64,
    pub attack_running: bool,
    pub running: Arc<AtomicBool>,
    pub scanner_running: Arc<AtomicBool>,
    pub wants_setup: bool,
    pub wants_settings: bool,
    pub scanner_rx: mpsc::Receiver<ScannerEvent>,
    pub scanner_tx: mpsc::Sender<ScannerEvent>,
    pub attack_tx: Option<mpsc::Sender<AttackEvent>>,
    pub attack_rx: Option<mpsc::Receiver<AttackEvent>>,
    pub attack_cmd_tx: Option<mpsc::Sender<AttackCommand>>,
    pub scanner_cmd_tx: Option<mpsc::Sender<ScannerCommand>>,
    pub sweep_target: Option<String>,
    pub log_messages: Vec<String>,
    pub total_traffic: u64,
    pub fps_counter: (u64, Instant),
    pub fps: f64,
    pub tab_selection: TabSelection,
    pub page_view: PageView,
    pub events_scroll: usize,
    pub scroll_offset: usize,
    pub target_scroll_offset: usize,
    pub channel_hopping: bool,
    pub current_channel: u8,
    pub current_band: Band,
    pub deauth_scope: DeauthScope,
    pub followed_clients: Vec<(String, Option<String>)>,
    pub log_file: Option<File>,
    pub log_path: Option<std::path::PathBuf>,
    pub log_bytes: u64,
    pub pursuit_mode: bool,
    pub last_ap_save: Instant,
    pub client_names: HashMap<String, String>,
    pub input_mode: InputMode,
    pub input_buffer: String,
    pub input_context: Option<String>,
    pub list_picker_open: bool,
    pub list_picker_slots: Vec<String>,
    pub list_picker_idx: usize,
    pub target_sub_section: TargetSubSection,
    pub txpower_dbm: Option<i32>,
    pub cpu_usage: f32,
    pub sys: System,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TabSelection {
    ApList,
    TargetList,
    ClientList,
}

/// Which sub-section of the Targets panel is focused
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum TargetSubSection {
    Clients,
    Aps,
}

impl App {
    pub fn new() -> (Self, mpsc::Sender<ScannerEvent>) {
        let (scanner_tx, scanner_rx) = mpsc::channel();
        let running = Arc::new(AtomicBool::new(true));

        let app = App {
            state: AppState::Scanning,
            ap_list: Vec::new(),
            targets: Vec::new(),
            selected_ap_idx: 0,
            selected_target_idx: None,
            selected_client_idx: None,
            show_clients: false,
            current_interface: None,
            monitor_interface: None,
            listen_interface: None,
            attack_interface: None,
            attack_physical: None,
            attack_mode: AttackMode::RoundRobin,
            attack_type: AttackType::Deauth,
            burst_size: 200,
            send_interval_ms: 50,
            attack_running: false,
            running: running,
            scanner_running: Arc::new(AtomicBool::new(true)),
            wants_setup: false,
            wants_settings: false,
            scanner_rx,
            scanner_tx: scanner_tx.clone(),
            attack_tx: None,
            attack_rx: None,
            attack_cmd_tx: None,
            scanner_cmd_tx: None,
            sweep_target: None,
            log_messages: Vec::new(),
            total_traffic: 0,
            fps_counter: (0, Instant::now()),
            fps: 0.0,
            tab_selection: TabSelection::ApList,
            page_view: PageView::Dashboard,
            events_scroll: 0,
            scroll_offset: 0,
            target_scroll_offset: 0,
            channel_hopping: true,
            current_channel: 0,
            current_band: Band::TwoGHz,
            deauth_scope: DeauthScope::Broadcast,
            followed_clients: Vec::new(),
            log_file: None,
            log_path: None,
            log_bytes: 0,
            pursuit_mode: false,
            last_ap_save: Instant::now(),
            client_names: HashMap::new(),
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            input_context: None,
            list_picker_open: false,
            list_picker_slots: Vec::new(),
            list_picker_idx: 0,
            target_sub_section: TargetSubSection::Aps,
            txpower_dbm: None,
            cpu_usage: 0.0,
            sys: System::new_all(),
        };

        (app, scanner_tx)
    }

    pub fn add_log(&mut self, msg: String) {
        self.log_messages.push(msg.clone());
        if self.log_messages.len() > 100 {
            self.log_messages.remove(0);
        }
        if let Some(ref mut f) = self.log_file {
            let ts = chrono::Local::now().format("%H:%M:%S");
            let line = format!("[{}] {}", ts, msg);
            let _ = writeln!(f, "{}", line);
            self.log_bytes += line.len() as u64 + 1;
        }
    }

    pub fn toggle_target(&mut self, bssid: &str) {
        if let Some(pos) = self.targets.iter().position(|t| t.bssid == bssid) {
            self.targets.remove(pos);
            self.selected_target_idx = None;
        } else {
            if let Some(ap) = self.ap_list.iter().find(|a| a.bssid == bssid) {
                self.targets.push(Target {
                    bssid: ap.bssid.clone(),
                    ssid: ap.ssid.clone(),
                    band: ap.band,
                    channel: ap.channel,
                    active: true,
                    deauth_count: 0,
                    disconnect_count: 0,
                    client_filter: vec![],
                    follow_managed: false,
                });
            }
        }
    }

    pub fn remove_target(&mut self, idx: usize) {
        if idx < self.targets.len() {
            self.targets.remove(idx);
            self.selected_target_idx = None;
        }
    }

    pub fn is_target(&self, bssid: &str) -> bool {
        self.targets.iter().any(|t| t.bssid == bssid)
    }

    pub fn selected_ap_clients(&self) -> Option<&Vec<Client>> {
        if self.ap_list.is_empty() {
            return None;
        }
        let idx = self.selected_ap_idx.min(self.ap_list.len() - 1);
        Some(&self.ap_list[idx].clients)
    }

    pub fn set_deauth_client(&mut self, client_mac: &str) {
        self.deauth_scope = DeauthScope::Client {
            client_mac: client_mac.to_string(),
        };
    }

    pub fn set_deauth_broadcast(&mut self) {
        self.deauth_scope = DeauthScope::Broadcast;
    }

    /// Toggle follow mode for a client MAC. Returns the AP BSSID it's currently on (if any).
    pub fn toggle_follow_client(&mut self, client_mac: &str) -> Option<String> {
        if let Some(pos) = self.followed_clients.iter().position(|(m, _)| m == client_mac) {
            self.followed_clients.remove(pos);
            self.rebuild_follow_targets();
            return None;
        }
        let current_ap = self.ap_list.iter()
            .find(|ap| ap.clients.iter().any(|c| c.mac == client_mac))
            .map(|ap| ap.bssid.clone());
        self.followed_clients.push((client_mac.to_string(), current_ap.clone()));
        self.rebuild_follow_targets();
        current_ap
    }

    /// Called when scanner sees a followed client on an AP — auto-update target
    pub fn update_followed_client_ap(&mut self, client_mac: &str, ap_bssid: &str) {
        if let Some(entry) = self.followed_clients.iter_mut().find(|(m, _)| m == client_mac) {
            if entry.1.as_deref() != Some(ap_bssid) {
                let old_ap = entry.1.clone();
                entry.1 = Some(ap_bssid.to_string());
                self.add_log(format!(
                    "Followed {} roamed: {} → {}",
                    client_mac,
                    old_ap.as_deref().unwrap_or("?"),
                    ap_bssid
                ));
                self.rebuild_follow_targets();
            }
        }
    }

    pub fn rebuild_follow_targets(&mut self) {
        let mut ap_to_clients: HashMap<String, Vec<String>> = HashMap::new();
        for (mac, maybe_ap) in &self.followed_clients {
            if let Some(ap) = maybe_ap {
                ap_to_clients.entry(ap.clone()).or_default().push(mac.clone());
            }
        }

        // Drop follow-managed targets whose AP has no followed clients
        self.targets.retain(|t| {
            !t.follow_managed || ap_to_clients.contains_key(&t.bssid)
        });

        // Update/add targets for each AP with followed clients
        for (ap_bssid, macs) in &ap_to_clients {
            if let Some(target) = self.targets.iter_mut().find(|t| t.bssid == *ap_bssid) {
                target.client_filter = macs.clone();
                target.follow_managed = true;
            } else if let Some(ap) = self.ap_list.iter().find(|a| a.bssid == *ap_bssid) {
                self.targets.push(Target {
                    bssid: ap.bssid.clone(),
                    ssid: ap.ssid.clone(),
                    band: ap.band,
                    channel: ap.channel,
                    active: true,
                    deauth_count: 0,
                    disconnect_count: 0,
                    client_filter: macs.clone(),
                    follow_managed: true,
                });
            }
        }

        // Clear filter on manually-added targets not hosting any followed client
        for target in self.targets.iter_mut() {
            if !target.follow_managed && !ap_to_clients.contains_key(&target.bssid) {
                target.client_filter.clear();
            }
        }
    }
}
