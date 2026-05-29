use anyhow::{Context, Result};
#[cfg(target_os = "linux")]
use pcap::{Capture, Device};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use crate::types::{AccessPoint, Band, Client, ScannerCommand, ScannerEvent, CHANNEL_HOP_MS, scan_channels_for};
#[cfg(target_os = "linux")]
use crate::types::{channel_to_freq_mhz, freq_to_band};

// ── Linux implementation ──────────────────────────────────────────────────────

/// Run the scanner in a separate thread.
///
/// Captures all 802.11 management frames (beacons, probe req/resp, assoc, auth)
/// to discover APs and clients. Performs channel hopping when enabled.
#[cfg(target_os = "linux")]
pub fn start_scanner(
    iface: &str,
    event_tx: mpsc::Sender<ScannerEvent>,
    cmd_rx: mpsc::Receiver<ScannerCommand>,
    running: Arc<AtomicBool>,
    supports_5ghz: bool,
    supports_6ghz: bool,
) -> Result<std::thread::JoinHandle<()>> {
    let iface = iface.to_string();

    let handle = std::thread::Builder::new()
        .name("scanner".into())
        .spawn(move || {
            let mut cap = match open_capture(&iface) {
                Ok(c) => c,
                Err(e) => {
                    let _ = event_tx.send(ScannerEvent::Error(format!(
                        "Failed to open capture: {}",
                        e
                    )));
                    return;
                }
            };

            let _ = event_tx.send(ScannerEvent::Error("Scanner started".into()));

            let mut ap_map: std::collections::HashMap<String, AccessPoint> =
                std::collections::HashMap::new();
            // Track clients per AP BSSID
            let mut client_map: std::collections::HashMap<
                String,
                std::collections::HashMap<String, Client>,
            > = std::collections::HashMap::new();
            let mut total_packets: u64 = 0;
            let mut last_cleanup = Instant::now();
            let mut last_channel_hop = Instant::now();
            let mut channel_idx = 0usize;
            let scan_channels = scan_channels_for(supports_5ghz, supports_6ghz);
            let mut locked = false;
            let mut sweep_mac: Option<String> = None;
            // Lazily-created handshake/PMKID capture file (opened on first EAPOL).
            let mut hs_writer: Option<crate::handshake::PcapWriter> = None;
            // BSSIDs whose beacon has already been written to the capture — one
            // beacon per AP gives crackers the ESSID (EAPOL frames don't carry it).
            let mut beacon_dumped: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            while running.load(Ordering::Relaxed) {
                // Drain scanner commands
                while let Ok(cmd) = cmd_rx.try_recv() {
                    match cmd {
                        ScannerCommand::LockChannel(ch, band) => {
                            if let Err(e) = set_channel(&iface, ch, band) {
                                let _ = event_tx.send(ScannerEvent::Error(format!("Channel lock failed: {}", e)));
                            }
                            let _ = event_tx.send(ScannerEvent::ChannelChanged { channel: ch, band });
                            locked = true;
                            sweep_mac = None;
                            last_channel_hop = Instant::now();
                        }
                        ScannerCommand::FreeHop => {
                            locked = false;
                            sweep_mac = None;
                        }
                        ScannerCommand::SweepFor { client_mac } => {
                            sweep_mac = Some(client_mac);
                            locked = false;
                        }
                    }
                }

                // Channel hopping: switch every CHANNEL_HOP_MS (skip when locked)
                if !locked
                    && last_channel_hop.elapsed() >= Duration::from_millis(CHANNEL_HOP_MS)
                    && !scan_channels.is_empty()
                {
                    channel_idx = (channel_idx + 1) % scan_channels.len();
                    let (ch, band) = scan_channels[channel_idx];
                    if let Err(e) = set_channel(&iface, ch, band) {
                        let _ = event_tx.send(ScannerEvent::Error(format!("Channel hop failed: {}", e)));
                    }
                    let _ = event_tx.send(ScannerEvent::ChannelChanged { channel: ch, band });
                    last_channel_hop = Instant::now();
                }

                match cap.next_packet() {
                    Ok(packet) => {
                        total_packets += 1;

                        // EAPOL / WPA-handshake capture: dump any 802.1X frame
                        // (with its radiotap header) to a session pcap that
                        // aircrack-ng / hashcat can crack offline.
                        if let Some((bssid, sta)) = crate::handshake::eapol_endpoints(packet.data) {
                            if hs_writer.is_none() {
                                match open_handshake_writer() {
                                    Ok((w, path)) => {
                                        let _ = event_tx.send(ScannerEvent::Error(format!(
                                            "Handshake capture started → {}", path
                                        )));
                                        hs_writer = Some(w);
                                    }
                                    Err(e) => {
                                        let _ = event_tx.send(ScannerEvent::Error(format!(
                                            "Handshake file error: {}", e
                                        )));
                                    }
                                }
                            }
                            if let Some(w) = hs_writer.as_mut() {
                                let ts = packet.header.ts;
                                let _ = w.write_frame(ts.tv_sec as u32, ts.tv_usec as u32, packet.data);
                            }
                            let _ = event_tx.send(ScannerEvent::Error(format!(
                                "EAPOL captured: {} ↔ {}", bssid, sta
                            )));
                        }

                        // Try parsing as beacon / probe response (AP detection)
                        // pcap::Packet doesn't implement Clone, so we slice the data
                        if let Some(ap) = parse_beacon_frame_raw(packet.data) {
                            let bssid = ap.bssid.clone();
                            // Record one beacon per AP into the handshake capture so
                            // the ESSID is recoverable alongside the EAPOL frames.
                            if let Some(w) = hs_writer.as_mut() {
                                if beacon_dumped.insert(bssid.clone()) {
                                    let ts = packet.header.ts;
                                    let _ = w.write_frame(ts.tv_sec as u32, ts.tv_usec as u32, packet.data);
                                }
                            }
                            if let Some(existing) = ap_map.get_mut(&bssid) {
                                existing.signal_dbm = ap.signal_dbm;
                                existing.signal_percent = ap.signal_percent;
                                existing.packets += 1;
                                existing.last_seen = Instant::now();
                                existing.encryption = ap.encryption;
                                let _ = event_tx.send(ScannerEvent::ApUpdated(existing.clone()));
                            } else {
                                let mut new_ap = ap;
                                new_ap.packets = 1;
                                new_ap.clients = Vec::new();
                                let bssid2 = new_ap.bssid.clone();
                                let _ = event_tx.send(ScannerEvent::ApDiscovered(new_ap.clone()));
                                ap_map.insert(bssid2, new_ap);
                            }
                            continue; // skip client parsing for beacons
                        }

                        // Try parsing as client frame (probe req, assoc, auth, data)
                        if let Some((ap_bssid, client)) = parse_client_frame_raw(packet.data) {
                            // Find or create client tracking for this AP
                            let clients = client_map
                                .entry(ap_bssid.clone())
                                .or_insert_with(std::collections::HashMap::new);

                            if let Some(existing) = clients.get_mut(&client.mac) {
                                existing.signal_dbm = client.signal_dbm;
                                existing.packets += 1;
                                existing.last_seen = Instant::now();
                                existing.associated = existing.associated || client.associated;
                                let _ = event_tx.send(ScannerEvent::ClientUpdated {
                                    ap_bssid: ap_bssid.clone(),
                                    client: existing.clone(),
                                });
                            } else {
                                let mac = client.mac.clone();
                                let _ = event_tx.send(ScannerEvent::ClientDiscovered {
                                    ap_bssid: ap_bssid.clone(),
                                    client: client.clone(),
                                });
                                clients.insert(mac, client);
                            }

                            // Also update the AP's client list
                            if let Some(ap) = ap_map.get_mut(&ap_bssid) {
                                ap.clients = clients.values().cloned().collect();
                            }
                        }
                    }
                    Err(pcap::Error::TimeoutExpired) => { /* expected, continue */ }
                    Err(e) => {
                        let _ = event_tx.send(ScannerEvent::Error(format!("Capture error: {}", e)));
                        std::thread::sleep(Duration::from_millis(100));
                    }
                }

                // Periodic traffic reporting
                if last_cleanup.elapsed() >= Duration::from_secs(30) {
                    let _ = event_tx.send(ScannerEvent::Traffic(total_packets));
                    total_packets = 0;
                    last_cleanup = Instant::now();
                }
            }
        })
        .context("Failed to spawn scanner thread")?;

    Ok(handle)
}

/// Set channel on a monitor interface via frequency.
#[cfg(target_os = "linux")]
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

/// Open pcap capture with filter for all management frames
#[cfg(target_os = "linux")]
fn open_capture(iface: &str) -> Result<Capture<pcap::Active>> {
    let devices = Device::list().context("Failed to list pcap devices")?;

    let device = devices.iter().find(|d| d.name == *iface);

    let mut cap = match device {
        Some(dev) => Capture::from_device(dev.name.as_str())
            .context("Failed to create capture from device")?
            .timeout(200)
            .promisc(true)
            .snaplen(65535)
            .open()
            .context(format!("Failed to open capture on {}", iface))?,
        None => Capture::from_device(iface)
            .context("Failed to create capture from device name")?
            .timeout(200)
            .promisc(true)
            .snaplen(65535)
            .open()
            .context(format!("Failed to open capture on {}", iface))?,
    };

    // Capture management frames (type 0: beacon/probe/assoc/auth/deauth) AND
    // data frames (type 2). Data frames are needed for EAPOL/handshake capture
    // and for discovering associated clients from their traffic.
    // BPF: type bits = frame_control bits 2-3.
    let filter = "(wlan[0] & 0x0C) == 0x00 or (wlan[0] & 0x0C) == 0x08";
    cap.filter(filter, true)
        .context("Failed to set capture filter")?;

    Ok(cap)
}

/// Open a new per-session handshake capture file under ~/.smartdos/handshakes/.
/// Returns the writer and its display path.
#[cfg(target_os = "linux")]
fn open_handshake_writer() -> Result<(crate::handshake::PcapWriter, String)> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let dir = std::path::PathBuf::from(home).join(".smartdos").join("handshakes");
    std::fs::create_dir_all(&dir).context("create handshakes dir")?;
    let stamp = chrono::Local::now().format("%Y%m%d-%H%M%S");
    let path = dir.join(format!("session-{}.pcap", stamp));
    let writer = crate::handshake::PcapWriter::create(&path)
        .context("create handshake pcap")?;
    Ok((writer, path.display().to_string()))
}

/// Parse a beacon or probe response frame → returns AP info
#[cfg(target_os = "linux")]
fn parse_beacon_frame_raw(data: &[u8]) -> Option<AccessPoint> {
    let total_len = data.len();

    if total_len < 24 {
        return None;
    }

    let (offset, signal_dbm) = parse_radiotap_offset(data);

    // Frame Control field
    if offset + 2 > total_len {
        return None;
    }
    let frame_control = u16::from_le_bytes([data[offset], data[offset + 1]]);
    let frame_type = (frame_control >> 2) & 0x03;
    let frame_subtype = (frame_control >> 4) & 0x0F;

    // Beacon (subtype 8) or Probe Response (subtype 5)
    if frame_type != 0 || (frame_subtype != 8 && frame_subtype != 5) {
        return None;
    }

    if offset + 24 > total_len {
        return None;
    }

    let bssid = mac_to_string(&data[offset + 16..offset + 22]);

    let body_start = offset + 24;
    if body_start >= total_len {
        return None;
    }
    let body = &data[body_start..];

    if body.len() < 12 {
        return None;
    }
    let _timestamp = u64::from_le_bytes(body[0..8].try_into().unwrap());
    let _beacon_interval = u16::from_le_bytes(body[8..10].try_into().unwrap());
    let _capabilities = u16::from_le_bytes(body[10..12].try_into().unwrap());

    // Parse tagged parameters
    let mut ssid = String::new();
    let mut channel: u8 = 0;
    let mut encryption = "OPEN".to_string();

    let mut pos = 12;
    while pos + 2 <= body.len() {
        let tag_number = body[pos];
        let tag_length = body[pos + 1] as usize;
        pos += 2;

        if pos + tag_length > body.len() {
            break;
        }

        let tag_value = &body[pos..pos + tag_length];

        match tag_number {
            0 => {
                if tag_length > 0 && tag_length <= 32 {
                    ssid = String::from_utf8_lossy(tag_value).to_string();
                } else {
                    ssid = "<Hidden>".to_string();
                }
            }
            3 => {
                if tag_length >= 1 {
                    channel = tag_value[0];
                }
            }
            48 => {
                encryption = parse_rsn_ie(tag_value);
            }
            0xDD => {
                if tag_length >= 4
                    && tag_value[0..4] == [0x00, 0x50, 0xF2, 0x01]
                    && encryption == "OPEN"
                {
                    encryption = parse_wpa_ie(tag_value);
                }
            }
            _ => {}
        }

        pos += tag_length;
    }

    if bssid == "00:00:00:00:00:00" || bssid == "ff:ff:ff:ff:ff:ff" {
        return None;
    }

    // Determine band: prefer radiotap frequency, fall back to channel number heuristic
    let band = parse_radiotap_freq(data)
        .map(freq_to_band)
        .unwrap_or_else(|| {
            if channel <= 14 { Band::TwoGHz }
            else { Band::FiveGHz } // 6 GHz shares numbers with 5 GHz — radiotap required for disambiguation
        });

    let signal_percent = if signal_dbm >= -30 {
        100
    } else if signal_dbm <= -95 {
        5
    } else {
        ((signal_dbm + 95) * 100 / 65).max(5).min(100) as u8
    };

    Some(AccessPoint {
        bssid,
        ssid,
        band,
        channel,
        signal_dbm,
        signal_percent,
        packets: 0,
        last_seen: Instant::now(),
        encryption,
        clients: Vec::new(),
        traffic_rate: 0.0,
    })
}

/// Decode RSN IE (tag 48) → "WPA2", "WPA3", "W2-Ent", "W2/TKIP", "OWE", etc.
#[cfg(target_os = "linux")]
fn parse_rsn_ie(ie: &[u8]) -> String {
    // Layout: 2B version | 4B group cipher | 2B pairwise count | N*4B pairwise | 2B AKM count | N*4B AKM
    if ie.len() < 8 {
        return "WPA2".to_string();
    }
    let pairwise_count = u16::from_le_bytes([ie[6], ie[7]]) as usize;
    let pairwise_end = 8 + pairwise_count * 4;
    if ie.len() < pairwise_end + 2 {
        return "WPA2".to_string();
    }

    let mut has_ccmp = false;
    let mut has_tkip = false;
    for i in 0..pairwise_count {
        let o = 8 + i * 4;
        if o + 4 > ie.len() {
            break;
        }
        match ie[o + 3] {
            4 | 8 | 9 => has_ccmp = true, // CCMP-128, GCMP-128, GCMP-256
            2 => has_tkip = true,
            _ => {}
        }
    }

    let akm_count = u16::from_le_bytes([ie[pairwise_end], ie[pairwise_end + 1]]) as usize;
    let mut is_enterprise = false;
    let mut is_psk = false;
    let mut is_sae = false;
    let mut is_owe = false;
    for i in 0..akm_count {
        let o = pairwise_end + 2 + i * 4;
        if o + 4 > ie.len() {
            break;
        }
        match ie[o + 3] {
            1 | 3 | 5 => is_enterprise = true, // 802.1X, FT-802.1X, 802.1X-SHA256
            2 | 4 | 6 => is_psk = true,        // PSK, FT-PSK, PSK-SHA256
            8 | 9 => is_sae = true,             // SAE / FT-SAE → WPA3
            18 => is_owe = true,                // OWE (Enhanced Open)
            _ => {}
        }
    }

    if is_owe {
        return "OWE".to_string();
    }
    if is_sae && is_psk {
        return "W2/W3".to_string(); // transition mode
    }
    if is_sae {
        return "WPA3".to_string();
    }
    if is_enterprise {
        return "W2-Ent".to_string();
    }
    if has_tkip && !has_ccmp {
        return "W2/T".to_string();
    }
    "WPA2".to_string()
}

/// Decode WPA vendor IE (OUI 00:50:F2 type 01) → "WPA", "WPA-E", "W1/T"
#[cfg(target_os = "linux")]
fn parse_wpa_ie(ie: &[u8]) -> String {
    // Layout: 4B OUI+type | 2B version | 4B mcast cipher | 2B ucast count | N*4B ucast | 2B AKM count | N*4B AKM
    if ie.len() < 14 {
        return "WPA".to_string();
    }
    let ucast_count = u16::from_le_bytes([ie[10], ie[11]]) as usize;
    let ucast_end = 12 + ucast_count * 4;
    if ie.len() < ucast_end + 2 {
        return "WPA".to_string();
    }

    let mut has_ccmp = false;
    let mut has_tkip = false;
    for i in 0..ucast_count {
        let o = 12 + i * 4;
        if o + 4 > ie.len() {
            break;
        }
        match ie[o + 3] {
            4 => has_ccmp = true,
            2 => has_tkip = true,
            _ => {}
        }
    }

    let akm_count = u16::from_le_bytes([ie[ucast_end], ie[ucast_end + 1]]) as usize;
    let mut is_enterprise = false;
    for i in 0..akm_count {
        let o = ucast_end + 2 + i * 4;
        if o + 4 > ie.len() {
            break;
        }
        if ie[o + 3] == 1 {
            is_enterprise = true;
        }
    }

    if is_enterprise {
        return "WPA-E".to_string();
    }
    if has_ccmp && !has_tkip {
        return "WPA/C".to_string();
    }
    "WPA".to_string()
}

/// Parse a frame that reveals a client/station:
/// - Probe Request (subtype 4): SA is client, probing for any/networks
/// - Association Request (subtype 0): SA is client, DA is AP
/// - Authentication (subtype 11): SA is client, DA is AP
/// - Data frames (type 2): SA or DA could be a client
/// Returns (ap_bssid, client)
#[cfg(target_os = "linux")]
fn parse_client_frame_raw(data: &[u8]) -> Option<(String, Client)> {
    let total_len = data.len();

    if total_len < 24 {
        return None;
    }

    let (offset, signal_dbm) = parse_radiotap_offset(data);

    if offset + 2 > total_len {
        return None;
    }
    let frame_control = u16::from_le_bytes([data[offset], data[offset + 1]]);
    let frame_type = (frame_control >> 2) & 0x03;
    let frame_subtype = (frame_control >> 4) & 0x0F;

    if offset + 22 > total_len {
        return None;
    }

    let da = mac_to_string(&data[offset + 4..offset + 10]);
    let sa = mac_to_string(&data[offset + 10..offset + 16]);
    let bssid = mac_to_string(&data[offset + 16..offset + 22]);

    // Filter out broadcast/invalid
    if sa == "00:00:00:00:00:00" || sa == "ff:ff:ff:ff:ff:ff" {
        return None;
    }
    if bssid == "00:00:00:00:00:00" {
        return None;
    }

    match (frame_type, frame_subtype) {
        // Probe Request — client probing
        (0, 4) => {
            // SA is the client, DA is usually broadcast
            // The BSSID field may be broadcast too
            // We associate this client with the BSSID if it's specific, or leave as generic
            if bssid != "ff:ff:ff:ff:ff:ff" && !bssid.starts_with("00:00:00") {
                Some((
                    bssid,
                    Client {
                        mac: sa,
                        signal_dbm,
                        packets: 1,
                        last_seen: Instant::now(),
                        associated: false,
                        friendly_name: None,
                    },
                ))
            } else {
                // Wildcard probe — can't determine AP, skip
                None
            }
        }
        // Association Request — client associating to AP
        (0, 0) => {
            if bssid != "ff:ff:ff:ff:ff:ff" {
                Some((
                    bssid,
                    Client {
                        mac: sa,
                        signal_dbm,
                        packets: 1,
                        last_seen: Instant::now(),
                        associated: true,
                        friendly_name: None,
                    },
                ))
            } else {
                None
            }
        }
        // Authentication — SA requesting auth from DA
        (0, 11) => {
            if bssid != "ff:ff:ff:ff:ff:ff" {
                Some((
                    bssid,
                    Client {
                        mac: sa,
                        signal_dbm,
                        packets: 1,
                        last_seen: Instant::now(),
                        associated: true,
                        friendly_name: None,
                    },
                ))
            } else {
                None
            }
        }
        // Reassociation Request
        (0, 2) => {
            if bssid != "ff:ff:ff:ff:ff:ff" {
                Some((
                    bssid,
                    Client {
                        mac: sa,
                        signal_dbm,
                        packets: 1,
                        last_seen: Instant::now(),
                        associated: true,
                        friendly_name: None,
                    },
                ))
            } else {
                None
            }
        }
        // Data frames — track data going to/from APs to find clients
        // We only do this if we can match to an AP we know
        // (handled by checking the BSSID field)
        (2, _) => {
            // Data frame: DA could be AP, SA could be AP
            // BSSID field is the BSSID for data frames
            if bssid != "ff:ff:ff:ff:ff:ff" && !bssid.starts_with("00:00:00") {
                // Determine which address is the client (the one that's NOT the BSSID)
                if sa == bssid {
                    // AP sending to client — client is DA
                    Some((
                        bssid,
                        Client {
                            mac: da,
                            signal_dbm,
                            packets: 1,
                            last_seen: Instant::now(),
                            associated: true,
                            friendly_name: None,
                        },
                    ))
                } else if da == bssid {
                    // Client sending to AP — client is SA
                    Some((
                        bssid,
                        Client {
                            mac: sa,
                            signal_dbm,
                            packets: 1,
                            last_seen: Instant::now(),
                            associated: true,
                            friendly_name: None,
                        },
                    ))
                } else {
                    None // BSSID doesn't match either address
                }
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Parse radiotap header to get offset and signal, or return (0, 0) for raw 802.11
#[cfg(target_os = "linux")]
fn parse_radiotap_offset(data: &[u8]) -> (usize, i16) {
    if data.len() >= 4 && data[0] == 0 && data[1] == 0 {
        let rt_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        if rt_len >= 4 && rt_len <= 128 {
            let sig = parse_radiotap_signal(data);
            return (rt_len, sig);
        }
    }
    (0, 0)
}

/// Extract channel frequency (MHz) from radiotap Channel field (present bit 3).
#[cfg(target_os = "linux")]
fn parse_radiotap_freq(data: &[u8]) -> Option<u32> {
    if data.len() < 8 || data[0] != 0 || data[1] != 0 {
        return None;
    }
    let present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if present & (1 << 3) == 0 {
        return None;
    }
    let mut offset = 8usize;
    if present & (1 << 0) != 0 { offset += 8; } // TSFT
    if present & (1 << 1) != 0 { offset += 1; } // Flags
    if present & (1 << 2) != 0 { offset += 1; } // Rate
    // bit 3 = Channel: u16 freq + u16 flags
    if offset + 2 > data.len() {
        return None;
    }
    let freq = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
    if freq > 1000 { Some(freq) } else { None }
}

/// Parse radiotap header to extract antenna signal (dBm)
#[cfg(target_os = "linux")]
fn parse_radiotap_signal(data: &[u8]) -> i16 {
    if data.len() < 8 {
        return 0;
    }

    let present = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let mut field_offset: usize = 8;
    let mut bit_index = 0;

    while bit_index < 32 {
        let check_bit = 1u32 << bit_index;
        if present & check_bit != 0 {
            match bit_index {
                0 => field_offset += 8, // TSFT
                1 => field_offset += 1, // Flags
                2 => field_offset += 1, // Rate
                3 => field_offset += 4, // Channel
                4 => field_offset += 2, // FHSS
                5 => {
                    if field_offset < data.len() {
                        return data[field_offset] as i8 as i16;
                    }
                    field_offset += 1;
                }
                6 => field_offset += 1,   // Antenna Noise
                7 => field_offset += 2,   // Lock Quality
                8 => field_offset += 2,   // TX Attenuation
                9 => field_offset += 2,   // DB TX Attenuation
                10 => field_offset += 1,  // TX Power
                11 => field_offset += 1,  // Antenna
                12 => field_offset += 1,  // DB Antenna Signal
                13 => field_offset += 1,  // DB Antenna Noise
                14 => field_offset += 2,  // RX Flags
                15 => field_offset += 2,  // TX Flags
                16 => field_offset += 1,  // RTS Retries
                17 => field_offset += 1,  // HW Queue
                18 => field_offset += 3,  // RSSI (experimental)
                19 => field_offset += 18, // XChannel
                _ => field_offset += 4,   // unknown, skip
            }
        }
        bit_index += 1;
        if bit_index == 32 && present & (1 << 31) != 0 {
            break; // skip extended flags for now
        }
    }

    0
}

#[cfg(target_os = "linux")]
fn mac_to_string(bytes: &[u8]) -> String {
    if bytes.len() < 6 {
        return String::new();
    }
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    // RSN IE contents: version | group | pairwise(count+suites) | akm(count+suites) | caps
    #[test]
    fn rsn_psk_ccmp_is_wpa2() {
        let ie = [
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x02, 0x00, 0x00,
        ];
        assert_eq!(parse_rsn_ie(&ie), "WPA2");
    }

    #[test]
    fn rsn_sae_is_wpa3() {
        let ie = [
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x08, 0x00, 0x00,
        ];
        assert_eq!(parse_rsn_ie(&ie), "WPA3");
    }

    #[test]
    fn rsn_enterprise_is_w2_ent() {
        let ie = [
            0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00, 0x00, 0x0F, 0xAC, 0x04, 0x01, 0x00,
            0x00, 0x0F, 0xAC, 0x01, 0x00, 0x00,
        ];
        assert_eq!(parse_rsn_ie(&ie), "W2-Ent");
    }

    #[test]
    fn mac_formats_uppercase_colons() {
        assert_eq!(
            mac_to_string(&[0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33]),
            "AA:BB:CC:11:22:33"
        );
    }

    #[test]
    fn radiotap_offset_reads_length_field() {
        let data = [0u8, 0, 8, 0, 0, 0, 0, 0, 0xDE];
        let (off, _sig) = parse_radiotap_offset(&data);
        assert_eq!(off, 8);
    }

    #[test]
    fn radiotap_signal_reads_antenna_dbm() {
        // present bitmap = bit5 (antenna signal); signal byte at offset 8.
        let data = [0u8, 0, 9, 0, 0x20, 0, 0, 0, (-50i8) as u8];
        assert_eq!(parse_radiotap_signal(&data), -50);
    }
}

// ── Stub implementation (non-Linux / macOS dev) ───────────────────────────────

/// Fake AP data: (bssid, ssid, channel, signal_dbm, encryption, band)
#[cfg(not(target_os = "linux"))]
static FAKE_APS: &[(&str, &str, u8, i16, &str, Band)] = &[
    // 2.4 GHz
    ("AA:BB:CC:11:22:33", "HomeNetwork",        6,  -45, "WPA2",  Band::TwoGHz),
    ("AA:BB:CC:44:55:66", "Neighbor_2.4G",     11,  -72, "WPA2",  Band::TwoGHz),
    ("AA:BB:CC:77:88:99", "XFINITY-GUEST",      1,  -81, "OPEN",  Band::TwoGHz),
    ("AA:BB:CC:AA:BB:CC", "Android-Hotspot",    6,  -68, "WPA2",  Band::TwoGHz),
    ("AA:BB:CC:DD:EE:FF", "DIRECT-printer",    11,  -55, "OPEN",  Band::TwoGHz),
    ("11:22:33:44:55:66", "CafeWiFi_Public",    6,  -60, "OWE",   Band::TwoGHz),
    ("22:33:44:55:66:77", "OldRouter",          1,  -75, "WPA",   Band::TwoGHz),
    ("33:44:55:66:77:88", "VeryOldRouter",      6,  -83, "WEP",   Band::TwoGHz),
    ("44:55:66:77:88:99", "Corp-Office",        1,  -58, "W2-Ent",Band::TwoGHz),
    ("55:66:77:88:99:AA", "WPA_Legacy",         6,  -70, "WPA-E", Band::TwoGHz),
    ("66:77:88:99:AA:BB", "WeakRouter",        11,  -79, "W2/T",  Band::TwoGHz),
    // 5 GHz
    ("AA:BB:CC:11:22:44", "HomeNetwork_5G",    36,  -42, "WPA3",  Band::FiveGHz),
    ("AA:BB:CC:44:55:77", "Neighbor_5G",       40,  -65, "WPA2",  Band::FiveGHz),
    ("AA:BB:CC:77:88:AA", "TP-Link_5G",        44,  -50, "W2/W3", Band::FiveGHz),
    ("77:88:99:AA:BB:CC", "Corp-Office_5G",   149,  -54, "W2-Ent",Band::FiveGHz),
    ("88:99:AA:BB:CC:DD", "Mesh_Node_5G",     161,  -48, "WPA3",  Band::FiveGHz),
    ("99:AA:BB:CC:DD:EE", "",                  48,  -88, "WPA2",  Band::FiveGHz),
    // 6 GHz
    ("AA:BB:CC:11:22:55", "HomeNetwork_6G",     5,  -38, "WPA3",  Band::SixGHz),
    ("AA:BB:CC:44:55:88", "Neighbor_6G",       37,  -61, "WPA3",  Band::SixGHz),
    ("BB:CC:DD:EE:FF:00", "Mesh_Node_6G",      69,  -44, "WPA3",  Band::SixGHz),
];

/// Fake clients: (ap_bssid, client_mac, signal_dbm, associated)
#[cfg(not(target_os = "linux"))]
static FAKE_CLIENTS: &[(&str, &str, i16, bool)] = &[
    ("AA:BB:CC:11:22:33", "DE:AD:BE:EF:00:01", -52, true),
    ("AA:BB:CC:11:22:33", "DE:AD:BE:EF:00:02", -61, true),
    ("AA:BB:CC:11:22:33", "DE:AD:BE:EF:00:07", -71, false),
    ("AA:BB:CC:44:55:66", "DE:AD:BE:EF:00:03", -78, true),
    ("AA:BB:CC:44:55:66", "DE:AD:BE:EF:00:08", -82, true),
    ("AA:BB:CC:77:88:99", "DE:AD:BE:EF:00:04", -65, false),
    ("AA:BB:CC:77:88:99", "DE:AD:BE:EF:00:09", -59, false),
    ("AA:BB:CC:77:88:99", "DE:AD:BE:EF:00:0A", -74, true),
    ("44:55:66:77:88:99", "DE:AD:BE:EF:00:05", -55, true),
    ("44:55:66:77:88:99", "DE:AD:BE:EF:00:06", -63, true),
    ("AA:BB:CC:11:22:44", "DE:AD:BE:EF:01:01", -44, true),
    ("AA:BB:CC:11:22:44", "DE:AD:BE:EF:01:02", -50, true),
    ("AA:BB:CC:77:88:AA", "DE:AD:BE:EF:01:03", -48, true),
    ("77:88:99:AA:BB:CC", "DE:AD:BE:EF:01:04", -57, true),
    ("77:88:99:AA:BB:CC", "DE:AD:BE:EF:01:05", -62, true),
    ("77:88:99:AA:BB:CC", "DE:AD:BE:EF:01:06", -69, true),
];

#[cfg(not(target_os = "linux"))]
fn make_ap(bssid: &str, ssid: &str, channel: u8, signal_dbm: i16, encryption: &str, band: Band) -> AccessPoint {
    let signal_percent = if signal_dbm >= -30 {
        100
    } else if signal_dbm <= -95 {
        5
    } else {
        ((signal_dbm + 95) * 100 / 65).max(5).min(100) as u8
    };
    AccessPoint {
        bssid: bssid.to_string(),
        ssid: ssid.to_string(),
        band,
        channel,
        signal_dbm,
        signal_percent,
        packets: 1,
        last_seen: Instant::now(),
        encryption: encryption.to_string(),
        clients: Vec::new(),
        traffic_rate: 0.0,
    }
}

#[cfg(not(target_os = "linux"))]
pub fn start_scanner(
    _iface: &str,
    event_tx: mpsc::Sender<ScannerEvent>,
    _cmd_rx: mpsc::Receiver<ScannerCommand>,
    running: Arc<AtomicBool>,
    supports_5ghz: bool,
    supports_6ghz: bool,
) -> Result<std::thread::JoinHandle<()>> {
    let handle = std::thread::Builder::new()
        .name("scanner-stub".into())
        .spawn(move || {
            let _ = event_tx.send(ScannerEvent::Error(
                "[STUB] Scanner started — no wireless hardware, using fake data".into(),
            ));

            let scan_channels = scan_channels_for(supports_5ghz, supports_6ghz);

            // Emit initial AP list filtered to enabled bands
            for (bssid, ssid, ch, dbm, enc, band) in FAKE_APS {
                let skip = match band {
                    Band::FiveGHz => !supports_5ghz,
                    Band::SixGHz  => !supports_6ghz,
                    Band::TwoGHz  => false,
                };
                if skip { continue; }
                let ap = make_ap(bssid, ssid, *ch, *dbm, enc, *band);
                let _ = event_tx.send(ScannerEvent::ApDiscovered(ap));
            }

            // Emit initial channel
            if let Some(&(ch, band)) = scan_channels.first() {
                let _ = event_tx.send(ScannerEvent::ChannelChanged { channel: ch, band });
            }

            // Stagger client discovery 2s after startup
            std::thread::sleep(Duration::from_secs(2));
            for (ap_bssid, mac, dbm, assoc) in FAKE_CLIENTS {
                if !running.load(Ordering::Relaxed) {
                    return;
                }
                let client = Client {
                    mac: mac.to_string(),
                    signal_dbm: *dbm,
                    packets: 1,
                    last_seen: Instant::now(),
                    associated: *assoc,
                    friendly_name: None,
                };
                let _ = event_tx.send(ScannerEvent::ClientDiscovered {
                    ap_bssid: ap_bssid.to_string(),
                    client,
                });
            }

            // Build per-AP client list — mutable so we can apply churn each tick
            let mut ap_clients: std::collections::HashMap<&str, Vec<Client>> =
                std::collections::HashMap::new();
            for (ap_bssid, mac, dbm, assoc) in FAKE_CLIENTS {
                ap_clients.entry(ap_bssid).or_default().push(Client {
                    mac: mac.to_string(),
                    signal_dbm: *dbm,
                    packets: 1,
                    last_seen: Instant::now(),
                    associated: *assoc,
                    friendly_name: None,
                });
            }

            let mut tick: u64 = 0;
            let mut channel_idx = 0usize;

            while running.load(Ordering::Relaxed) {
                std::thread::sleep(Duration::from_millis(CHANNEL_HOP_MS));

                // Hop channel every tick
                if !scan_channels.is_empty() {
                    channel_idx = (channel_idx + 1) % scan_channels.len();
                    let (ch, band) = scan_channels[channel_idx];
                    let _ = event_tx.send(ScannerEvent::ChannelChanged { channel: ch, band });
                }

                // Every ~1s (4 ticks × 250ms): AP updates + client churn
                if tick % 4 == 0 {
                    let sec = tick / 4;

                    for (i, (bssid, ssid, ch, base_dbm, enc, band)) in FAKE_APS.iter().enumerate() {
                        let skip = match band {
                            Band::FiveGHz => !supports_5ghz,
                            Band::SixGHz  => !supports_6ghz,
                            Band::TwoGHz  => false,
                        };
                        if skip { continue; }
                        let jitter = ((sec + i as u64) % 11) as i16 - 5;
                        let ap = make_ap(bssid, ssid, *ch, base_dbm + jitter, enc, *band);
                        let _ = event_tx.send(ScannerEvent::ApUpdated(ap));
                    }

                    // Emit ClientUpdated for each client with jittered signal + ticking packets
                    for (ap_bssid, clients) in &mut ap_clients {
                        for (ci, client) in clients.iter_mut().enumerate() {
                            let jitter = ((sec + ci as u64) % 7) as i16 - 3;
                            client.signal_dbm = (client.signal_dbm + jitter).clamp(-90, -20);
                            client.packets += 1;
                            client.last_seen = Instant::now();
                            // Every 30s briefly disassociate then reassociate (simulates roam/reconnect)
                            client.associated = (sec + ci as u64) % 30 != 0;
                            let _ = event_tx.send(ScannerEvent::ClientUpdated {
                                ap_bssid: ap_bssid.to_string(),
                                client: client.clone(),
                            });
                        }
                    }

                    let _ = event_tx.send(ScannerEvent::Traffic(tick * 4 + 1));
                }

                tick += 1;
            }
        })
        .context("Failed to spawn scanner stub thread")?;

    Ok(handle)
}
