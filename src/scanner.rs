use anyhow::{Context, Result};
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
use pcap::{Capture, Device};
use std::sync::mpsc;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc,
};
use std::time::{Duration, Instant};

use crate::types::{AccessPoint, Band, Client, ScannerCommand, ScannerEvent, CHANNEL_HOP_MS, scan_channels_for};
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
use crate::types::{band_from_channel, channel_to_freq_mhz, freq_to_band, freq_to_channel};

// ── Linux implementation ──────────────────────────────────────────────────────

/// Maximum number of consecutive hop-worker dispatches per hop tick before
/// giving up and waiting for the next tick. Shared by the hop timer and the
/// result-handler retry path.
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
const MAX_HOP_ATTEMPTS: usize = 4;

/// Spawn the hop-worker thread.
///
/// The worker blocks on `req_rx`, calls `set_channel`, then sends the result
/// back. Using `sync_channel(1)` in both directions ensures at most one hop
/// is in flight at a time and the scanner's `try_send` never needs to block.
///
/// The worker exits naturally when the scanner thread drops `hop_tx` (recv()
/// returns Err on a disconnected sender).
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
fn spawn_hop_worker(
    iface: String,
) -> (
    std::sync::mpsc::SyncSender<(u8, Band)>,
    std::sync::mpsc::Receiver<Result<(u8, Band)>>,
) {
    let (req_tx, req_rx) = std::sync::mpsc::sync_channel::<(u8, Band)>(1);
    let (res_tx, res_rx) = std::sync::mpsc::sync_channel::<Result<(u8, Band)>>(1);

    std::thread::Builder::new()
        .name("hop-worker".into())
        .spawn(move || {
            while let Ok((ch, band)) = req_rx.recv() {
                let result = set_channel(&iface, ch, band).map(|()| (ch, band));
                // If the scanner has already exited (dropped res_tx side),
                // sending will fail — just exit the loop cleanly.
                if res_tx.send(result).is_err() {
                    break;
                }
            }
        })
        .expect("failed to spawn hop-worker thread");

    (req_tx, res_rx)
}

/// Run the scanner in a separate thread.
///
/// Captures all 802.11 management frames (beacons, probe req/resp, assoc, auth)
/// to discover APs and clients. Performs channel hopping when enabled.
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
pub fn start_scanner(
    iface: &str,
    event_tx: mpsc::Sender<ScannerEvent>,
    cmd_rx: mpsc::Receiver<ScannerCommand>,
    running: Arc<AtomicBool>,
    supports_5ghz: bool,
    supports_6ghz: bool,
    band_2ghz_enabled: bool,
    band_5ghz_enabled: bool,
    band_6ghz_enabled: bool,
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

            // Spawn the dedicated hop-worker thread. Channel-tune calls happen
            // there so pcap reads are never blocked by iw set freq latency.
            let (hop_tx, hop_rx) = spawn_hop_worker(iface.clone());

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
            let mut band_2ghz_en = band_2ghz_enabled;
            let mut band_5ghz_en = band_5ghz_enabled;
            let mut band_6ghz_en = band_6ghz_enabled;
            let mut scan_channels = scan_channels_for(supports_5ghz, supports_6ghz, band_2ghz_en, band_5ghz_en, band_6ghz_en);
            // Channels whose last tune attempt failed — used only to log each
            // failing channel once (until it recovers). We never drop channels
            // from the rotation: a regdomain-disabled channel just fails cheaply
            // every pass, and a transiently-busy one self-heals next time around.
            let mut failed_channels: std::collections::HashSet<(u8, Band)> =
                std::collections::HashSet::new();
            let mut locked = false;
            let mut sweep_mac: Option<String> = None;
            let mut last_successful_hop = Instant::now();
            let mut last_heartbeat = Instant::now();
            let mut loop_iters: u64 = 0;
            // hop_pending: a request has been sent to the hop-worker and we are
            // waiting for the result. Only one hop is in flight at a time.
            let mut hop_pending = false;
            // hop_attempts: how many consecutive failed dispatches this hop cycle.
            let mut hop_attempts = 0usize;
            // Lazily-created handshake/PMKID capture file (opened on first EAPOL).
            let mut hs_writer: Option<crate::handshake::PcapWriter> = None;
            // BSSIDs whose beacon has already been written to the capture — one
            // beacon per AP gives crackers the ESSID (EAPOL frames don't carry it).
            let mut beacon_dumped: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            while running.load(Ordering::Relaxed) {
                loop_iters += 1;
                if last_heartbeat.elapsed() >= Duration::from_secs(2) {
                    let cur_ch = scan_channels.get(channel_idx).map(|(c,_)| *c).unwrap_or(0);
                    let _ = event_tx.send(ScannerEvent::Error(format!(
                        "[hb] iters={} ch={} dwell={}ms locked={}",
                        loop_iters, cur_ch, last_channel_hop.elapsed().as_millis(), locked
                    )));
                    loop_iters = 0;
                    last_heartbeat = Instant::now();
                }

                // ── Collect hop-worker result (non-blocking) ──────────────────
                if let Ok(result) = hop_rx.try_recv() {
                    if locked {
                        // A lock command arrived while the hop was in flight —
                        // discard the result, the channel is already set synchronously.
                        hop_pending = false;
                    } else {
                        match result {
                            Ok((ch, band)) => {
                                // Successful channel change.
                                failed_channels.remove(&(ch, band));
                                last_successful_hop = Instant::now();
                                let _ = event_tx.send(ScannerEvent::Error(format!(
                                    "[hop] ch{} OK (worker)", ch
                                )));
                                let _ = event_tx.send(ScannerEvent::ChannelChanged { channel: ch, band });
                                last_channel_hop = Instant::now();
                                hop_pending = false;
                                hop_attempts = 0;
                            }
                            Err(e) => {
                                // The channel failed — log it and optionally retry.
                                let (ch, band) = scan_channels[channel_idx];
                                let _ = event_tx.send(ScannerEvent::Error(format!(
                                    "[hop] ch{} FAIL (worker): {}", ch, e
                                )));
                                if failed_channels.insert((ch, band)) {
                                    let _ = event_tx.send(ScannerEvent::Error(format!(
                                        "Channel ch{} ({}) unavailable: {}", ch, band.label(), e
                                    )));
                                }
                                hop_attempts += 1;
                                let max_attempts = MAX_HOP_ATTEMPTS.min(scan_channels.len());
                                if hop_attempts < max_attempts && !scan_channels.is_empty() {
                                    // Dispatch the next candidate immediately.
                                    channel_idx = (channel_idx + 1) % scan_channels.len();
                                    let (next_ch, next_band) = scan_channels[channel_idx];
                                    // try_send won't block (bounded channel, worker is idle).
                                    let _ = hop_tx.try_send((next_ch, next_band));
                                    // hop_pending stays true
                                } else {
                                    // All retries exhausted — surface stall warning if needed.
                                    if last_successful_hop.elapsed() > Duration::from_secs(5) {
                                        let _ = event_tx.send(ScannerEvent::Error(format!(
                                            "Channel hop stalled: no usable channel in last {} attempts ({}s since last hop)",
                                            max_attempts,
                                            last_successful_hop.elapsed().as_secs(),
                                        )));
                                        last_successful_hop = Instant::now();
                                    }
                                    last_channel_hop = Instant::now();
                                    hop_pending = false;
                                    hop_attempts = 0;
                                }
                            }
                        }
                    }
                }

                // Drain scanner commands
                while let Ok(cmd) = cmd_rx.try_recv() {
                    match cmd {
                        ScannerCommand::LockChannel(ch, band) => {
                            let _ = event_tx.send(ScannerEvent::Error(format!(
                                "[dbg] LOCK ch{} (locked was {})", ch, locked
                            )));
                            // LockChannel is infrequent and needs immediate confirmation,
                            // so we call set_channel synchronously here. Any in-flight
                            // hop-worker result will be discarded (locked=true above).
                            match set_channel(&iface, ch, band) {
                                Ok(()) => {
                                    let _ = event_tx.send(ScannerEvent::ChannelChanged { channel: ch, band });
                                    locked = true;
                                    sweep_mac = None;
                                    last_channel_hop = Instant::now();
                                    // Mark pending=false so the discarded result (if any)
                                    // is handled by the locked branch above.
                                    hop_pending = false;
                                }
                                Err(e) => {
                                    // Don't lock on failure — keeps the scanner hopping rather
                                    // than parking on a channel it can't tune to (e.g. a
                                    // persisted AP whose band was misclassified, 2627 MHz).
                                    let _ = event_tx.send(ScannerEvent::Error(format!(
                                        "Channel lock failed ch{} ({}): {}", ch, band.label(), e
                                    )));
                                }
                            }
                        }
                        ScannerCommand::FreeHop => {
                            locked = false;
                            sweep_mac = None;
                        }
                        ScannerCommand::SweepFor { client_mac } => {
                            sweep_mac = Some(client_mac);
                            locked = false;
                        }
                        ScannerCommand::UpdateBands { band_2ghz, band_5ghz, band_6ghz } => {
                            band_2ghz_en = band_2ghz;
                            band_5ghz_en = band_5ghz;
                            band_6ghz_en = band_6ghz;
                            scan_channels = scan_channels_for(supports_5ghz, supports_6ghz, band_2ghz_en, band_5ghz_en, band_6ghz_en);
                            channel_idx = 0;
                        }
                    }
                }

                // ── Channel-hop timer ─────────────────────────────────────────
                // Only fires if no hop is currently in flight (!hop_pending) and
                // we are not locked to a channel. The actual set_channel call
                // happens in the hop-worker thread — this block just dispatches
                // the request and logs the intent.
                if !locked
                    && !hop_pending
                    && last_channel_hop.elapsed() >= Duration::from_millis(CHANNEL_HOP_MS)
                    && !scan_channels.is_empty()
                {
                    let dwell_ms = last_channel_hop.elapsed().as_millis();
                    let cur_ch = scan_channels.get(channel_idx).map(|(c,_)| *c).unwrap_or(0);
                    let _ = event_tx.send(ScannerEvent::Error(format!(
                        "[hop] firing dwell={}ms cur=ch{}", dwell_ms, cur_ch
                    )));
                    // Advance to the next candidate and dispatch to the worker.
                    hop_attempts = 0;
                    channel_idx = (channel_idx + 1) % scan_channels.len();
                    let (ch, band) = scan_channels[channel_idx];
                    // try_send: the channel has capacity 1 and the worker is idle
                    // (hop_pending was false). If somehow full, fall back to
                    // resetting the timer so we retry next tick.
                    if hop_tx.try_send((ch, band)).is_ok() {
                        hop_pending = true;
                        // last_channel_hop is reset only when the result arrives
                        // (success) or all retries are exhausted.
                    } else {
                        last_channel_hop = Instant::now();
                    }
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
                                if let Some(clients) = client_map.get(&bssid) {
                                    existing.clients = clients.values().cloned().collect();
                                }
                                let _ = event_tx.send(ScannerEvent::ApUpdated(existing.clone()));
                            } else {
                                let mut new_ap = ap;
                                new_ap.packets = 1;
                                new_ap.clients = Vec::new();
                                let bssid2 = new_ap.bssid.clone();
                                let _ = event_tx.send(ScannerEvent::ApDiscovered(new_ap.clone()));
                                ap_map.insert(bssid2, new_ap);
                            }
                            // Fall through to parse_client_frame_raw:
                            // beacons (subtype 8) → _ => None (no-op);
                            // probe responses (subtype 5) → extracts client MAC from Addr1.
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
                    Err(pcap::Error::TimeoutExpired) | Err(pcap::Error::NoMorePackets) => {
                        // Non-blocking: no packet queued — sleep briefly to avoid busy-spin.
                        std::thread::sleep(Duration::from_millis(1));
                    }
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

/// Tune a monitor interface to `channel` on `band`, reporting failure.
///
/// Surfaces a rejected tune as an error the caller can log instead of vanishing
/// — e.g. `iw set freq` refused because the active regulatory domain doesn't
/// permit that channel (the trap that hid 5 GHz UNII-1 under a bad regdomain).
///
/// Spawned with a hard timeout rather than a plain `output()`: a wedged `iw`
/// (driver in a bad state, channel mid-CAC, etc.) would otherwise block the
/// scanner thread indefinitely. On timeout we kill the child and report it as a
/// normal failure so the hop loop just skips the channel and moves on.
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
fn set_channel(iface: &str, channel: u8, band: Band) -> Result<()> {
    const TUNE_TIMEOUT: Duration = Duration::from_millis(150);
    let freq = channel_to_freq_mhz(channel, band);
    let mut child = std::process::Command::new("iw")
        .args(["dev", iface, "set", "freq", &freq.to_string()])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context(format!("Failed to run iw for freq {} MHz on {}", freq, iface))?;

    let deadline = Instant::now() + TUNE_TIMEOUT;
    loop {
        match child.try_wait().context("iw try_wait failed")? {
            Some(status) => {
                if status.success() {
                    return Ok(());
                }
                // Child has exited, so reading the piped stderr won't block.
                let mut stderr = String::new();
                if let Some(mut e) = child.stderr.take() {
                    use std::io::Read;
                    let _ = e.read_to_string(&mut stderr);
                }
                anyhow::bail!(
                    "iw set freq {} MHz (ch {}) rejected: {}",
                    freq,
                    channel,
                    stderr.trim()
                );
            }
            None => {
                if Instant::now() >= deadline {
                    let _ = child.kill();
                    // Do NOT call child.wait() here — iw may be in kernel D-state
                    // (uninterruptible sleep waiting for the driver to ack the freq
                    // change). wait() would block the scanner thread for seconds.
                    // Spawn a reaper so the zombie is cleaned up without blocking.
                    std::thread::spawn(move || { let _ = child.wait(); });
                    anyhow::bail!(
                        "iw set freq {} MHz (ch {}) timed out after {}ms",
                        freq,
                        channel,
                        TUNE_TIMEOUT.as_millis()
                    );
                }
                std::thread::sleep(Duration::from_millis(5));
            }
        }
    }
}

/// Open pcap capture with filter for all management frames
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
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

    // Switch to non-blocking mode so next_packet() never hangs in poll().
    // On some drivers, after iw set freq the ring buffer fd stops responding
    // to poll() until the hardware finishes tuning, causing an indefinite
    // block that no timeout value can fix. Non-blocking returns NoMorePackets
    // instantly when nothing is queued; the main loop sleeps 1 ms to avoid
    // busy-spinning.
    let cap = cap.setnonblock().context("Failed to set pcap nonblocking")?;

    Ok(cap)
}

/// Open a new per-session handshake capture file under ~/.smartdos/handshakes/.
/// Returns the writer and its display path.
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
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

/// Make a raw 802.11 SSID safe to render in the TUI.
///
/// SSIDs are arbitrary 0–32 byte blobs and routinely contain control
/// characters (CR/LF/TAB/ESC/NUL, ANSI escapes). Written verbatim into a
/// terminal cell those bytes move the cursor — CR jumps to column 0, LF
/// drops a line, TAB hops a tab stop — which shatters the AP-list column
/// layout and can make a row's name appear to vanish. Replace every control
/// char with a visible '.' so the string occupies exactly the width it shows.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn sanitize_ssid(raw: &str) -> String {
    raw.chars()
        .map(|c| if c.is_control() { '.' } else { c })
        .collect()
}

/// Parse a beacon or probe response frame → returns AP info
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
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
    let mut ht_channel: u8 = 0; // HT Operation IE (tag 61) primary channel — present on 5GHz when tag 3 is absent
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
                    ssid = sanitize_ssid(&String::from_utf8_lossy(tag_value));
                } else {
                    ssid = "<Hidden>".to_string();
                }
            }
            3 => {
                if tag_length >= 1 {
                    channel = tag_value[0];
                }
            }
            61 => {
                // HT Operation: first byte is primary channel — reliable on 5GHz
                if tag_length >= 1 {
                    ht_channel = tag_value[0];
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

    // Determine band and channel.
    // Priority: radiotap frequency > DS Parameter Set (tag 3) > HT Operation (tag 61).
    // 5GHz APs often omit tag 3; WiFi 6 APs sometimes omit both — fall back to radiotap.
    let radiotap_freq = parse_radiotap_freq(data);
    // Channel: prefer tag 3 / tag 61 IEs; fall back to frequency→channel conversion.
    // Compute before band so the cross-validation below can use effective_channel.
    let effective_channel = if channel != 0 {
        channel
    } else if ht_channel != 0 {
        ht_channel
    } else {
        radiotap_freq.map(freq_to_channel).unwrap_or(0)
    };
    // Band: only trust radiotap_freq when it's in a recognised range — garbage
    // values (e.g. 2627 from a mis-parsed present-word) map to TwoGHz via the
    // freq_to_band fallback and would misclassify 5 GHz APs (iPhone ch 44 → 2627).
    // If radiotap is absent or out-of-range, infer from the IE-derived channel:
    // any channel > 14 must be 5 GHz; <= 14 is 2.4 GHz.
    let band = radiotap_freq
        .filter(|&f| matches!(f, 2412..=2484 | 5180..=5825 | 5925..=7125))
        .map(freq_to_band)
        .unwrap_or_else(|| band_from_channel(effective_channel));

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
        channel: effective_channel,
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
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
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
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
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
#[cfg(all(not(feature = "demo"), target_os = "linux"))]
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
        // AP→Client management responses: Addr1=DA=client, Addr2=SA=AP BSSID
        // These are the highest-volume client-bearing frames in any environment:
        //   1 = Association Response, 3 = Reassociation Response
        //   5 = Probe Response (sent by AP for every directed or broadcast probe)
        (0, 1) | (0, 3) => {
            if !is_group_mac(&da) && !sa.starts_with("00:00:00") && sa != "ff:ff:ff:ff:ff:ff" {
                Some((sa, Client { mac: da, signal_dbm, packets: 1, last_seen: Instant::now(), associated: true, friendly_name: None }))
            } else { None }
        }
        (0, 5) => {
            // Probe Response: client is probing, not yet associated
            if !is_group_mac(&da) && !sa.starts_with("00:00:00") && sa != "ff:ff:ff:ff:ff:ff" {
                Some((sa, Client { mac: da, signal_dbm, packets: 1, last_seen: Instant::now(), associated: false, friendly_name: None }))
            } else { None }
        }
        // Deauthentication / Disassociation sent by AP to client:
        //   Addr1=DA=client, Addr2=SA=AP BSSID. Mark not-associated.
        (0, 10) | (0, 12) => {
            if !is_group_mac(&da) && !sa.starts_with("00:00:00") && sa != "ff:ff:ff:ff:ff:ff" {
                Some((sa, Client { mac: da, signal_dbm, packets: 1, last_seen: Instant::now(), associated: false, friendly_name: None }))
            } else { None }
        }
        // Authentication (subtype 11) — deliberately NOT used for client
        // discovery. Our own AuthDos flood injects auth frames with a fresh
        // spoofed SA every frame; the monitor interface (locked to the target's
        // channel during an attack) captures them and would otherwise register
        // thousands of phantom clients against the target BSSID. A bare auth with
        // no following assoc/data is weak evidence of a real client anyway — a
        // genuine station that authenticates also associates (subtype 0/2) or
        // sends data, so it is still discovered through those paths.
        (0, 11) => None,
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
        // Address layout in 802.11 infrastructure data frames depends on To-DS/From-DS bits:
        //   To-DS=1, From-DS=0: Addr1=BSSID, Addr2=SA(client), Addr3=DA
        //   To-DS=0, From-DS=1: Addr1=DA(client), Addr2=BSSID, Addr3=SA
        (2, _) => {
            let to_ds = (frame_control >> 8) & 1;
            let from_ds = (frame_control >> 9) & 1;
            match (to_ds, from_ds) {
                (1, 0) => {
                    // Client → AP: Addr1=BSSID(da var), Addr2=client(sa var)
                    let actual_bssid = da;
                    let client_mac = sa;
                    if !is_group_mac(&actual_bssid)
                        && !actual_bssid.starts_with("00:00:00")
                        && !is_group_mac(&client_mac)
                    {
                        Some((
                            actual_bssid,
                            Client {
                                mac: client_mac,
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
                (0, 1) => {
                    // AP → Client: Addr1=client(da var), Addr2=BSSID(sa var)
                    let actual_bssid = sa;
                    let client_mac = da;
                    // Addr1 here is the destination, which is frequently a group
                    // address (broadcast/IPv4 mcast 01:00:5e.., IPv6 mcast 33:33..,
                    // STP 01:80:c2..). Those are not clients — reject any address
                    // with the I/G (group) bit set. (The old `!= "ff:ff:ff.."`
                    // check was also a no-op: mac_to_string emits uppercase.)
                    if !is_group_mac(&actual_bssid)
                        && !actual_bssid.starts_with("00:00:00")
                        && !is_group_mac(&client_mac)
                    {
                        Some((
                            actual_bssid,
                            Client {
                                mac: client_mac,
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
                _ => None, // IBSS or WDS — skip
            }
        }
        _ => None,
    }
}

/// Parse radiotap header to get offset and signal, or return (0, 0) for raw 802.11
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_radiotap_offset(data: &[u8]) -> (usize, i16) {
    if data.len() >= 4 && data[0] == 0 && data[1] == 0 {
        let rt_len = u16::from_le_bytes([data[2], data[3]]) as usize;
        if rt_len >= 4 && rt_len <= data.len() {
            let sig = parse_radiotap_signal(data);
            return (rt_len, sig);
        }
    }
    (0, 0)
}

/// Extract channel frequency (MHz) from radiotap Channel field (present bit 3).
/// Mirrors the EXT-word handling from parse_radiotap_signal so multi-word
/// present bitmaps don't make us read a present-word fragment as a frequency.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_radiotap_freq(data: &[u8]) -> Option<u32> {
    if data.len() < 8 || data[0] != 0 || data[1] != 0 {
        return None;
    }
    // Walk all present words so field data starts at the right offset.
    let mut pw_off = 4usize;
    let mut first_present = 0u32;
    let mut found_first = false;
    loop {
        if pw_off + 4 > data.len() { return None; }
        let pw = u32::from_le_bytes([data[pw_off], data[pw_off+1], data[pw_off+2], data[pw_off+3]]);
        if !found_first { first_present = pw; found_first = true; }
        pw_off += 4;
        if pw & (1 << 31) == 0 { break; }
    }
    // Channel (bit 3) is always a first-word field.
    if first_present & (1 << 3) == 0 {
        return None;
    }
    let mut offset = pw_off; // field data begins after all present words
    if first_present & (1 << 0) != 0 { // TSFT: align 8, size 8
        offset = (offset + 7) & !7;
        offset += 8;
    }
    if first_present & (1 << 1) != 0 { offset += 1; } // Flags: u8
    if first_present & (1 << 2) != 0 { offset += 1; } // Rate: u8
    // Channel: align 2, size 4 (freq u16 + flags u16)
    if offset % 2 != 0 { offset += 1; }
    if offset + 2 > data.len() {
        return None;
    }
    let freq = u16::from_le_bytes([data[offset], data[offset + 1]]) as u32;
    if freq > 1000 { Some(freq) } else { None }
}

/// Parse radiotap header to extract antenna signal (dBm).
/// Handles multi-word present bitmaps (EXT bit) and natural field alignment.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn parse_radiotap_signal(data: &[u8]) -> i16 {
    if data.len() < 8 || data[0] != 0 || data[1] != 0 {
        return 0;
    }

    // Collect all present words; each has EXT (bit 31) set if another follows.
    let mut present_words: [u32; 8] = [0; 8];
    let mut num_words = 0usize;
    let mut pw_off = 4usize;
    loop {
        if pw_off + 4 > data.len() || num_words >= 8 {
            return 0;
        }
        let pw = u32::from_le_bytes([data[pw_off], data[pw_off+1], data[pw_off+2], data[pw_off+3]]);
        present_words[num_words] = pw;
        num_words += 1;
        pw_off += 4;
        if pw & (1 << 31) == 0 { break; }
    }

    // Field data begins immediately after all present words.
    let mut field_offset = pw_off;

    for wi in 0..num_words {
        let present = present_words[wi];
        for bit in 0..29u32 { // bits 29/30/31 are NS/EXT control, not fields
            if present & (1 << bit) == 0 { continue; }
            let global_bit = wi as u32 * 32 + bit;
            match global_bit {
                0 => { // TSFT: align 8, size 8
                    field_offset = (field_offset + 7) & !7;
                    field_offset += 8;
                }
                1 => field_offset += 1, // Flags
                2 => field_offset += 1, // Rate
                3 => { // Channel: align 2, size 4
                    field_offset = (field_offset + 1) & !1;
                    field_offset += 4;
                }
                4 => { // FHSS: align 2, size 2
                    field_offset = (field_offset + 1) & !1;
                    field_offset += 2;
                }
                5 => { // Antenna Signal: align 1, size 1
                    if field_offset < data.len() {
                        return data[field_offset] as i8 as i16;
                    }
                    return 0;
                }
                6 => field_offset += 1,  // Antenna Noise
                7 => { // Lock Quality: align 2, size 2
                    field_offset = (field_offset + 1) & !1;
                    field_offset += 2;
                }
                8 => { // TX Attenuation: align 2, size 2
                    field_offset = (field_offset + 1) & !1;
                    field_offset += 2;
                }
                9 => { // DB TX Attenuation: align 2, size 2
                    field_offset = (field_offset + 1) & !1;
                    field_offset += 2;
                }
                10 => field_offset += 1, // TX Power
                11 => field_offset += 1, // Antenna
                12 => field_offset += 1, // DB Antenna Signal
                13 => field_offset += 1, // DB Antenna Noise
                14 => { // RX Flags: align 2, size 2
                    field_offset = (field_offset + 1) & !1;
                    field_offset += 2;
                }
                15 => { // TX Flags: align 2, size 2
                    field_offset = (field_offset + 1) & !1;
                    field_offset += 2;
                }
                16 => field_offset += 1, // RTS Retries
                17 => field_offset += 1, // HW Queue
                18 => field_offset += 3, // RSSI (experimental)
                19 => field_offset += 18, // XChannel
                _  => field_offset += 4,  // unknown
            }
        }
    }

    0
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn mac_to_string(bytes: &[u8]) -> String {
    if bytes.len() < 6 {
        return String::new();
    }
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

/// True if `mac` (formatted "AA:BB:CC:..") is a group/multicast address — the
/// I/G bit (least-significant bit of the first octet) is set. Covers broadcast
/// (FF:..), IPv4 multicast (01:00:5E:..), IPv6 multicast (33:33:..), STP
/// (01:80:C2:..), etc. Case-insensitive; malformed input returns false. Pure +
/// platform-independent so it can be unit-tested on the macOS dev box.
#[allow(dead_code)] // only called from the Linux-gated frame parser
fn is_group_mac(mac: &str) -> bool {
    mac.split(':')
        .next()
        .and_then(|oct| u8::from_str_radix(oct, 16).ok())
        .map(|first| first & 0x01 == 1)
        .unwrap_or(false)
}

#[cfg(test)]
mod group_mac_tests {
    use super::is_group_mac;

    #[test]
    fn rejects_group_and_broadcast() {
        assert!(is_group_mac("FF:FF:FF:FF:FF:FF")); // broadcast
        assert!(is_group_mac("ff:ff:ff:ff:ff:ff")); // case-insensitive
        assert!(is_group_mac("01:00:5E:00:00:FB")); // IPv4 mcast (mDNS)
        assert!(is_group_mac("33:33:00:00:00:FB")); // IPv6 mcast
        assert!(is_group_mac("01:80:C2:00:00:00")); // STP
    }

    #[test]
    fn accepts_unicast() {
        assert!(!is_group_mac("A4:5E:60:11:22:33")); // real vendor unicast
        assert!(!is_group_mac("02:11:22:33:44:55")); // locally-administered unicast (AuthDos spoof shape)
        assert!(!is_group_mac("")); // malformed
        assert!(!is_group_mac("zz")); // garbage
    }
}

#[cfg(test)]
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
    fn sanitize_ssid_replaces_control_chars() {
        // CR/LF/TAB/ESC/NUL would move the terminal cursor and break columns.
        assert_eq!(sanitize_ssid("Home\rXX"), "Home.XX");
        assert_eq!(sanitize_ssid("a\tb"), "a.b");
        assert_eq!(sanitize_ssid("Line\nBreak"), "Line.Break");
        assert_eq!(sanitize_ssid("\x1b[31mred\x1b[0m"), ".[31mred.[0m");
        assert_eq!(sanitize_ssid("nul\0byte"), "nul.byte");
    }

    #[test]
    fn sanitize_ssid_preserves_printable_unicode() {
        // Wide/multibyte glyphs are not control chars — ratatui clips them to
        // the cell, so leave them intact.
        assert_eq!(sanitize_ssid("café-日本語"), "café-日本語");
        assert_eq!(sanitize_ssid("CleanAP"), "CleanAP");
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

    // ── radiotap EXT-bit regression tests ────────────────────────────────────
    // Modern mac80211 drivers emit multi-word present bitmaps (bit 31 = EXT).
    // Before the fix, parse_radiotap_signal/freq used offset=8 as the start of
    // field data regardless of how many present words preceded it, so they read
    // present-word bytes as signal/frequency — producing garbage like 2627 MHz.

    #[test]
    fn radiotap_signal_ext_word_field_starts_after_all_present_words() {
        // Two present words: word0 = bit5 (signal) | bit31 (EXT), word1 = 0.
        // Field data starts at byte 12 (after both present words), not byte 8.
        let signal: u8 = (-70i8) as u8;
        let data: &[u8] = &[
            0x00, 0x00,             // version, pad
            0x0D, 0x00,             // rt_len = 13
            0x20, 0x00, 0x00, 0x80, // present word 0: bit5 | bit31(EXT)
            0x00, 0x00, 0x00, 0x00, // present word 1: empty
            signal,                 // Antenna Signal at byte 12
        ];
        assert_eq!(parse_radiotap_signal(data), -70);
    }

    #[test]
    fn radiotap_freq_single_present_word_returns_channel_freq() {
        // Baseline: one present word, bit3 (Channel) set, field data at byte 8.
        // freq = 2437 MHz (channel 6).
        let data: &[u8] = &[
            0x00, 0x00,             // version, pad
            0x0C, 0x00,             // rt_len = 12
            0x08, 0x00, 0x00, 0x00, // present word 0: bit3 (Channel)
            0x85, 0x09,             // freq = 0x0985 = 2437 MHz (LE)
            0xA0, 0x00,             // channel flags
        ];
        assert_eq!(parse_radiotap_freq(data), Some(2437));
    }

    #[test]
    fn radiotap_freq_ext_word_reads_field_after_all_present_words() {
        // Two present words: word0 = bit3 (Channel) | bit31 (EXT), word1 = 0.
        // Field data starts at byte 12.  freq = 5180 MHz (channel 36).
        let data: &[u8] = &[
            0x00, 0x00,             // version, pad
            0x10, 0x00,             // rt_len = 16
            0x08, 0x00, 0x00, 0x80, // present word 0: bit3 | bit31(EXT)
            0x00, 0x00, 0x00, 0x00, // present word 1: empty
            0x3C, 0x14,             // freq = 0x143C = 5180 MHz (LE)
            0x00, 0x01,             // channel flags
        ];
        assert_eq!(parse_radiotap_freq(data), Some(5180));
    }

    #[test]
    fn radiotap_freq_ext_bit_does_not_return_2627_regression() {
        // Regression: with EXT bit set, the second present word happened to
        // decode as 2627 MHz (0x0A43 LE) if the old code read bytes [8..10].
        // New code must read bytes [12..14] and return the real frequency.
        let data: &[u8] = &[
            0x00, 0x00,             // version, pad
            0x10, 0x00,             // rt_len = 16
            0x08, 0x00, 0x00, 0x80, // present word 0: bit3 | bit31(EXT)
            0x43, 0x0A, 0x00, 0x00, // present word 1: bytes [8..10] = 0x0A43 = 2627 (old bug)
            0x71, 0x16,             // real freq = 0x1671 = 5745 MHz (LE)
            0x00, 0x01,             // channel flags
        ];
        let freq = parse_radiotap_freq(data);
        assert_ne!(freq, Some(2627), "must not decode present-word bytes as frequency");
        assert_eq!(freq, Some(5745));
    }

    #[test]
    fn radiotap_freq_tsft_alignment_with_ext_word() {
        // TSFT (bit 0) needs 8-byte alignment.  With two present words the field
        // data starts at byte 12, which is not 8-byte aligned — 4 bytes of
        // implicit padding bring TSFT to byte 16, then Channel lands at byte 24.
        let mut data = vec![
            0x00, 0x00,             // version, pad
            0x1C, 0x00,             // rt_len = 28
            0x09, 0x00, 0x00, 0x80, // present word 0: bit0 (TSFT) | bit3 (Channel) | bit31 (EXT)
            0x00, 0x00, 0x00, 0x00, // present word 1: empty
            // byte 12: field data start; TSFT needs align-8 → pad to byte 16
            0x00, 0x00, 0x00, 0x00, // alignment padding
            // TSFT: 8 bytes at byte 16
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            // Channel: byte 24 (already 2-byte aligned)
            0x9E, 0x09,             // freq = 0x099E = 2462 MHz (ch11, LE)
            0x00, 0x00,             // channel flags
        ];
        assert_eq!(data.len(), 28);
        assert_eq!(parse_radiotap_freq(&data), Some(2462));
        // Corrupt the TSFT region to prove the parser isn't accidentally reading it
        for b in &mut data[16..24] { *b = 0xFF; }
        assert_eq!(parse_radiotap_freq(&data), Some(2462));
    }
}

// ── Demo implementation (--features demo or non-Linux) ───────────────────────

/// Fake AP data: (bssid, ssid, channel, signal_dbm, encryption, band)
#[cfg(any(feature = "demo", not(target_os = "linux")))]
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
#[cfg(any(feature = "demo", not(target_os = "linux")))]
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

#[cfg(any(feature = "demo", not(target_os = "linux")))]
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

#[cfg(any(feature = "demo", not(target_os = "linux")))]
fn start_scanner_demo(
    event_tx: mpsc::Sender<ScannerEvent>,
    running: Arc<AtomicBool>,
    supports_5ghz: bool,
    supports_6ghz: bool,
) -> Result<std::thread::JoinHandle<()>> {
    let handle = std::thread::Builder::new()
        .name("scanner-demo".into())
        .spawn(move || {
            let _ = event_tx.send(ScannerEvent::Error(
                "[DEMO] Scanner started — using fake data".into(),
            ));

            let scan_channels = scan_channels_for(supports_5ghz, supports_6ghz, true, true, true);

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

            // Build per-AP client list (owned keys so clients can move between APs)
            let mut ap_clients: std::collections::HashMap<String, Vec<Client>> =
                std::collections::HashMap::new();
            for (ap_bssid, mac, dbm, assoc) in FAKE_CLIENTS {
                ap_clients.entry(ap_bssid.to_string()).or_default().push(Client {
                    mac: mac.to_string(),
                    signal_dbm: *dbm,
                    packets: 1,
                    last_seen: Instant::now(),
                    associated: *assoc,
                    friendly_name: None,
                });
            }

            // Track mutable channel per simulated AP (band steering can shift these)
            let mut ap_channels: std::collections::HashMap<String, u8> =
                FAKE_APS.iter().map(|(bssid, _, ch, _, _, _)| (bssid.to_string(), *ch)).collect();

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
                                ap_bssid: ap_bssid.clone(),
                                client: client.clone(),
                            });
                        }
                    }

                    stub_roam_clients(
                        &mut ap_clients,
                        &mut ap_channels,
                        &event_tx,
                        supports_5ghz,
                        supports_6ghz,
                    );

                    let _ = event_tx.send(ScannerEvent::Traffic(tick * 4 + 1));
                }

                tick += 1;
            }
        })
        .context("Failed to spawn scanner demo thread")?;

    Ok(handle)
}

/// Probabilistic client roaming for the macOS stub.
/// Called once per second. Each client has a ~5% chance of roaming.
/// - 60%: hard roam — client moves to a different simulated AP
/// - 40%: band steer — client's current AP shifts to a different channel
#[cfg(any(feature = "demo", not(target_os = "linux")))]
fn stub_roam_clients(
    ap_clients: &mut std::collections::HashMap<String, Vec<Client>>,
    ap_channels: &mut std::collections::HashMap<String, u8>,
    event_tx: &mpsc::Sender<ScannerEvent>,
    supports_5ghz: bool,
    supports_6ghz: bool,
) {
    use rand::RngExt;
    let mut rng = rand::rng();

    // Collect bssids visible in this scan (filtered to enabled bands)
    let visible_bssids: Vec<String> = FAKE_APS
        .iter()
        .filter(|(_, _, _, _, _, band)| match band {
            Band::FiveGHz => supports_5ghz,
            Band::SixGHz  => supports_6ghz,
            Band::TwoGHz  => true,
        })
        .map(|(bssid, _, _, _, _, _)| bssid.to_string())
        .collect();

    if visible_bssids.len() < 2 {
        return;
    }

    // Collect (bssid, mac) pairs for clients that will roam this tick
    let roam_candidates: Vec<(String, String)> = ap_clients
        .iter()
        .flat_map(|(bssid, clients)| {
            clients.iter().map(move |c| (bssid.clone(), c.mac.clone()))
        })
        .filter(|_| rng.random_bool(0.05))
        .collect();

    for (old_bssid, mac) in roam_candidates {
        let is_hard_roam = rng.random_bool(0.60);

        if is_hard_roam {
            let other_bssids: Vec<&String> = visible_bssids
                .iter()
                .filter(|b| *b != &old_bssid)
                .collect();
            if other_bssids.is_empty() {
                continue;
            }
            let new_bssid = other_bssids[rng.random_range(0..other_bssids.len())].clone();

            let client_opt = ap_clients
                .get_mut(&old_bssid)
                .and_then(|v| v.iter().position(|c| c.mac == mac).map(|i| v.remove(i)));
            if let Some(mut client) = client_opt {
                client.last_seen = Instant::now();
                client.associated = true;
                let new_ch = ap_channels.get(&new_bssid).copied().unwrap_or(6);
                let _ = event_tx.send(ScannerEvent::ClientDiscovered {
                    ap_bssid: new_bssid.clone(),
                    client: client.clone(),
                });
                let _ = event_tx.send(ScannerEvent::Error(format!(
                    "[stub] {} roamed {}→{} ch{}",
                    mac, old_bssid, new_bssid, new_ch
                )));
                ap_clients.entry(new_bssid).or_default().push(client);
            }
        } else {
            let ap_meta = FAKE_APS.iter().find(|(b, _, _, _, _, _)| *b == old_bssid);
            if let Some((bssid, ssid, base_ch, base_dbm, enc, band)) = ap_meta {
                let skip = match band {
                    Band::FiveGHz => !supports_5ghz,
                    Band::SixGHz  => !supports_6ghz,
                    Band::TwoGHz  => false,
                };
                if skip {
                    continue;
                }
                let old_ch = ap_channels.get(&old_bssid).copied().unwrap_or(*base_ch);
                let new_ch = match band {
                    Band::TwoGHz  => if old_ch == 1 { 6 } else if old_ch == 6 { 11 } else { 1 },
                    Band::FiveGHz => if old_ch == 36 { 40 } else if old_ch == 40 { 44 } else { 36 },
                    Band::SixGHz  => if old_ch == 5 { 37 } else if old_ch == 37 { 69 } else { 5 },
                };
                ap_channels.insert(old_bssid.clone(), new_ch);
                let ap = make_ap(bssid, ssid, new_ch, *base_dbm, enc, *band);
                let _ = event_tx.send(ScannerEvent::ApUpdated(ap));
                let _ = event_tx.send(ScannerEvent::Error(format!(
                    "[stub] {} band-steered ch{}→ch{}",
                    old_bssid, old_ch, new_ch
                )));
            }
        }
    }
}

#[cfg(any(feature = "demo", not(target_os = "linux")))]
pub fn start_scanner(
    _iface: &str,
    event_tx: mpsc::Sender<ScannerEvent>,
    _cmd_rx: mpsc::Receiver<ScannerCommand>,
    running: Arc<AtomicBool>,
    supports_5ghz: bool,
    supports_6ghz: bool,
    _band_2ghz_enabled: bool,
    _band_5ghz_enabled: bool,
    _band_6ghz_enabled: bool,
) -> Result<std::thread::JoinHandle<()>> {
    start_scanner_demo(event_tx, running, supports_5ghz, supports_6ghz)
}
