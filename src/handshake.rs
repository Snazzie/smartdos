//! WPA handshake / PMKID capture support.
//!
//! Pure, platform-independent helpers:
//! - [`PcapWriter`] writes a standard libpcap file (linktype 127 = radiotap)
//!   that aircrack-ng / hashcat can consume directly.
//! - [`eapol_endpoints`] detects an 802.1X/EAPOL frame inside an 802.11 data
//!   frame and returns `(bssid, station)` so callers can label captures.
//!
//! Kept free of `cfg(target_os)` gates so the logic is unit-tested on every
//! platform; the Linux scanner is the only caller of the capture path.

use std::fs::File;
use std::io::{self, Write};
use std::path::Path;

/// LINKTYPE_IEEE802_11_RADIOTAP — frames are prefixed with a radiotap header.
const LINKTYPE_IEEE802_11_RADIOTAP: u32 = 127;
const PCAP_MAGIC: u32 = 0xa1b2_c3d4;
const SNAPLEN: u32 = 65535;

/// Minimal libpcap-format writer. Produces a file readable by Wireshark,
/// aircrack-ng and hashcat (after `hcxpcapngtool`/`cap2hccapx`).
pub struct PcapWriter {
    file: File,
    bytes: u64,
}

impl PcapWriter {
    /// Create a new pcap file and write the 24-byte global header.
    pub fn create<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let mut file = File::create(path)?;
        file.write_all(&Self::global_header())?;
        Ok(PcapWriter { file, bytes: 24 })
    }

    /// The 24-byte pcap global header for a radiotap-linktype capture.
    fn global_header() -> [u8; 24] {
        let mut h = [0u8; 24];
        h[0..4].copy_from_slice(&PCAP_MAGIC.to_le_bytes());
        h[4..6].copy_from_slice(&2u16.to_le_bytes()); // version major
        h[6..8].copy_from_slice(&4u16.to_le_bytes()); // version minor
        // h[8..12]  thiszone = 0
        // h[12..16] sigfigs  = 0
        h[16..20].copy_from_slice(&SNAPLEN.to_le_bytes());
        h[20..24].copy_from_slice(&LINKTYPE_IEEE802_11_RADIOTAP.to_le_bytes());
        h
    }

    /// Append one captured frame (raw bytes including radiotap header).
    pub fn write_frame(&mut self, ts_sec: u32, ts_usec: u32, data: &[u8]) -> io::Result<()> {
        let mut rec = [0u8; 16];
        rec[0..4].copy_from_slice(&ts_sec.to_le_bytes());
        rec[4..8].copy_from_slice(&ts_usec.to_le_bytes());
        rec[8..12].copy_from_slice(&(data.len() as u32).to_le_bytes()); // incl_len
        rec[12..16].copy_from_slice(&(data.len() as u32).to_le_bytes()); // orig_len
        self.file.write_all(&rec)?;
        self.file.write_all(data)?;
        self.bytes += 16 + data.len() as u64;
        Ok(())
    }

    pub fn bytes_written(&self) -> u64 {
        self.bytes
    }
}

/// Length of the radiotap header at the front of `data`, if present.
fn radiotap_len(data: &[u8]) -> Option<usize> {
    if data.len() >= 4 && data[0] == 0 && data[1] == 0 {
        let len = u16::from_le_bytes([data[2], data[3]]) as usize;
        if (4..=128).contains(&len) && len <= data.len() {
            return Some(len);
        }
    }
    None
}

/// If `data` (radiotap + 802.11) carries an EAPOL (802.1X) payload, return
/// `(bssid, station)` MAC strings. Used to label handshake/PMKID captures.
///
/// EAPOL rides inside an 802.11 *data* frame: after the MAC header (+QoS, +ToDS
/// addr4) comes an LLC/SNAP header `AA AA 03 00 00 00` followed by ethertype
/// `0x888E`.
pub fn eapol_endpoints(data: &[u8]) -> Option<(String, String)> {
    let off = radiotap_len(data).unwrap_or(0);
    let frame = data.get(off..)?;
    if frame.len() < 24 {
        return None;
    }

    let fc = u16::from_le_bytes([frame[0], frame[1]]);
    let ftype = (fc >> 2) & 0x03;
    let subtype = (fc >> 4) & 0x0F;
    if ftype != 2 {
        return None; // not a data frame
    }

    let to_ds = fc & 0x0100 != 0;
    let from_ds = fc & 0x0200 != 0;

    // addr1=DA/RA, addr2=SA/TA, addr3=BSSID (varies with DS bits)
    let addr1 = mac(&frame[4..10]);
    let addr2 = mac(&frame[10..16]);
    let addr3 = mac(&frame[16..22]);

    // BSSID + station depend on the DS direction.
    let (bssid, station) = match (to_ds, from_ds) {
        (true, false) => (addr1, addr2),  // STA → AP
        (false, true) => (addr2, addr1),  // AP → STA
        _ => (addr3, addr2),              // IBSS / WDS — best effort
    };

    // Header length: 24 base, +6 if WDS (4-addr), +2 if QoS data subtype (>=8).
    let mut hdr = 24usize;
    if to_ds && from_ds {
        hdr += 6;
    }
    if subtype & 0x08 != 0 {
        hdr += 2; // QoS control
    }

    let body = frame.get(hdr..)?;
    // LLC/SNAP: AA AA 03 00 00 00, then 2-byte ethertype.
    if body.len() < 8 {
        return None;
    }
    if body[0..6] != [0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00] {
        return None;
    }
    let ethertype = u16::from_be_bytes([body[6], body[7]]);
    if ethertype != 0x888E {
        return None;
    }

    Some((bssid, station))
}

fn mac(bytes: &[u8]) -> String {
    if bytes.len() < 6 {
        return String::new();
    }
    format!(
        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5]
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn global_header_is_well_formed() {
        let h = PcapWriter::global_header();
        assert_eq!(&h[0..4], &PCAP_MAGIC.to_le_bytes());
        assert_eq!(u16::from_le_bytes([h[4], h[5]]), 2);
        assert_eq!(u16::from_le_bytes([h[6], h[7]]), 4);
        assert_eq!(u32::from_le_bytes([h[20], h[21], h[22], h[23]]), 127);
    }

    #[test]
    fn detects_eapol_sta_to_ap() {
        // No radiotap. FC: data frame (type 2), ToDS set.
        let mut f = vec![0u8; 24];
        f[0] = 0x08; // subtype 0 data
        f[1] = 0x01; // ToDS
        // addr1 = AP (DA), addr2 = STA (SA), addr3 = BSSID
        f[4..10].copy_from_slice(&[0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x01]); // AP
        f[10..16].copy_from_slice(&[0xBB, 0xBB, 0xBB, 0x00, 0x00, 0x02]); // STA
        f[16..22].copy_from_slice(&[0xAA, 0xAA, 0xAA, 0x00, 0x00, 0x01]); // BSSID
        // LLC/SNAP + EAPOL ethertype
        f.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        let (bssid, sta) = eapol_endpoints(&f).expect("should detect EAPOL");
        assert_eq!(bssid, "AA:AA:AA:00:00:01");
        assert_eq!(sta, "BB:BB:BB:00:00:02");
    }

    #[test]
    fn ignores_non_eapol_data() {
        let mut f = vec![0u8; 24];
        f[0] = 0x08;
        f[1] = 0x01;
        f.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00]); // IPv4
        assert!(eapol_endpoints(&f).is_none());
    }

    #[test]
    fn ignores_management_frame() {
        let mut f = vec![0u8; 24];
        f[0] = 0x80; // beacon
        assert!(eapol_endpoints(&f).is_none());
    }

    #[test]
    fn qos_data_offset_is_handled() {
        // QoS data (subtype 8) adds 2 bytes before the LLC/SNAP header.
        let mut f = vec![0u8; 26];
        f[0] = 0x88; // QoS data subtype 8
        f[1] = 0x02; // FromDS
        f[4..10].copy_from_slice(&[0xCC, 0, 0, 0, 0, 0x01]); // STA (DA)
        f[10..16].copy_from_slice(&[0xDD, 0, 0, 0, 0, 0x02]); // AP (SA)
        // 2 bytes QoS control already counted in the 26 len
        f.extend_from_slice(&[0xAA, 0xAA, 0x03, 0x00, 0x00, 0x00, 0x88, 0x8E]);
        let (bssid, sta) = eapol_endpoints(&f).expect("QoS EAPOL");
        assert_eq!(bssid, "DD:00:00:00:00:02");
        assert_eq!(sta, "CC:00:00:00:00:01");
    }

    #[test]
    fn writer_counts_bytes() {
        let dir = std::env::temp_dir().join("smartdos_test_hs.pcap");
        let mut w = PcapWriter::create(&dir).unwrap();
        assert_eq!(w.bytes_written(), 24);
        w.write_frame(1, 2, &[0xDE, 0xAD]).unwrap();
        assert_eq!(w.bytes_written(), 24 + 16 + 2);
        let _ = std::fs::remove_file(&dir);
    }
}
