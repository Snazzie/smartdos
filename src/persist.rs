use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::time::Instant;

use crate::types::{AccessPoint, AttackMode, AttackType, Band, DeauthScope, Target};

#[derive(Serialize, Deserialize)]
struct SavedTarget {
    bssid: String,
    ssid: String,
    channel: u8,
}

fn attack_settings_path() -> PathBuf {
    smartdos_dir().join("attack_settings.json")
}

#[derive(Serialize, Deserialize)]
pub struct AttackSettings {
    pub attack_type: AttackType,
    pub attack_mode: AttackMode,
    pub burst_size: u16,
    pub send_interval_ms: u64,
    pub pursuit_mode: bool,
    pub deauth_scope: DeauthScope,
}

pub fn save_attack_settings(settings: &AttackSettings) -> Result<()> {
    let path = attack_settings_path();
    let _ = std::fs::create_dir_all(smartdos_dir());
    std::fs::write(&path, serde_json::to_string_pretty(settings)?)?;
    Ok(())
}

pub fn load_attack_settings() -> Option<AttackSettings> {
    let data = std::fs::read_to_string(attack_settings_path()).ok()?;
    serde_json::from_str(&data).ok()
}

fn smartdos_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".smartdos")
}

fn targets_path() -> PathBuf {
    smartdos_dir().join("targets.json")
}

fn aps_path() -> PathBuf {
    smartdos_dir().join("aps.json")
}

#[derive(Serialize, Deserialize)]
struct SavedAp {
    bssid: String,
    ssid: String,
    band: Band,
    channel: u8,
    signal_dbm: i16,
    encryption: String,
}

pub fn save_ap_list(aps: &[AccessPoint]) -> Result<()> {
    let path = aps_path();
    let _ = std::fs::create_dir_all(path.parent().unwrap());
    let mut seen = std::collections::HashSet::new();
    let saved: Vec<SavedAp> = aps
        .iter()
        .filter(|a| seen.insert(a.bssid.clone()))
        .map(|a| SavedAp {
            bssid: a.bssid.clone(),
            ssid: a.ssid.clone(),
            band: a.band,
            channel: a.channel,
            signal_dbm: a.signal_dbm,
            encryption: a.encryption.clone(),
        })
        .collect();
    let json = serde_json::to_string_pretty(&saved)?;
    std::fs::write(&path, json)?;
    Ok(())
}

pub fn load_ap_list() -> Vec<AccessPoint> {
    let path = aps_path();
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let saved: Vec<SavedAp> = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    let now = Instant::now();
    let mut seen = std::collections::HashSet::new();
    saved
        .into_iter()
        .filter(|s| seen.insert(s.bssid.clone()))
        .map(|s| AccessPoint {
            bssid: s.bssid,
            ssid: s.ssid,
            band: s.band,
            channel: s.channel,
            signal_dbm: s.signal_dbm,
            signal_percent: 0,
            packets: 0,
            last_seen: now,
            encryption: s.encryption,
            clients: Vec::new(),
            traffic_rate: 0.0,
        })
        .collect()
}

pub fn save_targets(targets: &[Target]) -> Result<()> {
    let path = targets_path();
    let _ = std::fs::create_dir_all(smartdos_dir());
    let saved: Vec<SavedTarget> = targets
        .iter()
        .map(|t| SavedTarget {
            bssid: t.bssid.clone(),
            ssid: t.ssid.clone(),
            channel: t.channel,
        })
        .collect();
    let json = serde_json::to_string_pretty(&saved)?;
    std::fs::write(&path, json)?;
    Ok(())
}

pub fn load_targets() -> Vec<Target> {
    let path = targets_path();
    let data = match std::fs::read_to_string(&path) {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let saved: Vec<SavedTarget> = match serde_json::from_str(&data) {
        Ok(v) => v,
        Err(_) => return Vec::new(),
    };
    saved
        .into_iter()
        .map(|s| Target {
            bssid: s.bssid,
            ssid: s.ssid,
            band: if s.channel > 14 { Band::FiveGHz } else { Band::TwoGHz },
            channel: s.channel,
            active: true,
            deauth_count: 0,
            disconnect_count: 0,
            client_filter: vec![],
            follow_managed: false,
        })
        .collect()
}
