use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::types::{Band, Target};

fn smartdos_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    PathBuf::from(home).join(".smartdos")
}

fn lists_dir() -> PathBuf {
    smartdos_dir().join("lists")
}

fn client_names_path() -> PathBuf {
    smartdos_dir().join("client_names.json")
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SavedListType {
    Aps,
    Clients,
}

#[derive(Serialize, Deserialize)]
struct SavedListEntry {
    bssid: String,
    ssid: String,
    channel: u8,
    band: Option<Band>,
    mac: Option<String>,
    friendly_name: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct SavedList {
    list_type: SavedListType,
    entries: Vec<SavedListEntry>,
}

pub enum LoadedList {
    Aps(Vec<Target>),
    /// (mac, last_known_ap_bssid, friendly_name)
    Clients(Vec<(String, Option<String>, Option<String>)>),
}

pub fn save_ap_list_named(name: &str, targets: &[Target]) -> Result<()> {
    let dir = lists_dir();
    std::fs::create_dir_all(&dir)?;
    let entries = targets
        .iter()
        .map(|t| SavedListEntry {
            bssid: t.bssid.clone(),
            ssid: t.ssid.clone(),
            channel: t.channel,
            band: Some(t.band),
            mac: None,
            friendly_name: None,
        })
        .collect();
    let list = SavedList { list_type: SavedListType::Aps, entries };
    let json = serde_json::to_string_pretty(&list)?;
    std::fs::write(dir.join(format!("{}.json", name)), json)?;
    Ok(())
}

pub fn save_client_list_named(
    name: &str,
    followed: &[(String, Option<String>)],
    client_names: &HashMap<String, String>,
) -> Result<()> {
    let dir = lists_dir();
    std::fs::create_dir_all(&dir)?;
    let entries = followed
        .iter()
        .map(|(mac, maybe_ap)| SavedListEntry {
            bssid: maybe_ap.clone().unwrap_or_default(),
            ssid: String::new(),
            channel: 0,
            band: None,
            mac: Some(mac.clone()),
            friendly_name: client_names.get(mac).cloned(),
        })
        .collect();
    let list = SavedList { list_type: SavedListType::Clients, entries };
    let json = serde_json::to_string_pretty(&list)?;
    std::fs::write(dir.join(format!("{}.json", name)), json)?;
    Ok(())
}

pub fn load_saved_list(name: &str) -> Result<LoadedList> {
    let path = lists_dir().join(format!("{}.json", name));
    let data = std::fs::read_to_string(path)?;
    let list: SavedList = serde_json::from_str(&data)?;
    match list.list_type {
        SavedListType::Aps => {
            let targets = list
                .entries
                .into_iter()
                .map(|e| {
                    let band = e.band.unwrap_or(if e.channel > 14 {
                        Band::FiveGHz
                    } else {
                        Band::TwoGHz
                    });
                    Target {
                        bssid: e.bssid,
                        ssid: e.ssid,
                        band,
                        channel: e.channel,
                        active: true,
                        deauth_count: 0,
                        disconnect_count: 0,
                        client_filter: vec![],
                        follow_managed: false,
                    }
                })
                .collect();
            Ok(LoadedList::Aps(targets))
        }
        SavedListType::Clients => {
            let clients = list
                .entries
                .into_iter()
                .filter_map(|e| {
                    e.mac.map(|mac| {
                        let ap = if e.bssid.is_empty() { None } else { Some(e.bssid) };
                        (mac, ap, e.friendly_name)
                    })
                })
                .collect();
            Ok(LoadedList::Clients(clients))
        }
    }
}

pub fn list_slots() -> Vec<String> {
    let dir = lists_dir();
    match std::fs::read_dir(&dir) {
        Ok(entries) => {
            let mut slots: Vec<String> = entries
                .filter_map(|e| e.ok())
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().to_string();
                    if name.ends_with(".json") {
                        Some(name[..name.len() - 5].to_string())
                    } else {
                        None
                    }
                })
                .collect();
            slots.sort();
            slots
        }
        Err(_) => Vec::new(),
    }
}

pub fn save_client_names(names: &HashMap<String, String>) -> Result<()> {
    let dir = smartdos_dir();
    std::fs::create_dir_all(&dir)?;
    let json = serde_json::to_string_pretty(names)?;
    std::fs::write(client_names_path(), json)?;
    Ok(())
}

pub fn load_client_names() -> HashMap<String, String> {
    let data = match std::fs::read_to_string(client_names_path()) {
        Ok(d) => d,
        Err(_) => return HashMap::new(),
    };
    serde_json::from_str(&data).unwrap_or_default()
}
