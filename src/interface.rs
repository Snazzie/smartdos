use anyhow::Result;
#[cfg(target_os = "linux")]
use anyhow::Context;
#[cfg(target_os = "linux")]
use std::process::Command;

use crate::types::{Band, WirelessInterface};
#[cfg(target_os = "linux")]
use crate::types::channel_to_freq_mhz;

// ── Linux implementations ────────────────────────────────────────────────────

/// Discover all wireless interfaces on the system
#[cfg(target_os = "linux")]
pub fn discover_interfaces() -> Result<Vec<WirelessInterface>> {
    let mut interfaces = Vec::new();

    // Try `iw dev` first (modern)
    let output = Command::new("iw")
        .args(["dev"])
        .output()
        .context("Failed to run `iw dev`. Is iw installed?")?;

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let mut current_iface: Option<String> = None;

        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Interface ") {
                let name = trimmed
                    .strip_prefix("Interface ")
                    .unwrap_or("")
                    .trim()
                    .to_string();
                current_iface = Some(name);
            } else if trimmed.starts_with("ifindex ") {
                // skip
            } else if trimmed.starts_with("wdev ") {
                // skip
            } else if trimmed.starts_with("addr ") && current_iface.is_some() {
                // skip
            } else if trimmed.starts_with("ssid ") && current_iface.is_some() {
                // skip
            } else if trimmed.starts_with("type ") && current_iface.is_some() {
                let iface_name = current_iface.take().unwrap();
                let iftype = trimmed.strip_prefix("type ").unwrap_or("").trim();
                // Check if it's a wireless (not P2P, not monitor-only)
                if iftype.contains("managed") || iftype.contains("monitor") || iftype.contains("AP")
                {
                    let is_mon = iftype.contains("monitor");
                    let mon_name = if is_mon {
                        Some(iface_name.clone())
                    } else {
                        // Check if there's a monitor variant
                        get_monitor_name(&iface_name)
                    };

                    interfaces.push(WirelessInterface {
                        name: iface_name.clone(),
                        phy: String::new(), // filled below
                        monitor_name: mon_name,
                        is_monitor: is_mon,
                    });
                }
            } else if trimmed.starts_with("channel ") && current_iface.is_some() {
                // skip
            }
        }
    }

    // Attach phy name using `iw dev` more carefully or `iw phy`
    for iface in &mut interfaces {
        let phy_output = Command::new("iw")
            .args(["dev", &iface.name, "info"])
            .output();
        if let Ok(output) = phy_output {
            if output.status.success() {
                let stdout = String::from_utf8_lossy(&output.stdout);
                for line in stdout.lines() {
                    let t = line.trim();
                    if let Some(phy) = t.strip_prefix("wiphy ") {
                        iface.phy = format!("phy{}", phy.trim());
                    }
                }
            }
        }
    }

    // Fallback: try `airmon-ng` if no interfaces found
    if interfaces.is_empty() {
        let output = Command::new("airmon-ng")
            .output()
            .context("No interfaces via iw and airmon-ng not available")?;
        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            for line in stdout.lines() {
                let trimmed = line.trim();
                // airmon-ng output: PHY	Interface	Driver		Chipset
                // Skip header lines
                if trimmed.starts_with("PHY") || trimmed.starts_with("--") || trimmed.is_empty() {
                    continue;
                }
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    let phy = parts[0].to_string();
                    let name = parts[1].to_string();
                    interfaces.push(WirelessInterface {
                        name,
                        phy,
                        monitor_name: None,
                        is_monitor: false,
                    });
                }
            }
        }
    }

    Ok(interfaces)
}

/// Get monitor mode interface name if one exists
#[cfg(target_os = "linux")]
fn get_monitor_name(iface: &str) -> Option<String> {
    let mon = format!("{}mon", iface);
    // Check if it exists
    let output = Command::new("iw")
        .args(["dev", &mon, "info"])
        .output()
        .ok()?;

    if output.status.success() {
        return Some(mon);
    }

    // Check common alternatives
    for candidate in &[
        format!("mon-{}", iface),
        format!("{}mon", iface),
        format!("{}m", iface),
    ] {
        let out = Command::new("iw")
            .args(["dev", candidate, "info"])
            .output()
            .ok()?;
        if out.status.success() {
            return Some(candidate.clone());
        }
    }

    None
}

/// Enable monitor mode on an interface using `airmon-ng`
#[cfg(target_os = "linux")]
pub fn enable_monitor_mode(iface: &str) -> Result<String> {
    let output = Command::new("airmon-ng")
        .args(["start", iface])
        .output()
        .context(format!("Failed to run airmon-ng start {}", iface))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // airmon-ng typically outputs "monitor mode vif enabled on <name>"
    // Try to parse the monitor interface name
    for line in stdout.lines().chain(stderr.lines()) {
        let trimmed = line.trim();
        // Common patterns:
        // "Enabled monitor mode on wlan0mon"
        // "(monitor mode enabled on mon0)"
        // "monitor mode vif enabled on wlan0mon"
        if let Some(rest) = trimmed
            .to_lowercase()
            .strip_prefix("(monitor mode enabled on ")
        {
            let name = rest.trim_end_matches(')').trim().to_string();
            if !name.is_empty() {
                return Ok(name);
            }
        }
        if let Some(rest) = trimmed.strip_prefix("Enabled monitor mode on ") {
            let name = rest.trim().to_string();
            if !name.is_empty() {
                return Ok(name);
            }
        }
        if let Some(rest) = trimmed
            .to_lowercase()
            .strip_prefix("monitor mode vif enabled on ")
        {
            let name = rest.trim().to_string();
            if !name.is_empty() {
                return Ok(name);
            }
        }
    }

    // If we can't parse it, fallback: check if a mon variant appeared
    let mon_name = format!("{}mon", iface);
    let check = Command::new("iw").args(["dev", &mon_name, "info"]).output();
    if let Ok(out) = check {
        if out.status.success() {
            return Ok(mon_name);
        }
    }

    // If airmon succeeded but we couldn't determine name, try iw directly
    let iw_output = Command::new("iw")
        .args(["dev", iface, "set", "monitor", "none"])
        .output()
        .context("airmon-ng output parse failed and iw set monitor also failed")?;

    if iw_output.status.success() {
        return Ok(iface.to_string());
    }

    Err(anyhow::anyhow!(
        "Could not determine monitor interface name. airmon-ng output:\n{}\n{}",
        stdout.trim(),
        stderr.trim()
    ))
}

/// Disable monitor mode
#[cfg(target_os = "linux")]
pub fn disable_monitor_mode(iface: &str, mon_iface: &str) -> Result<()> {
    // Try airmon-ng stop first
    let _ = Command::new("airmon-ng").args(["stop", mon_iface]).output();

    // Also try iw to delete the monitor interface if it's a separate vif
    let _ = Command::new("iw").args(["dev", mon_iface, "del"]).output();

    // Bring original interface up
    let _ = Command::new("ip")
        .args(["link", "set", iface, "up"])
        .output();

    Ok(())
}

#[cfg(target_os = "linux")]
pub fn discover_interfaces_demo() -> Result<Vec<WirelessInterface>> {
    Ok(vec![WirelessInterface {
        name: "stub0".to_string(),
        phy: "phy0".to_string(),
        monitor_name: Some("stub0mon".to_string()),
        is_monitor: false,
    }])
}

/// Check if running as root (required for monitor mode + packet injection)
#[cfg(target_os = "linux")]
pub fn check_root() -> bool {
    let output = match Command::new("id").arg("-u").output() {
        Ok(o) => o,
        Err(_) => return false,
    };
    let uid = String::from_utf8_lossy(&output.stdout).trim().to_string();
    uid == "0"
}

/// Set channel on monitor interface via frequency — works for 2.4/5/6 GHz.
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn set_channel(mon_iface: &str, channel: u8, band: Band) -> Result<()> {
    let freq = channel_to_freq_mhz(channel, band);
    let out = Command::new("iw")
        .args(["dev", mon_iface, "set", "freq", &freq.to_string()])
        .output()
        .context(format!(
            "Failed to set freq {} MHz (ch {} {:?}) on {}",
            freq, channel, band, mon_iface
        ))?;
    if !out.status.success() {
        anyhow::bail!(
            "iw set freq {} MHz (ch {} {:?}) on {} failed: {}",
            freq, channel, band, mon_iface,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Probe which bands the physical interface supports via `iw phy <phy> channels`.
/// Returns (supports_5ghz, supports_6ghz).
#[cfg(target_os = "linux")]
pub fn detect_band_capabilities(phy: &str) -> (bool, bool) {
    let output = match Command::new("iw").args(["phy", phy, "channels"]).output() {
        Ok(o) => o,
        Err(_) => return (false, false),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut has_5 = false;
    let mut has_6 = false;
    for line in stdout.lines() {
        if let Some(freq_str) = line.trim().split_whitespace().next() {
            if let Ok(mhz) = freq_str.parse::<u32>() {
                if (5180..=5825).contains(&mhz) { has_5 = true; }
                if (5925..=7125).contains(&mhz) { has_6 = true; }
            }
        }
    }
    (has_5, has_6)
}

/// Get the current channel of an interface
#[cfg(target_os = "linux")]
#[allow(dead_code)]
pub fn get_current_channel(iface: &str) -> Result<u8> {
    let output = Command::new("iw")
        .args(["dev", iface, "info"])
        .output()
        .context(format!("Failed to get info for {}", iface))?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let t = line.trim();
        if let Some(ch_str) = t.strip_prefix("channel ") {
            let ch = ch_str.split_whitespace().next().unwrap_or("0");
            if let Ok(ch) = ch.parse::<u8>() {
                return Ok(ch);
            }
        }
    }

    Ok(0)
}

/// Read current TX power from interface info (returns dBm, None if unavailable).
#[cfg(target_os = "linux")]
pub fn get_txpower(iface: &str) -> Option<i32> {
    let output = Command::new("iw").args(["dev", iface, "info"]).output().ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for line in stdout.lines() {
        let t = line.trim();
        if t.starts_with("txpower ") && t.ends_with("dBm") {
            if let Some(val) = t.split_whitespace().nth(1) {
                return val.parse::<f64>().ok().map(|f| f.round() as i32);
            }
        }
    }
    None
}

/// Set TX power on interface. None = auto, Some(dbm) = fixed at dbm dBm.
#[cfg(target_os = "linux")]
pub fn set_txpower(iface: &str, dbm: Option<i32>) -> Result<()> {
    let out = match dbm {
        None => Command::new("iw")
            .args(["dev", iface, "set", "txpower", "auto"])
            .output()
            .context(format!("iw set txpower auto on {} failed", iface))?,
        Some(v) => Command::new("iw")
            .args(["dev", iface, "set", "txpower", "fixed", &(v * 100).to_string()])
            .output()
            .context(format!("iw set txpower {}dBm on {} failed", v, iface))?,
    };
    if !out.status.success() {
        anyhow::bail!(
            "iw set txpower on {} failed: {}",
            iface,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

// ── Stub implementations (non-Linux / macOS dev) ─────────────────────────────

#[cfg(not(target_os = "linux"))]
pub fn discover_interfaces() -> Result<Vec<WirelessInterface>> {
    Ok(vec![])
}

#[cfg(not(target_os = "linux"))]
pub fn discover_interfaces_demo() -> Result<Vec<WirelessInterface>> {
    Ok(vec![WirelessInterface {
        name: "stub0".to_string(),
        phy: "phy0".to_string(),
        monitor_name: Some("stub0mon".to_string()),
        is_monitor: false,
    }])
}

#[cfg(not(target_os = "linux"))]
pub fn enable_monitor_mode(iface: &str) -> Result<String> {
    Ok(format!("{}mon", iface))
}

#[cfg(not(target_os = "linux"))]
pub fn disable_monitor_mode(_iface: &str, _mon_iface: &str) -> Result<()> {
    Ok(())
}

/// Always returns true on non-Linux — skip root check during Mac development
#[cfg(not(target_os = "linux"))]
pub fn check_root() -> bool {
    true
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn set_channel(_mon_iface: &str, _channel: u8, _band: Band) -> Result<()> {
    Ok(())
}

#[cfg(not(target_os = "linux"))]
#[allow(dead_code)]
pub fn get_current_channel(_iface: &str) -> Result<u8> {
    Ok(6)
}

#[cfg(not(target_os = "linux"))]
pub fn detect_band_capabilities(_phy: &str) -> (bool, bool) {
    // Stub: pretend 5 GHz supported, 6 GHz not (safe default for dev)
    (true, false)
}

#[cfg(not(target_os = "linux"))]
pub fn get_txpower(_iface: &str) -> Option<i32> {
    None
}

#[cfg(not(target_os = "linux"))]
pub fn set_txpower(_iface: &str, _dbm: Option<i32>) -> Result<()> {
    Ok(())
}
