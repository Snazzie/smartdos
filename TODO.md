# TODO / Deferred Work

## CSA-Beacon: clone the real captured beacon (higher disconnect rate)

**Status:** deferred.

**Current behaviour:** `build_csa_beacon_frame` (src/attack.rs) synthesizes a
*minimal* beacon for the target — correct BSSID + SSID + DS-param + a
Channel-Switch-Announcement element, but missing the AP's RSN/security IE,
HT/VHT/HE capability IEs, country, TIM, and vendor (WPS/Apple) IEs.

**Problem:** modern clients (iOS especially) cross-check a CSA beacon against the
AP's real beacon. A stripped-down skeleton is easier to flag as suspicious, so
the CSA gets ignored and the client stays connected. Hit rate < 100%.

**Upgrade:** capture the target's *actual* beacon (the scanner already receives
beacons per-BSSID — see scanner.rs beacon dump) and replay it **verbatim with
only the CSA element appended**, producing a byte-faithful clone. This is the
difference between "sometimes works" and "reliably works" against iOS.

**Work required:**
- Plumb the captured raw beacon frame from the scanner thread → attack thread
  (extend `ScannerEvent` / `Target` / `TargetState` to carry the last raw beacon
  bytes for each BSSID).
- In the CSA path, take that raw beacon, strip/replace any existing CSA IE, append
  a fresh CSA element, refresh the sequence number, and inject.
- Fall back to the current synthesized beacon when no captured beacon is available
  yet.
