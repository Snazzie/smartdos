# Harvest Mode Design

## Summary

Mark an AP for "harvest" — any client seen on that AP is automatically added to `followed_clients` and tracked across roams. Existing clients on the AP at time of harvest are backfilled immediately.

## Data

`App.harvested_aps: Vec<String>` — list of BSSIDs currently marked for harvest.

## New Methods (`types.rs`)

### `toggle_ap_harvest(bssid: &str) -> bool`
- If BSSID already in `harvested_aps`: remove it, return `false`
- If not: add it, backfill all current clients of that AP into `followed_clients` (skip dupes), call `rebuild_follow_targets()`, return `true`

### `is_ap_harvested(bssid: &str) -> bool`
- Returns whether BSSID is in `harvested_aps`

## Hook in `app.rs`

In `ClientDiscovered` handler, after existing `maybe_update_follow` call:

```
if harvested_aps contains ap_bssid
    and client.mac not already in followed_clients:
        push (client.mac, Some(ap_bssid)) to followed_clients
        rebuild_follow_targets()
        log "Harvested: <mac> from <SSID>"
```

## Keybinding (`main.rs`)

- `H` on AP list — toggles harvest for selected AP

## UI (`ui.rs`)

- AP list row: show `[H]` badge when AP is harvested (same style as existing target `[T]` indicator)

## Log Messages

- Harvest ON: `"Harvest ON: <SSID> (<N> clients auto-followed)"`
- New client from harvested AP: `"Harvested: <mac> from <SSID>"`
- Harvest OFF: `"Harvest OFF: <SSID>"`

## Scope

Touches: `types.rs`, `app.rs`, `main.rs`, `ui.rs`. No new files.
