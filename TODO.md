# TODO / Deferred Work

## CSA-Beacon: clone the real captured beacon — DONE

Implemented. The scanner now stashes each AP's last raw 802.11 beacon
(`AccessPoint.raw_beacon`, radiotap + trailing FCS stripped via
`radiotap_has_fcs`). It flows AP → `Target` → `TargetState`, and the CSA-Beacon
attack prefers `build_csa_from_beacon` (verbatim clone with a refreshed sequence
number, any stale CSA element stripped, and a fresh CSA inserted at the front of
the IE list). Falls back to the synthesized `build_csa_beacon_frame` when no
beacon has been captured yet.

### Possible follow-ups
- Refresh a live target's `raw_beacon` on every `ApUpdated` (currently captured
  at target-add time; `rebuild_target_states` keeps the previous clone if a later
  update carries none).
- Match the radiotap TX rate/channel of the cloned beacon to the AP's real PHY
  for even closer fidelity.
