# smartdos vs airgeddon — Capability Comparison

> Reference: [airgeddon](https://github.com/v1s1t0r1sh3r3/airgeddon) (~14,000+ line bash framework)
> Scope: wireless pentest / audit tooling

---

## TL;DR

smartdos = focused Rust TUI deauth tool. airgeddon = full-spectrum bash framework wrapping 30+ external tools. They overlap only on the DoS/deauth layer. smartdos wins on: self-contained binary, TUI real-time AP/client tracking, no dependency hell. airgeddon wins on: breadth (handshake, PMKID, WPS, evil twin, enterprise, WEP, WPA3 downgrade).

---

## DoS / Deauth Comparison

| Attack Type | smartdos | airgeddon | Notes |
|---|---|---|---|
| Broadcast deauth (aireplay) | ✓ native pcap | ✓ aireplay-ng | smartdos does it natively in Rust, no aireplay-ng dep |
| Targeted client deauth | ✓ | ✓ | |
| MDK deauth (`mdk4 d`) | ✗ | ✓ | MDK can be more aggressive / harder to block |
| Auth DoS (`mdk4 a`) | ✓ native pcap | ✓ aireplay-ng | smartdos crafts 802.11 auth frames natively |
| Beacon flood (`mdk4 b`) | ✓ native pcap | ✓ mdk4 | smartdos injects random SSID/BSSID beacons natively |
| WDS confusion (`mdk4 w`) | ✗ | ✗ weak | Legacy WDS attack |
| Michael shutdown (`mdk4 m`) | ✗ | ✓ | TKIP-specific DoS |
| DoS pursuit mode | ✓ | ✓ | smartdos follows AP channel hops in real time |
| Multi-target parallel | ✓ | ✗ | smartdos advantage |
| Round-robin multi-target | ✓ | ✗ | smartdos advantage |
| Real-time AP/client TUI | ✓ | ✗ | smartdos advantage — airgeddon is menu-driven |
| Client roaming auto-follow | ✓ | ✗ | smartdos advantage |

---

## Band / Channel Support

| Feature | smartdos | airgeddon |
|---|---|---|
| 2.4GHz (ch 1-14) | ✓ ch 1-13 | ✓ |
| 5GHz | ✓ ch 36-165 + DFS | ✓ ch 36-165 + DFS |
| 6GHz | ✗ | ✓ |
| Per-interface band detection | ✗ | ✓ iw phy check |
| Channel hop scope | 2.4GHz + 5GHz | all supported bands |

---

## Handshake / PMKID

| Feature | smartdos | airgeddon |
|---|---|---|
| WPA handshake capture | ✗ | ✓ airodump-ng + deauth trigger |
| PMKID capture | ✗ | ✓ hcxdumptool |
| Decloak hidden SSID via DoS | ✗ | ✓ |
| .cap → hashcat format convert | ✗ | ✓ hcxtools |
| Crack: aircrack dict | ✗ | ✓ |
| Crack: hashcat dict/bruteforce/rules | ✗ | ✓ |

---

## WPS Attacks

| Feature | smartdos | airgeddon |
|---|---|---|
| PixieWPS (reaver/bully) | ✗ | ✓ |
| PIN bruteforce | ✗ | ✓ |
| PIN database lookup | ✗ | ✓ |
| Custom PIN | ✗ | ✓ |
| Null PIN (reaver) | ✗ | ✓ |
| wash scan for WPS APs | ✗ | ✓ |

---

## Evil Twin / Rogue AP

| Feature | smartdos | airgeddon |
|---|---|---|
| Rogue AP (hostapd) | ✗ | ✓ |
| Captive portal | ✗ | ✓ lighttpd + dnsmasq |
| SSL strip (bettercap) | ✗ | ✓ |
| BeEF hook | ✗ | ✓ |
| Sniffing (ettercap) | ✗ | ✓ |
| Enterprise rogue (hostapd-wpe/mana) | ✗ | ✓ |

---

## Other Attacks

| Feature | smartdos | airgeddon |
|---|---|---|
| WEP (besside-ng / allinone) | ✗ | ✓ |
| WPA3 downgrade | ✗ | ✓ |
| WPA3 DoS | ✗ | ✓ |
| Enterprise 802.1X attacks | ✗ | ✓ asleap/john/hashcat |

---

## Infrastructure / UX

| Feature | smartdos | airgeddon |
|---|---|---|
| Self-contained binary | ✓ single ~900KB | ✗ bash + 30 deps |
| Real-time TUI | ✓ ratatui | ✗ menu-driven |
| Root check | ✓ | ✓ |
| Monitor mode setup | ✓ iw / airmon-ng | ✓ |
| Multi-interface support | ✓ scan+inject NICs | ✓ |
| File logging | ✓ ~/.smartdos/session.log | ✓ |
| Persistent targets | ✓ ~/.smartdos/targets.json | n/a (session) |
| Burst size control | ✓ 1-50 via [ ] keys | ✓ |
| Adaptive burst / rate throttle | ✓ | ✓ |
| Plugin system | ✗ | ✓ |
| Docker support | ✗ | ✓ |

---

## Prioritized Improvement Roadmap

### Implemented ✓

All Tier 1 and Tier 2 items are complete:

| Feature | Status |
|---|---|
| 5GHz support | ✓ |
| Configurable burst size (`[`/`]`, 1-50) | ✓ |
| File logging to `~/.smartdos/session.log` | ✓ |
| Persistent targets (`~/.smartdos/targets.json`) | ✓ |
| Auth DoS (random MAC 802.11 auth flood) | ✓ |
| Beacon flood (random SSID/BSSID injection) | ✓ |
| DoS pursuit mode (follows AP channel hops) | ✓ |
| Multi-interface (separate scan + inject NICs) | ✓ |

### Out of scope for smartdos (by design)

smartdos is a **DoS/disruption testing tool only** — not a credential-capture or cracking tool.

- **WPS attacks** — requires subprocess reaver/bully/pixiewps; outside DoS scope
- **Handshake capture / WPA cracking** — this tool is DoS-only, not credential theft
- **PMKID capture** — same reason
- **Evil twin / captive portal** (hostapd + dhcpd + webserver — different tool category)
- **WEP attacks** (legacy, besside-ng dependency)
- **WPA3 downgrade** (complex protocol handling)
- **Enterprise 802.1X attacks**

---

## External Tool Dependency Comparison

| Category | smartdos deps | airgeddon deps |
|---|---|---|
| Essential | libpcap, iw or airmon-ng | iw, awk, airmon-ng, airodump-ng, aircrack-ng, xterm, ip, lspci, ps |
| Optional | — | aireplay-ng, mdk4, hashcat, hostapd, dhcpd, nft, ettercap, lighttpd, dnsmasq, wash, reaver, bully, pixiewps, bettercap, beef, packetforge-ng, hostapd-wpe, asleap, john, openssl, hcxtools, hcxdumptool, tshark, tcpdump, besside-ng, hostapd-mana |

smartdos advantage: zero optional deps, single binary.
