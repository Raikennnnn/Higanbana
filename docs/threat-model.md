# Threat model

The honeypot deliberately invites attackers. The goal of this model is to
make sure they can only reach the part built to receive them, and that
nothing built on their data harms anyone else, including the attackers'
victims (many "attacker" IPs are compromised machines).

## Components and trust boundaries

```
 Internet (hostile)
     │  TB1: inbound SSH :22 → Cowrie :2222
     ▼
 ┌───────────── Sensor VM (free cloud tier, untrusted) ──────────────┐
 │  Cowrie (unprivileged, emulated shell)  → JSON logs on disk        │
 │  Real sshd on high port, key-only, allowlisted to my IP            │
 │  Egress: DENY ALL                                                  │
 └────────────────────────────────────────────────────────────────────┘
     ▲  TB2: home PC pulls logs over SSH (read-only user)
     │
 ┌───────────── Home PC (trusted, private) ──────────────────────────┐
 │  Collector → PostgreSQL → Grafana (localhost only)                 │
 │  Enrichment worker ──TB3──► DB-IP/MaxMind files, AbuseIPDB, URLhaus │
 │  Daily export → summary.json (aggregated, delayed, sanitized)      │
 └────────────────────────────────────────────────────────────────────┘
     │  TB4: summary.json published with the portfolio site
     ▼
 Public visitors
```

- **TB1**, internet to sensor: everything crossing it is hostile.
- **TB2**, sensor to home PC: log files are **untrusted input**, because a
  compromised sensor could serve tampered logs.
- **TB3**, home PC to third-party APIs: I send attacker IPs and URLs out; API
  keys live only on the home PC.
- **TB4**, private to public: only allowlisted aggregate fields leave.

## Assets

| Asset | Why it matters |
|---|---|
| Home PC and LAN | My real machine. Must never be reachable from the sensor. |
| Cloud account | Takeover leads to abuse under my name, or a surprise bill if it gets upgraded. |
| Raw logs (IPs, passwords, commands, URLs) | Personal data of (often compromised) third parties; live malware URLs. |
| API keys (AbuseIPDB, URLhaus) | Quota abuse, account bans. |
| My reputation / provider standing | Abuse reports can get the account closed. |
| Public widget integrity | Showing wrong or harmful content on my portfolio. |

## Threats and mitigations

| # | Threat | Boundary | Mitigation | Residual risk |
|---|---|---|---|---|
| T1 | Attacker uses the honeypot as a **proxy** to attack others | TB1 | `[ssh] forwarding = false`; egress deny-all at both the host firewall and the cloud security list | Low |
| T2 | Attacker **escapes Cowrie's emulation** onto the VM | TB1 | Cowrie is a Python emulator, not a real shell; runs as an unprivileged user in a container; VM patched in maintenance windows; nothing of value on the VM | Low, but not zero (Cowrie/Twisted bugs) |
| T3 | Compromised sensor used to **pivot to the home PC** | TB2 | Pull model: the sensor has no credentials to anything and no route home; home PC only makes outbound SSH to it | Low |
| T4 | **Tampered or malicious logs** attack the pipeline | TB2 | Parser does JSON parsing only; line size limit; type checks; parameterized SQL only; bad lines logged and skipped (see `collector/parser.py`, tests) | Low |
| T5 | **Stored XSS / injection** through attacker-controlled strings (usernames, commands) shown in Grafana or the widget | TB2/TB4 | Grafana escapes text by default, and no HTML panels render raw fields; the public widget renders only numbers and allowlisted categorical values via `textContent` | Low |
| T6 | Leaking **real credentials** via "top passwords" | TB4 | A password is only published if ≥20 distinct source IPs tried it | Low |
| T7 | Leaking **victims' IPs / personal data** | TB4 | No raw IPs publicly; country/ASN aggregates only; `_private` columns never exported; 24h delay | Low |
| T8 | Publishing **live malware URLs** | TB4 | URLs are never public; only counts and malware family names from URLhaus | Low |
| T9 | **Honeypot fingerprinting** makes the data less representative | TB1 | Custom hostname/users/banner/filesystem; real values kept out of the public repo | Medium (accepted, documented as a limitation) |
| T10 | **Cloud account takeover** | none | MFA; unique password; account never upgraded from free tier | Low |
| T11 | **Surprise costs** | none | Free-tier accounts only, never upgraded to pay-as-you-go; no paid services or API keys; spending limits where the provider offers them | Low |
| T12 | **Disk exhaustion** (log flooding) takes the sensor down | TB1 | Log rotation + size caps from day 1; container disk limits; pull and prune | Medium (availability only) |
| T13 | **Provider reclaims idle VM** or closes the account after abuse reports | none | Rebuild script; frequent pulls; AUP reviewed; respond to abuse reports within 24h | Medium (accepted) |
| T14 | **API key leak** via the public repo | TB3 | Keys only in `.env` (git-ignored); secret scanning on GitHub | Low |
| T15 | Admin SSH **brute-forced** | TB1 | Key-only, high port, allowlisted source IP at the cloud firewall | Low |

## Data classification

| Class | Examples | Where it may live |
|---|---|---|
| Private | Source IPs, passwords, full command lines, URLs, raw payloads (`*_private` columns) | Sensor disk (short term), home PC database |
| Internal | Per-session labels, enrichment results | Home PC database, Grafana |
| Public | Daily/weekly counts, country/ASN aggregates, top labels, thresholded passwords | `summary.json`, reports, portfolio |

## Kill switch

1. Block inbound 22 at the cloud firewall.
2. Confirm egress is blocked.
3. Pull/snapshot logs.
4. Stop Cowrie.
5. Rotate admin keys.
6. Review logs.
7. Write up what happened.
