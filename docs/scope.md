# Scope

## Goal

Turn what attackers do to an SSH honeypot into explainable, sanitized threat
intelligence:

- a private analysis database (PostgreSQL)
- a public, aggregated summary shown on my portfolio site
- written analysis of what the data shows

The sensor is disposable. The data and the analysis are the product.

## Design principles

- **Zero cost.** Every component runs on a free tier or on hardware I already
  own. Nothing can bill without my knowledge: no paid APIs, no pay-as-you-go
  accounts.
- **Contain the honeypot.** Attackers reach only Cowrie's emulated shell.
  The sensor can't be used to attack anyone else: all egress is blocked and SSH
  forwarding is off.
- **Pull, don't push.** The private side pulls logs from the sensor, so the
  sensor holds no credentials and ingestion isn't exposed to the internet.
- **Publish aggregates only.** No IPs, commands, URLs or raw payloads leave the
  private database (see [threat-model.md](threat-model.md)).
- **Explainable labels.** Behaviour labels come from readable rules with an
  evidence sentence each, mapped to MITRE ATT&CK only where the mapping is clear.

## Components

| Component | Runs on | Code |
|---|---|---|
| Sensor: Cowrie SSH honeypot | Any small Ubuntu 24.04 VM (sized for free cloud tiers) | `infrastructure/sensor/` |
| Parser, loader, dedup | Private machine, Python | `collector/parser.py`, `collector/loader.py` |
| Analysis database | PostgreSQL in Docker | `collector/schema.sql` |
| Behaviour rules | YAML, applied by the classifier | `rules/`, `collector/classifier.py` |
| Public summary | Static `summary.json`, published with the portfolio site | `collector/export.py` |
| Public dataset import | Same pipeline as the sensor | `collector/datasets.py` |
| Live layer | GitHub Actions, daily; publishes to the `data` branch | `collector/dshield.py`, `.github/workflows/dshield-live.yml` |

The public summary is a static file rather than a live API: it's delayed and
aggregated anyway, so there's no server to host, rate-limit or protect.

## Data sources

- **Own sensor:** Cowrie JSON logs pulled from the VM.
- **Public datasets:** the CyberLab honeynet dataset (CC BY 4.0). It runs through
  the same pipeline and is labelled as such wherever it's shown.
- **Live feed:** SANS Internet Storm Center / DShield daily aggregates
  (CC BY-NC-SA 4.0): SSH attack volume, most attacked ports, and a username
  ranking. No IP addresses are fetched.

## In scope

- Cowrie SSH on port 22 (redirected to 2222 on the sensor).
- Deny-by-default network: inbound 22 (honeypot) and admin SSH on a private
  port allowlisted to my IP; all egress blocked except during maintenance windows.
- Parsing, deduplication and a normalized PostgreSQL schema.
- Rule-based behaviour labels mapped to MITRE ATT&CK.
- A sanitized public summary.

## Out of scope

- Downloading or executing malware (egress is blocked; URLs are recorded only).
- High-interaction honeypots or real shells.
- Attribution to countries, groups or people.
- Hacking back, contacting attackers, or scanning attacker infrastructure.
- Hosting the sensor on a home network (it would expose the home IP and LAN).
- Paid services of any kind.
