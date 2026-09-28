# Higanbana 彼岸花

An SSH honeypot threat-intelligence pipeline: a hardened, isolated Cowrie
sensor, a parser and loader into PostgreSQL, rule-based behaviour labels mapped
to MITRE ATT&CK, and an aggregated, sanitized public summary. Built to run at
**zero cost**.

*Why the name:* Japanese farmers planted red spider lilies (higanbana) along
rice fields and graves because their bulbs are poisonous. The bright border
invites pests in and protects what lies behind it, the way a honeypot does.

> Status: the pipeline runs end to end on a **public honeynet dataset** (below).
> The hardened sensor is built and firewall-tested (`infrastructure/sensor/`) and
> goes live when cloud hosting is available.

## Docs

- [Scope](docs/scope.md): goals, zero-cost architecture, what's in and out
- [Threat model](docs/threat-model.md): trust boundaries, threats, data classification

## Local lab (Windows / PowerShell)

Requires Docker Desktop (WSL 2 backend) and Python 3.11+.

```powershell
Copy-Item .env.example .env        # then edit the password in .env
docker compose up -d               # Cowrie on 127.0.0.1:2222, Postgres on 127.0.0.1:5432

python -m venv .venv
.\.venv\Scripts\pip install -r requirements.txt
.\.venv\Scripts\python -m pytest   # unit tests; DB test runs if DATABASE_URL is set

# Synthetic data → database
.\.venv\Scripts\python -m collector.synthetic --sessions 200 --out sample-data/synthetic-cowrie.json
$env:DATABASE_URL = "postgresql://honeypot:<password>@127.0.0.1:5432/honeypot"
.\.venv\Scripts\python -m collector.loader --sensor-id synthetic sample-data/synthetic-cowrie.json

# Real Cowrie events: attack your own lab honeypot, then load its log
ssh -p 2222 root@127.0.0.1
.\.venv\Scripts\python -m collector.loader --sensor-id lab var/cowrie/cowrie.json
```

Loading the same file twice is safe: events are deduplicated on
`(sensor_id, sha256(event))`.

## Real data without a sensor: the CyberLab dataset

The pipeline can import the **CyberLab honeynet dataset**: about 50 Cowrie
honeypots at EU and US universities and companies, 2019. IPs are pseudonymised
by its authors.

> Sedlar, U., Kren, M., Štefanič Južnič, L., Volk, M. (2020). *CyberLab honeynet
> dataset*. Zenodo. https://doi.org/10.5281/zenodo.3687527 (CC BY 4.0)

This repo does not include the data. Fetch the prepared day file (flattened by
[honeypot-log-analyzer](https://github.com/b33pl0g1c/honeypot-log-analyzer)), then
run it through the pipeline:

```powershell
curl.exe -L -o sample-data/cyberlab-2019-05-18.jsonl https://raw.githubusercontent.com/b33pl0g1c/honeypot-log-analyzer/HEAD/evidence/sample_data.txt
# sha256: 2b933516c3845b23f82440097fec52b1c92a24048e6757a263df59aefefff23f
.\.venv\Scripts\python -m collector.datasets cyberlab sample-data/cyberlab-2019-05-18.jsonl
.\.venv\Scripts\python -m collector.classifier
.\.venv\Scripts\python -m collector.export --sensor dataset-cyberlab --dataset cyberlab `
    --start 2019-05-18T00:00:00Z --end 2019-05-19T00:00:00Z --out sample-data/summary-cyberlab.json
```

The export is what the portfolio widget shows (`Ken_Portfolio/content/honeypot-summary.json`).

## Layout

```
collector/       parser, loader, classifier, export, dataset importer, synthetic generator, schema.sql
rules/           behaviour rules mapped to MITRE ATT&CK
infrastructure/  sensor provisioning (Ubuntu 24.04) + firewall test
tests/           unit tests (+ DB integration tests)
docs/            scope, threat model
sample-data/     datasets and generated files (git-ignored)
```
