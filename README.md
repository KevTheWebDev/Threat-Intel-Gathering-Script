# Threat-Intel-Gathering-Script

A résumé‑ready, MIT‑licensed mini‑pipeline that ingests open‑source threat‑intelligence
indicators (IOCs) from AlienVault OTX and Abuse.ch URLhaus, persists them in SQLite,
and prints fast analytics.

## Why this matters

* **Threat‑analysis skills** – consuming, normalising and triaging raw feeds.
* **Data‑engineering fundamentals** – building an ETL pipeline with idempotent storage.
* **Python fluency** – requests, pandas, SQLite, CLI ergonomics.

## Data sources
* **AlienVault OTX**: indicators export API (IPv4 & domains) :contentReference[oaicite:2]{index=2}  
* **Abuse.ch URLhaus**: `csv_recent` feed (last 24 h of malicious URLs) :contentReference[oaicite:3]{index=3}

## Running

```bash
python main.py ingest   # fetch + store
python main.py analyze  # view metrics
