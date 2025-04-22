#!/usr/bin/env python3
"""
Threat‑Intel‑Gatherer
─────────────────────
Fetches indicators from AlienVault OTX and Abuse.ch URLhaus,
stores them in SQLite, and runs quick analytics.

Usage:
    python main.py ingest      # pull & store new data
    python main.py analyze     # print analytics
"""

import argparse
import csv
import ipaddress
import os
import sqlite3
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from io import StringIO
from urllib.parse import urlparse

import pandas as pd
import requests
from dotenv import load_dotenv
from tqdm import tqdm

DB_PATH = "threatintel.db"
URLHAUS_RECENT = "https://urlhaus.abuse.ch/downloads/csv_recent/"      # :contentReference[oaicite:0]{index=0}
OTX_EXPORT_TEMPLATE = (
    "https://otx.alienvault.com/api/v1/indicators/export"
    "?type={ioc_type}&apikey={api_key}&limit={limit}&modified_since={since}"
)  # :contentReference[oaicite:1]{index=1}


# ────────────────────────── helpers ──────────────────────────
def init_db(path: str = DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(path)
    conn.execute(
        """CREATE TABLE IF NOT EXISTS indicators (
           indicator TEXT,
           ioc_type  TEXT,
           source    TEXT,
           first_seen TEXT,
           PRIMARY KEY(indicator, source)
        )"""
    )
    return conn


def persist(conn: sqlite3.Connection, rows: list[tuple]):
    with conn:  # commits automatically
        conn.executemany(
            "INSERT OR IGNORE INTO indicators VALUES (?,?,?,?)",
            rows,
        )


def classify(value: str) -> str:
    """Return basic type: ip, url, domain, hash."""
    try:
        ipaddress.ip_address(value)
        return "ip"
    except ValueError:
        if value.startswith("http"):
            return "url"
        if "." in value:  # crude domain test
            return "domain"
        return "hash"


# ────────────────────────── collectors ───────────────────────
def fetch_urlhaus() -> list[tuple]:
    """Return list[(indicator, type, source, first_seen)] from URLhaus."""
    resp = requests.get(URLHAUS_RECENT, timeout=30)
    resp.raise_for_status()
    # CSV is '#'‑commented header; skip first 9 lines
    data = resp.text.splitlines()[9:]
    reader = csv.reader(data)
    rows = []
    today = datetime.utcnow().strftime("%Y-%m-%d")
    for row in reader:
        # CSV layout: id,dateadded,url,url_status,threat,tags,urlhaus_reference
        _, dateadded, url, *_ = row
        ioc_type = classify(url)
        rows.append((url, ioc_type, "URLhaus", dateadded or today))
    return rows


def fetch_otx(ioc_type: str = "IPv4", days: int = 1, limit: int = 5000) -> list[tuple]:
    """Fetch recent indicators from OTX export API."""
    load_dotenv()
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        print("⚠️  Skipping OTX (no OTX_API_KEY set)", file=sys.stderr)
        return []

    since = (datetime.utcnow() - timedelta(days=days)).isoformat(timespec="seconds") + "Z"
    url = OTX_EXPORT_TEMPLATE.format(
        ioc_type=ioc_type,
        api_key=api_key,
        limit=limit,
        since=since,
    )
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    rows = [
        (line.strip(), classify(line.strip()), "AlienVault OTX", since)
        for line in resp.text.splitlines()
        if line.strip() and not line.startswith("#")
    ]
    return rows


# ────────────────────────── analytics ────────────────────────
def analytics(conn: sqlite3.Connection):
    df = pd.read_sql_query("SELECT * FROM indicators", conn)

    total = len(df)
    by_source = df.groupby("source").size()
    by_type = df.groupby("ioc_type").size()

    # Who appears in multiple feeds?
    duplicates = (
        df.groupby("indicator")
        .source.nunique()
        .loc[lambda s: s > 1]
        .sort_values(ascending=False)
    )

    # Most common /24 subnets (quick IP clustering)
    ip_df = df[df.ioc_type == "ip"].copy()
    if not ip_df.empty:
        ip_df["/24"] = ip_df.indicator.apply(lambda ip: str(ipaddress.ip_network(f"{ip}/24", strict=False).network_address))
        top_subnets = ip_df.groupby("/24").size().sort_values(ascending=False).head(10)
    else:
        top_subnets = pd.Series(dtype=int)

    # Pretty‑print
    print("\n========== Threat‑Intel Snapshot ==========")
    print(f"Total unique IOCs: {total:,}")
    print("\nBy source:\n", by_source.to_string())
    print("\nBy type:\n", by_type.to_string())
    print("\nIndicators seen in >1 feed (top 20):\n", duplicates.head(20).to_string())
    if not top_subnets.empty:
        print("\nTop malicious /24 subnets:\n", top_subnets.to_string())
    print("===========================================\n")


# ────────────────────────── CLI ──────────────────────────────
def main():
    parser = argparse.ArgumentParser(description="Open‑Source Threat Intel Gatherer")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("ingest", help="Download & store latest indicators")
    sub.add_parser("analyze", help="Run quick analytics on the database")
    args = parser.parse_args()

    conn = init_db()

    if args.cmd == "ingest":
        rows = []
        print("Pulling URLhaus …")
        rows.extend(fetch_urlhaus())
        print("Pulling OTX IPv4 …")
        rows.extend(fetch_otx("IPv4"))
        print("Pulling OTX domain …")
        rows.extend(fetch_otx("domain"))
        print(f"Ingesting {len(rows):,} rows …")
        persist(conn, rows)
        print("✅  Done.")
    elif args.cmd == "analyze":
        analytics(conn)


if __name__ == "__main__":
    main()
