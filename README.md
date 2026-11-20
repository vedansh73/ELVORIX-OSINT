# ELVORIX-OSINT

A modular, data-driven **OSINT (Open-Source Intelligence)**, **Web & Network Reconnaissance**, and **Local File Forensics** CLI suite built in Python.

Designed to scale cleanly from core reconnaissance modules to **500+ real, evidence-backed checks** using external JSON rule packs (`data/*.json`), multi-threaded execution, and structured JSON reports.

---

## Key Capabilities & Feature Overview

### 1. Identity, Social & Public Footprint OSINT
- **Phone Number Intelligence:** Parses `E.164`, `International`, and `National` formats; checks validity and possibility; identifies line type (`Mobile`, `Fixed Line`, `VoIP`, etc.), region/state, telecom carrier, timezones, and public `wa.me` / search links.
- **Data-Driven Multi-Platform Username OSINT:** Multi-threaded platform scanner driven by `data/platforms.json` (easily expandable to 250+ public platforms) with false-positive and login-redirect filtering.
- **YouTube Channel Metadata & RSS OSINT:** Extracts channel title, handle, `UC...` Channel ID, avatar/logo URL (when available in static HTML), direct channel links, and recent public uploads via RSS (`videos.xml`).
- **Targeted OSINT Search Query Builder:** Generates structured search queries (`site:`, `filetype:`, GitHub/GitLab code & repo queries, and directory listing queries).

### 2. Domain, DNS, SSL & Web Reconnaissance
- **Deep Domain Audit:** Resolves IPv4 (`A`) and IPv6 (`AAAA`) records, performs Reverse DNS (`PTR`) lookups, inspects SSL/TLS certificates (`Common Name`, `Issuer`, validity dates, and `SANs`), queries `RDAP` registration data, enumerates passive subdomains via `crt.sh`, and checks `Wayback Machine` snapshots.
- **Web Public Endpoints & Files Audit:** Multi-threaded endpoint checker driven by `data/web_checks.json` (`robots.txt`, `sitemap.xml`, `security.txt`, `humans.txt`, `ads.txt`, API specs, etc. — scalable to 100+ checks).
- **IP Address & Network Intelligence:** Multi-source IP lookup with fallback providers for geolocation, ISP/Organization, ASN, timezone, and proxy/hosting indicators.

### 3. Local File Forensics, Crypto & Reporting
- **Local File Forensics (`core/forensics.py`):** Detects real file types via **Magic Bytes** (even if extensions are renamed), computes `MD5`, `SHA1`, and `SHA256` hashes, reads image `EXIF` metadata (via `Pillow`), and extracts readable strings, embedded URLs, and email addresses.
- **JWT Header & Payload Decoder:** Decodes Base64URL JWT segments cleanly for inspection.
- **Cryptographic Hash Generator:** Generates `MD5`, `SHA1`, `SHA256`, and `SHA512` digests.
- **JSON Report Exporter:** Automatically saves structured scan outputs to `reports/` with timestamps and target metadata.

---

## Scaling to 500+ Real Checks (Data-Driven Architecture)

Instead of hardcoding hundreds of duplicate functions inside `scanner.py`, **ELVORIX-OSINT** scales through modular Python engines + external JSON rule sets:

| Layer / Rule Set | Role | How It Scales |
| :--- | :--- | :--- |
| `core/engine.py` | Multi-threaded HTTP runner, DNS/SSL/RDAP/`crt.sh`/Wayback engine, IP lookup & JSON reporter | Handles concurrent checks with timeouts and safe error handling |
| `core/forensics.py` | Magic byte signatures, EXIF tags, string/URL/email extraction & JWT decoding | Add more magic byte signatures and forensic parsers |
| `data/platforms.json` | Public profile URL templates, not-found markers & redirect filters | Add 250+ public platforms without touching core logic |
| `data/web_checks.json` | Public paths, policy files & metadata endpoints | Add 100+ path/endpoint rules for web audits |

---

## Project Structure

```text
ELVORIX-OSINT/
├── scanner.py              # Interactive CLI menu & workflow controller
├── requirements.txt        # Python dependencies
├── README.md               # Documentation
├── core/
│   ├── __init__.py
│   ├── engine.py           # Recon, IP, DNS/SSL/crt.sh & multi-threaded rule runner
│   └── forensics.py        # Magic bytes, EXIF, strings & JWT decoder
├── data/
│   ├── platforms.json      # Username OSINT platform rules
│   └── web_checks.json     # Web endpoint & file check rules
└── reports/                # Auto-generated JSON scan reports (created on run)


git clone https://github.com/vedansh73/ELVORIX-OSINT.git
cd ELVORIX-OSINT
pip install -r requirements.txt
python scanner.py
