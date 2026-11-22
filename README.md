# ELVORIX-OSINT

A modular, data-driven **OSINT (Open-Source Intelligence)**, **Web & Network Reconnaissance**, and **Local File Forensics** CLI suite built in Python.

Designed to work either as a complete modular repository (`core/` + `data/*.json`) or as a **single self-contained script** (`scanner.py`), featuring a **500-option operational registry explorer** and automatic **JSON report exporting** (`reports/`).

---

## Quick Setup & Run Commands (`venv` - Kali Linux Safe)

Modern Debian/Kali Linux systems enforce **PEP 668** (`externally-managed-environment`). Use a Python virtual environment (`venv`) to install dependencies cleanly:

```bash
git clone [https://github.com/vedansh73/ELVORIX-OSINT.git](https://github.com/vedansh73/ELVORIX-OSINT.git)
cd ELVORIX-OSINT
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install requests rich phonenumbers Pillow
python scanner.py
If python3 -m venv venv Needs python3-fullBashsudo apt update && sudo apt install -y python3-full python3-pip
python3 -m venv venv
source venv/bin/activate
pip install requests rich phonenumbers Pillow
python scanner.py
Run as a Single Self-Contained Script (scanner.py Only)Bashmkdir -p ~/ELVORIX-OSINT && cd ~/ELVORIX-OSINT
# Place scanner.py in this directory
python3 -m venv venv
source venv/bin/activate
pip install requests rich phonenumbers Pillow
python scanner.py
Re-running Later in a New TerminalBashcd ~/ELVORIX-OSINT
source venv/bin/activate
python scanner.py
Terminal Interface PreviewPlaintext╭──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ ELVORIX-OSINT - Complete Modular OSINT & Forensics Suite                                                             │
│ Repo: [https://github.com/vedansh73/ELVORIX-OSINT.git](https://github.com/vedansh73/ELVORIX-OSINT.git) | Developer: Vedansh Srivastava                                 │
╰──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
[ 1] Phone Number OSINT Intelligence
[ 2] Multi-Platform Username OSINT (JSON Rules)
[ 3] Deep Domain Recon (DNS, SSL, RDAP, crt.sh, Wayback)
[ 4] Web Public Endpoints Audit (JSON Rules)
[ 5] IP Address Intelligence Lookup
[ 6] YouTube Channel Metadata, Avatar & RSS OSINT
[ 7] Local File Forensics (Magic Bytes, EXIF, Strings)
[ 8] JWT Header & Payload Decoder
[ 9] Cryptographic Hash Generator
[10] Targeted OSINT Search Query Builder
[11] Fast Multi-Threaded Username OSINT
[12] HTTP Security Headers & WAF / CDN Detector
[13] Deep WhatsApp Public Link & Dork Helper
[14] Base64 & URL Encoder / Decoder
[15] 500-Option Operational Registry Explorer
[ 0] Exit

Select option:
Inside Option [15] (500-Option Registry Explorer):PlaintextOptions 1–25 of 500 (Page 1/20)
[001] Platform Check: GitHub
[002] Platform Check: GitLab
...
[ n ] Next | [ p ] Prev | [ g ] Jump # (1-500) | [ b ] Back to Main Menu

Select option (001-500) or command (n/p/g/b):
All Features & Option ReferenceOptionFeature / ModuleDescription & Output[ 1]Phone Number OSINT IntelligenceFormats numbers (E.164, International, National), checks validity/possibility, detects line type (Mobile, Fixed Line, VoIP, etc.), region/state, telecom carrier, timezones, and wa.me link; exports JSON report.[ 2]Multi-Platform Username OSINT (JSON Rules)Multi-threaded username check driven by data/platforms.json with status and redirect/not-found filtering; exports JSON report.[ 3]Deep Domain ReconResolves IPv4 (A) and IPv6 (AAAA), runs Reverse DNS (PTR), inspects SSL/TLS certificate (Common Name, Issuer, expiry dates, SANs), queries RDAP registration info, enumerates subdomains via crt.sh, and checks Wayback Machine snapshots; exports JSON report.[ 4]Web Public Endpoints Audit (JSON Rules)Multi-threaded audit of public files/endpoints from data/web_checks.json (robots.txt, sitemap.xml, security.txt, humans.txt, ads.txt, swagger.json, etc.); exports JSON report.[ 5]IP Address Intelligence LookupQueries multiple IP intelligence providers with automatic fallback for geolocation, coordinates + Google Maps link, ISP/Organization, ASN, timezone, and proxy/hosting flags; exports JSON report.[ 6]YouTube Channel Metadata, Avatar & RSS OSINTExtracts channel title, @handle, UC... Channel ID, avatar/logo URL (when present in static HTML), and recent public video uploads via RSS (videos.xml); exports JSON report.[ 7]Local File ForensicsIdentifies true file types via Magic Bytes (even when file extensions are changed), computes MD5, SHA1, and SHA256 hashes, reads image dimensions and EXIF metadata (Pillow), and extracts readable strings, embedded URLs, and emails; exports JSON report.[ 8]JWT Header & Payload DecoderDecodes Base64URL JWT header and payload JSON structures cleanly for inspection.[ 9]Cryptographic Hash GeneratorComputes MD5, SHA1, SHA256, and SHA512 digests for any text input.[10]Targeted OSINT Search Query BuilderGenerates structured Google search URLs (site:, filetype:pdf/xlsx/csv, github.com/gitlab.com, intitle:"index of").[11]Fast Multi-Threaded Username OSINTConcurrent username lookup across popular social, developer, and gaming platforms; exports JSON report.[12]HTTP Security Headers & WAF / CDN DetectorInspects HTTP status, final redirect URL, security headers (Server, X-Frame-Options, CSP, HSTS, X-Content-Type-Options, Referrer-Policy), and common WAF/CDN signatures (Cloudflare, CloudFront, Akamai, Fastly, Sucuri, Imperva).[13]Deep WhatsApp Public Link & Dork HelperFormats phone numbers (E.164 / International), creates wa.me and api.whatsapp.com/send links, and builds public Google Dork search URLs.[14]Base64 & URL Encoder / DecoderEncodes and decodes Base64 and URL strings.[15]500-Option Operational Registry ExplorerPaginated 001–500 operational explorer (n next, p previous, g jump to 1–500, b back) covering platform checks (001–200), web endpoints (201–320), domain/DNS/SSL/Wayback (321–380), IP/CIDR/TCP ports (381–440), and forensics/utilities (441–500).[ 0]ExitExits the CLI cleanly.Project StructurePlaintextELVORIX-OSINT/
├── scanner.py              # Main CLI interface, menus & 500-option explorer
├── requirements.txt        # Python dependencies
├── README.md               # Project documentation
├── core/
│   ├── __init__.py
│   ├── engine.py           # IP lookup, deep domain recon, rule runner & JSON reporter
│   └── forensics.py        # File magic bytes, EXIF, strings & JWT decoder
├── data/
│   ├── platforms.json      # Username OSINT check rules
│   └── web_checks.json     # Web endpoint check rules
└── reports/                # Auto-generated JSON scan reports
Ethical & Legal NoticeUse ELVORIX-OSINT strictly on targets you own or have explicit authorization to assess, relying only on publicly accessible data. This suite does not bypass authentication or access private accounts, private messages, or non-public records. Always comply with applicable laws and platform terms of service.
