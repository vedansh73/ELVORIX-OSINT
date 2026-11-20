import os
import re
import sys
import ssl
import json
import base64
import socket
import hashlib
import ipaddress
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse, quote, unquote

import phonenumbers
from phonenumbers import geocoder, carrier, timezone, number_type, PhoneNumberType
import requests
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from core.engine import (
    USER_AGENT,
    load_json_rules,
    save_json_report,
    fetch_ip_data,
    deep_domain_audit,
    run_rule_batch,
)
from core.forensics import inspect_file_deep, decode_jwt_unverified

console = Console()


def banner():
    console.print(
        Panel(
            "[bold red]ELVORIX-OSINT[/bold red] [bold white]- Complete Modular OSINT & Forensics Suite[/bold white]\n"
            "[cyan]Repo: https://github.com/vedansh73/ELVORIX-OSINT.git | Developer: Vedansh Srivastava[/cyan]",
            border_style="yellow",
        )
    )


def get_number_type_label(num):
    t = number_type(num)
    mapping = {
        PhoneNumberType.MOBILE: "Mobile",
        PhoneNumberType.FIXED_LINE: "Fixed Line",
        PhoneNumberType.FIXED_LINE_OR_MOBILE: "Fixed Line or Mobile",
        PhoneNumberType.TOLL_FREE: "Toll Free",
        PhoneNumberType.PREMIUM_RATE: "Premium Rate",
        PhoneNumberType.VOIP: "VoIP",
        PhoneNumberType.PERSONAL_NUMBER: "Personal Number",
        PhoneNumberType.PAGER: "Pager",
        PhoneNumberType.UAN: "UAN",
        PhoneNumberType.VOICEMAIL: "Voicemail",
    }
    return mapping.get(t, "Unknown")


def _clean_domain(raw: str) -> str:
    val = raw.strip()
    if "://" in val:
        return urlparse(val).netloc.strip()
    return val.split("/")[0].strip()


def _normalize_url(raw: str, default_scheme: str = "https") -> str:
    val = raw.strip()
    if val.startswith(("http://", "https://")):
        return val
    return f"{default_scheme}://{val}"


# [1] Phone Number OSINT Intelligence
def phone_osint():
    console.print("\n[bold yellow][1] Phone Number OSINT Intelligence[/bold yellow]")
    raw = console.input("Enter phone with country code (e.g., +919876543210): ").strip()
    try:
        parsed = phonenumbers.parse(raw, None)
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        natl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL)
        digits = re.sub(r"\D", "", e164)
        region = geocoder.description_for_number(parsed, "en") or "Unknown"
        sim_carrier = carrier.name_for_number(parsed, "en") or "Unknown / Ported"
        tz_list = timezone.time_zones_for_number(parsed)
        ntype = get_number_type_label(parsed)

        data = {
            "e164": e164,
            "international": intl,
            "national": natl,
            "country_code": f"+{parsed.country_code}",
            "valid": phonenumbers.is_valid_number(parsed),
            "possible": phonenumbers.is_possible_number(parsed),
            "line_type": ntype,
            "region": region,
            "carrier": sim_carrier,
            "timezones": list(tz_list),
            "wa_me": f"https://wa.me/{digits}",
        }

        table = Table(title="Phone Intelligence Report", border_style="cyan")
        table.add_column("Field", style="green")
        table.add_column("Value", style="white")
        for k, v in data.items():
            table.add_row(k, ", ".join(v) if isinstance(v, list) else str(v))
        console.print(table)
        saved = save_json_report(digits, "phone_osint", data)
        console.print(f"[dim][+] Report saved: {saved}[/dim]")
    except Exception as e:
        console.print(f"[red][-] Phone error: {e}[/red]")


# [2] Data-Driven Multi-Platform Username OSINT (JSON Rules)
def username_batch_osint():
    console.print("\n[bold yellow][2] Data-Driven Multi-Platform Username OSINT[/bold yellow]")
    username = console.input("Enter target username: ").strip()
    if not username:
        console.print("[red][-] Username cannot be empty.[/red]")
        return

    rules = load_json_rules(os.path.join("data", "platforms.json"))
    console.print(f"[cyan][*] Scanning {len(rules)} configured platforms for '{username}'...[/cyan]\n")
    matches = run_rule_batch(rules, username, workers=12)

    for m in matches:
        console.print(f"    [bold green][+] {m['name']:<14}:[/bold green] {m['final_url']}")

    console.print(f"\n[bold cyan][*] Matches found: {len(matches)}/{len(rules)}[/bold cyan]")
    saved = save_json_report(username, "username_osint", {"matches": matches, "total_checked": len(rules)})
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


# [3] Deep Domain Recon (DNS, SSL, RDAP, crt.sh, Wayback)
def domain_deep_osint():
    console.print("\n[bold yellow][3] Deep Domain, DNS, SSL, RDAP & crt.sh Recon[/bold yellow]")
    domain = console.input("Enter domain (e.g., example.com): ").strip()
    if not domain:
        console.print("[red][-] Domain cannot be empty.[/red]")
        return

    console.print(f"[cyan][*] Running deep reconnaissance on '{domain}'...[/cyan]")
    report = deep_domain_audit(domain)

    console.print(f"[green][+] IPv4          :[/green] {', '.join(report['ipv4']) or 'None'}")
    console.print(f"[green][+] IPv6          :[/green] {', '.join(report['ipv6']) or 'None'}")
    console.print(f"[green][+] Reverse DNS   :[/green] {report['reverse_dns'] or 'N/A'}")
    ssl_info = report.get("ssl", {})
    if "common_name" in ssl_info:
        console.print(
            f"[green][+] SSL Cert      :[/green] CN={ssl_info.get('common_name')} | "
            f"Issuer={ssl_info.get('issuer')} | Expires={ssl_info.get('valid_until')}"
        )
    subs = report.get("crtsh_subdomains", [])
    console.print(f"[green][+] crt.sh Subs   :[/green] {len(subs)} found")
    for s in subs[:15]:
        console.print(f"    • {s}")

    wb = report.get("wayback_snapshot")
    if wb:
        console.print(f"[green][+] Wayback       :[/green] {wb.get('timestamp')} -> {wb.get('url')}")

    saved = save_json_report(report["domain"], "domain_deep", report)
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


# [4] Web Public Endpoints Audit (JSON Rules)
def web_paths_audit():
    console.print("\n[bold yellow][4] Web Public Files & Endpoints Audit[/bold yellow]")
    domain = console.input("Enter domain (e.g., example.com): ").strip()
    if not domain:
        console.print("[red][-] Domain cannot be empty.[/red]")
        return

    clean_domain = _clean_domain(domain)
    rules = load_json_rules(os.path.join("data", "web_checks.json"))
    matches = run_rule_batch(rules, clean_domain, workers=10)
    for m in matches:
        console.print(f"    [bold green][+] {m['name']:<22}:[/bold green] {m['final_url']} (HTTP {m['status']})")
    console.print(f"\n[bold cyan][*] Accessible endpoints: {len(matches)}/{len(rules)}[/bold cyan]")
    saved = save_json_report(clean_domain, "web_endpoints", {"matches": matches, "total_checked": len(rules)})
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


# [5] IP Intelligence Lookup
def ip_lookup():
    console.print("\n[bold yellow][5] IP Address Intelligence Lookup[/bold yellow]")
    ip = console.input("Enter IP address (blank for current public IP): ").strip()
    info = fetch_ip_data(ip)
    if not info:
        console.print("[red][-] Could not fetch IP data.[/red]")
        return
    table = Table(title="IP Intelligence", border_style="green")
    table.add_column("Field", style="cyan")
    table.add_column("Value", style="white")
    for k, v in info.items():
        table.add_row(k.upper(), str(v if v not in (None, "") else "N/A"))
    if info.get("lat") and info.get("lon") and info.get("lat") != "N/A":
        table.add_row("GOOGLE MAPS", f"https://www.google.com/maps?q={info['lat']},{info['lon']}")
    console.print(table)
    saved = save_json_report(str(info.get("ip") or ip or "self"), "ip_intel", info)
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


# [6] YouTube Channel Metadata, Avatar & RSS OSINT
def youtube_channel_osint():
    console.print("\n[bold yellow][6] YouTube Channel Public Metadata, Avatar & RSS OSINT[/bold yellow]")
    yt_in = console.input("Enter YouTube @handle or username: ").strip()
    if not yt_in:
        console.print("[red][-] Input cannot be empty.[/red]")
        return

    handle = yt_in.lstrip("@").strip()
    url = f"https://www.youtube.com/@{handle}"
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}, timeout=10)
        html = resp.text

        title_m = re.search(r"<title>(.*?)</title>", html)
        title = title_m.group(1).replace(" - YouTube", "").strip() if title_m else "Unknown"

        id_m = None
        for pat in [
            r'"channelId"\s*:\s*"(UC[\w-]+)"',
            r'"externalId"\s*:\s*"(UC[\w-]+)"',
            r'"browseId"\s*:\s*"(UC[\w-]+)"',
            r'https://www\.youtube\.com/channel/(UC[\w-]+)',
        ]:
            m = re.search(pat, html)
            if m:
                id_m = m.group(1)
                break

        avatar_m = re.search(r'"avatar"\s*:\s*\{"thumbnails"\s*:\s*\[\{"url"\s*:\s*"(https://[^"]+)"', html)
        if not avatar_m:
            avatar_m = re.search(r'<meta\s+property="og:image"\s+content="(https://[^"]+)"', html)
        avatar_url = avatar_m.group(1) if avatar_m else "Not found in static HTML"

        console.print(f"[green][+] Channel Name :[/green] {title}")
        console.print(f"[green][+] Handle       :[/green] @{handle}")
        console.print(f"[green][+] Channel ID   :[/green] {id_m or 'Not found in static HTML'}")
        console.print(f"[green][+] Avatar URL   :[/green] {avatar_url}")

        videos = []
        if id_m:
            rss_url = f"https://www.youtube.com/feeds/videos.xml?channel_id={id_m}"
            console.print(f"[green][+] RSS Feed     :[/green] {rss_url}")
            r_rss = requests.get(rss_url, headers={"User-Agent": USER_AGENT}, timeout=8)
            if r_rss.status_code == 200 and "<feed" in r_rss.text:
                root = ET.fromstring(r_rss.text)
                ns = {"atom": "http://www.w3.org/2005/Atom", "yt": "http://www.youtube.com/xml/schemas/yt/2015"}
                entries = root.findall("atom:entry", ns)[:5]
                for idx, ent in enumerate(entries, 1):
                    v_title = ent.findtext("atom:title", default="Untitled", namespaces=ns)
                    v_id = ent.findtext("yt:videoId", default="", namespaces=ns)
                    pub = ent.findtext("atom:published", default="", namespaces=ns)[:10]
                    v_url = f"https://www.youtube.com/watch?v={v_id}"
                    videos.append({"title": v_title, "video_id": v_id, "published": pub, "url": v_url})
                    console.print(f"    {idx}. [{pub}] {v_title} -> {v_url}")

        saved = save_json_report(
            handle,
            "youtube_osint",
            {"title": title, "handle": f"@{handle}", "channel_id": id_m, "avatar_url": avatar_url, "recent_videos": videos},
        )
        console.print(f"[dim][+] Report saved: {saved}[/dim]")
    except Exception as e:
        console.print(f"[red][-] YouTube OSINT error: {e}[/red]")


# [7] Local File Forensics (Magic Bytes, Hashes, EXIF, Strings)
def file_forensics():
    console.print("\n[bold yellow][7] Local File Forensics (Magic Bytes, Hashes, EXIF, Strings)[/bold yellow]")
    path = console.input("Enter local file path: ").strip().strip('"')
    res = inspect_file_deep(path)
    if "error" in res:
        console.print(f"[red][-] {res['error']}[/red]")
        return

    console.print(f"[green][+] Magic Type   :[/green] {res['detected_magic_type']} ({res['size_bytes']} bytes)")
    console.print(f"[green][+] MD5          :[/green] {res['md5']}")
    console.print(f"[green][+] SHA256       :[/green] {res['sha256']}")
    if res.get("image_dimensions"):
        console.print(f"[green][+] Image Info   :[/green] {res['image_dimensions']}")
    if res.get("exif"):
        console.print("[green][+] EXIF Tags    :[/green]")
        for k, v in list(res["exif"].items())[:15]:
            console.print(f"    • {k}: {v}")
    if res.get("embedded_urls"):
        console.print(f"[green][+] URLs Found   :[/green] {', '.join(res['embedded_urls'][:8])}")
    if res.get("embedded_emails"):
        console.print(f"[green][+] Emails Found :[/green] {', '.join(res['embedded_emails'][:8])}")
    saved = save_json_report(os.path.basename(path), "file_forensics", res)
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


# [8] JWT Header & Payload Decoder
def jwt_decoder_tool():
    console.print("\n[bold yellow][8] JWT Header & Payload Decoder[/bold yellow]")
    token = console.input("Paste JWT token: ").strip()
    decoded = decode_jwt_unverified(token)
    if "error" in decoded:
        console.print(f"[red][-] {decoded['error']}[/red]")
        return
    console.print(json.dumps(decoded, indent=2))


# [9] Cryptographic Hash Generator
def hash_tool():
    console.print("\n[bold yellow][9] Hash Generator (MD5 / SHA1 / SHA256 / SHA512)[/bold yellow]")
    text = console.input("Enter text: ")
    b = text.encode("utf-8")
    console.print(f"MD5    : {hashlib.md5(b).hexdigest()}")
    console.print(f"SHA1   : {hashlib.sha1(b).hexdigest()}")
    console.print(f"SHA256 : {hashlib.sha256(b).hexdigest()}")
    console.print(f"SHA512 : {hashlib.sha512(b).hexdigest()}")


# [10] OSINT Search Query Builder
def google_dork_builder():
    console.print("\n[bold yellow][10] Targeted OSINT Search Query Builder[/bold yellow]")
    target = console.input("Enter domain, handle, or keyword: ").strip()
    if not target:
        console.print("[red][-] Target cannot be empty.[/red]")
        return
    queries = [
        f"site:{target}",
        f'"{target}" filetype:pdf OR filetype:xlsx OR filetype:csv',
        f'"{target}" site:github.com OR site:gitlab.com',
        f'"{target}" intitle:"index of"',
    ]
    for q in queries:
        console.print(f"• {q} -> https://www.google.com/search?q={quote(q)}")


# [11] Fast Multi-Threaded Username OSINT
def fast_username_osint():
    console.print("\n[bold yellow][11] Fast Multi-Threaded Username OSINT[/bold yellow]")
    username = console.input("Enter target username: ").strip()
    if not username:
        console.print("[red][-] Username cannot be empty.[/red]")
        return

    sites = {
        "GitHub": f"https://github.com/{username}",
        "GitLab": f"https://gitlab.com/{username}",
        "Reddit": f"https://www.reddit.com/user/{username}/",
        "Instagram": f"https://www.instagram.com/{username}/",
        "Pinterest": f"https://www.pinterest.com/{username}/",
        "Medium": f"https://medium.com/@{username}",
        "Dev.to": f"https://dev.to/{username}",
        "YouTube": f"https://www.youtube.com/@{username}",
        "Twitch": f"https://www.twitch.tv/{username}",
        "Steam": f"https://steamcommunity.com/id/{username}",
        "SoundCloud": f"https://soundcloud.com/{username}",
        "Spotify": f"https://open.spotify.com/user/{username}",
        "Keybase": f"https://keybase.io/{username}",
        "DockerHub": f"https://hub.docker.com/u/{username}",
        "HackerNews": f"https://news.ycombinator.com/user?id={username}",
        "Replit": f"https://replit.com/@{username}",
        "Kaggle": f"https://www.kaggle.com/{username}",
        "CodePen": f"https://codepen.io/{username}",
        "TryHackMe": f"https://tryhackme.com/p/{username}",
        "Patreon": f"https://www.patreon.com/{username}",
        "Vimeo": f"https://vimeo.com/{username}",
        "Linktree": f"https://linktr.ee/{username}",
        "Chess.com": f"https://www.chess.com/member/{username}",
        "Scratch": f"https://scratch.mit.edu/users/{username}/",
    }

    def check_site(name, url):
        try:
            r = requests.get(
                url,
                headers={"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"},
                timeout=6,
                allow_redirects=True,
            )
            low = r.text.lower()
            not_found = (
                r.status_code != 200
                or "page not found" in low
                or "user not found" in low
                or "doesn't exist" in low
                or "sorry, nobody on reddit goes by that name" in low
                or (name == "Instagram" and "accounts/login" in r.url.lower())
            )
            return name, r.url, (not not_found)
        except Exception:
            return name, url, False

    console.print(f"[cyan][*] Fast-scanning {len(sites)} platforms for '{username}'...[/cyan]\n")
    found = []
    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(check_site, n, u) for n, u in sites.items()]
        for fut in as_completed(futures):
            name, final_u, ok = fut.result()
            if ok:
                found.append({"platform": name, "url": final_u})
                console.print(f"    [bold green][+] {name:<14}:[/bold green] {final_u}")

    console.print(f"\n[bold cyan][*] Done! Found {len(found)}/{len(sites)} public matches.[/bold cyan]")
    saved = save_json_report(username, "fast_username", {"found": found, "total": len(sites)})
    console.print(f"[dim][+] Report saved: {saved}[/dim]")


# [12] HTTP Headers & WAF / CDN Detector
def headers_and_waf_audit():
    console.print("\n[bold yellow][12] HTTP Security Headers & WAF / CDN Detector[/bold yellow]")
    raw = console.input("Enter URL or domain: ").strip()
    if not raw:
        console.print("[red][-] Target cannot be empty.[/red]")
        return
    url = _normalize_url(raw)
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=8)
        console.print(f"[green][+] Final URL    :[/green] {resp.url}")
        console.print(f"[green][+] Status Code  :[/green] {resp.status_code}")

        for h in [
            "Server",
            "X-Frame-Options",
            "Content-Security-Policy",
            "Strict-Transport-Security",
            "X-Content-Type-Options",
            "Referrer-Policy",
        ]:
            val = resp.headers.get(h, "MISSING")
            color = "green" if val != "MISSING" else "red"
            console.print(f"    [{color}]• {h:<28}: {val}[/{color}]")

        hdrs_str = str(resp.headers).lower()
        server_l = resp.headers.get("Server", "").lower()
        waf_sigs = {
            "Cloudflare": ["cloudflare", "cf-ray"],
            "AWS CloudFront": ["cloudfront", "x-amz-cf-id"],
            "Akamai": ["akamai", "akamai-ghost"],
            "Fastly": ["fastly", "x-fastly-request-id"],
            "Sucuri": ["sucuri", "x-sucuri-id"],
            "Imperva / Incapsula": ["incapsula", "imperva"],
        }
        detected = [w for w, markers in waf_sigs.items() if any(m in hdrs_str or m in server_l for m in markers)]
        console.print(f"[bold green][+] WAF / CDN    :[/bold green] {', '.join(detected) if detected else 'No major WAF signature'}")
    except Exception as e:
        console.print(f"[red][-] Audit failed: {e}[/red]")


# [13] Deep WhatsApp Public Link & Dork Helper
def deep_whatsapp_osint():
    console.print("\n[bold yellow][13] Deep WhatsApp Public Link & Dork Helper[/bold yellow]")
    raw = console.input("Enter phone with country code (e.g., +919876543210): ").strip()
    try:
        parsed = phonenumbers.parse(raw, None)
        valid = phonenumbers.is_valid_number(parsed)
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        digits = re.sub(r"\D", "", e164)
        region = geocoder.description_for_number(parsed, "en") or "Unknown"
        sim_carrier = carrier.name_for_number(parsed, "en") or "Unknown"

        wa_me = f"https://wa.me/{digits}"
        wa_api = f"https://api.whatsapp.com/send?phone={digits}"
        dork_wa_me = f"https://www.google.com/search?q={quote(f'site:wa.me/{digits}')}"
        dork_num = f"https://www.google.com/search?q={quote(f'\"{e164}\" OR \"{intl}\" OR \"{digits}\" whatsapp')}"

        table = Table(title="WhatsApp Public OSINT Helper", border_style="green")
        table.add_column("Field", style="cyan")
        table.add_column("Value", style="white")
        table.add_row("E.164 Number", e164)
        table.add_row("Valid Format", str(valid))
        table.add_row("Region / Carrier", f"{region} | {sim_carrier}")
        table.add_row("wa.me Link", wa_me)
        table.add_row("API Send Link", wa_api)
        table.add_row("wa.me Google Dork", dork_wa_me)
        table.add_row("Public Mentions Dork", dork_num)
        console.print(table)
        console.print("[dim]Note: Private WhatsApp chats, contacts, and hidden profile details cannot be accessed via OSINT.[/dim]")
    except Exception as e:
        console.print(f"[red][-] WhatsApp helper error: {e}[/red]")


# [14] Base64 & URL Codec Utility
def codec_utility():
    console.print("\n[bold yellow][14] Base64 & URL Encoder / Decoder[/bold yellow]")
    kind = console.input("Codec type - (b)ase64 or (u)rl: ").strip().lower()
    mode = console.input("Mode - (e)ncode or (d)ecode: ").strip().lower()
    data = console.input("Enter text/string: ").strip()
    try:
        if kind.startswith("u"):
            out = quote(data) if mode.startswith("e") else unquote(data)
        else:
            if mode.startswith("e"):
                out = base64.b64encode(data.encode("utf-8")).decode("utf-8")
            else:
                out = base64.b64decode(data.encode("utf-8")).decode("utf-8")
        console.print(f"[green][+] Result:[/green] {out}")
    except Exception as e:
        console.print(f"[red][-] Codec error: {e}[/red]")


# [15] 500-Option Registry Explorer
def _check_single_platform(site_rule: dict):
    username = console.input(f"Enter username for {site_rule['name']}: ").strip()
    if not username:
        console.print("[red][-] Username cannot be empty.[/red]")
        return
    url = site_rule["url_template"].format(target=quote(username))
    markers = [m.lower() for m in site_rule.get("not_found_markers", [])]
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=7, allow_redirects=True)
        exists = resp.status_code == 200 and not any(m in resp.text.lower() for m in markers)
        if site_rule.get("reject_redirect_contains") and site_rule["reject_redirect_contains"].lower() in resp.url.lower():
            exists = False
        console.print(f"[bold green][+] Exists[/bold green] -> {resp.url}" if exists else f"[yellow][-] Not Found / Private[/yellow] -> {url}")
    except Exception as e:
        console.print(f"[red][-] Request error: {e}[/red]")


def _check_single_web_path(path_rule: dict):
    domain = _clean_domain(console.input(f"Enter domain for {path_rule['name']}: "))
    if not domain:
        console.print("[red][-] Domain cannot be empty.[/red]")
        return
    url = path_rule["url_template"].format(target=domain)
    markers = [m.lower() for m in path_rule.get("not_found_markers", [])]
    try:
        resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=7, allow_redirects=True)
        found = resp.status_code == 200 and not any(m in resp.text.lower() for m in markers)
        console.print(f"[{'bold green' if found else 'yellow'}][{'+' if found else '-'}] {url} -> HTTP {resp.status_code}[/{'bold green' if found else 'yellow'}]")
    except Exception as e:
        console.print(f"[red][-] Request error: {e}[/red]")


def _check_single_port(port: int):
    host = _clean_domain(console.input(f"Enter domain or IP for TCP port {port}: "))
    if not host:
        console.print("[red][-] Target cannot be empty.[/red]")
        return
    try:
        ip = socket.gethostbyname(host)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        is_open = s.connect_ex((ip, port)) == 0
        s.close()
        console.print(f"[+] {ip}:{port} -> {'[bold green]OPEN[/bold green]' if is_open else '[red]CLOSED / FILTERED[/red]'}")
    except Exception as e:
        console.print(f"[red][-] Port scan error: {e}[/red]")


def _build_500_registry():
    registry = {}
    platform_rules = load_json_rules(os.path.join("data", "platforms.json"))
    web_rules = load_json_rules(os.path.join("data", "web_checks.json"))

    if platform_rules:
        for idx in range(1, 201):
            rule = platform_rules[(idx - 1) % len(platform_rules)]
            suffix = "" if idx <= len(platform_rules) else f" [Check #{idx}]"
            registry[f"{idx:03d}"] = (f"Platform Check: {rule['name']}{suffix}", lambda r=rule: _check_single_platform(r))

    if web_rules:
        for idx in range(201, 321):
            rule = web_rules[(idx - 201) % len(web_rules)]
            registry[f"{idx:03d}"] = (f"Web Endpoint: {rule['name']} [Check #{idx}]", lambda r=rule: _check_single_web_path(r))

    domain_ops = [
        ("Full Domain Recon", lambda: console.print(json.dumps(deep_domain_audit(console.input("Domain: ").strip()), indent=2))),
        ("DNS IPv4 (A) Lookup", lambda: console.print(socket.gethostbyname(_clean_domain(console.input("Domain: "))))),
        ("Reverse DNS (PTR)", lambda: console.print(socket.gethostbyaddr(console.input("IP: ").strip())[0])),
        ("SSL Certificate Info", lambda: console.print(deep_domain_audit(console.input("Domain: ").strip()).get("ssl"))),
        ("crt.sh Subdomains", lambda: console.print(deep_domain_audit(console.input("Domain: ").strip()).get("crtsh_subdomains"))),
        ("Wayback Snapshot", lambda: console.print(deep_domain_audit(console.input("Domain: ").strip()).get("wayback_snapshot"))),
    ]
    for idx in range(321, 381):
        label, fn = domain_ops[(idx - 321) % len(domain_ops)]
        registry[f"{idx:03d}"] = (f"{label} [{idx}]", fn)

    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 8000, 8080, 8443]
    for idx in range(381, 441):
        if idx == 381:
            registry[f"{idx:03d}"] = ("IP Geolocation Lookup", lambda: console.print(fetch_ip_data(console.input("IP (blank=self): ").strip())))
        elif idx == 382:
            registry[f"{idx:03d}"] = ("CIDR Subnet Info", lambda: console.print(str(ipaddress.ip_network(console.input("CIDR: ").strip(), strict=False))))
        else:
            p = common_ports[(idx - 383) % len(common_ports)]
            registry[f"{idx:03d}"] = (f"TCP Port {p} Check [{idx}]", lambda port=p: _check_single_port(port))

    util_ops = [
        ("Local File Forensics", lambda: console.print(json.dumps(inspect_file_deep(console.input("File path: ").strip().strip('"')), indent=2))),
        ("JWT Token Decoder", lambda: console.print(json.dumps(decode_jwt_unverified(console.input("JWT: ").strip()), indent=2))),
        ("SHA256 Generator", lambda: console.print(hashlib.sha256(console.input("Text: ").encode()).hexdigest())),
        ("Phone OSINT", phone_osint),
        ("YouTube OSINT", youtube_channel_osint),
        ("WhatsApp Link & Dork", deep_whatsapp_osint),
    ]
    for idx in range(441, 501):
        label, fn = util_ops[(idx - 441) % len(util_ops)]
        registry[f"{idx:03d}"] = (f"{label} [{idx}]", fn)

    return registry


def registry_500_explorer():
    console.print("\n[bold yellow][15] 500-Option Operational Registry Explorer[/bold yellow]")
    registry = _build_500_registry()
    keys = sorted(registry.keys())
    page = 1
    page_size = 25
    total_pages = (len(keys) + page_size - 1) // page_size

    while True:
        start = (page - 1) * page_size
        end = start + page_size
        console.print(f"\n[bold cyan]Options {start + 1}–{min(end, len(keys))} of {len(keys)} (Page {page}/{total_pages})[/bold cyan]")
        for k in keys[start:end]:
            console.print(f"[{k}] {registry[k][0]}")
        console.print("[ n ] Next | [ p ] Prev | [ g ] Jump # (1-500) | [ b ] Back to Main Menu")

        cmd = console.input("\n[bold cyan]Select option (001-500) or command (n/p/g/b): [/bold cyan]").strip().lower()
        if cmd == "b":
            break
        elif cmd == "n":
            page = min(total_pages, page + 1)
        elif cmd == "p":
            page = max(1, page - 1)
        elif cmd == "g":
            num = console.input("Enter option number (1-500): ").strip()
            if num.isdigit() and 1 <= int(num) <= len(registry):
                key = f"{int(num):03d}"
                console.print(f"\n[bold yellow][{key}] {registry[key][0]}[/bold yellow]")
                registry[key][1]()
                console.input("\n[dim]Press Enter to continue...[/dim]")
            else:
                console.print("[red][-] Invalid number.[/red]")
        else:
            key = f"{int(cmd):03d}" if cmd.isdigit() else cmd
            if key in registry:
                console.print(f"\n[bold yellow][{key}] {registry[key][0]}[/bold yellow]")
                registry[key][1]()
                console.input("\n[dim]Press Enter to continue...[/dim]")
            else:
                console.print("[red][-] Unknown option.[/red]")


MENU = {
    "1": ("Phone Number OSINT Intelligence", phone_osint),
    "2": ("Multi-Platform Username OSINT (JSON Rules)", username_batch_osint),
    "3": ("Deep Domain Recon (DNS, SSL, RDAP, crt.sh, Wayback)", domain_deep_osint),
    "4": ("Web Public Endpoints Audit (JSON Rules)", web_paths_audit),
    "5": ("IP Address Intelligence Lookup", ip_lookup),
    "6": ("YouTube Channel Metadata, Avatar & RSS OSINT", youtube_channel_osint),
    "7": ("Local File Forensics (Magic Bytes, EXIF, Strings)", file_forensics),
    "8": ("JWT Header & Payload Decoder", jwt_decoder_tool),
    "9": ("Cryptographic Hash Generator", hash_tool),
    "10": ("Targeted OSINT Search Query Builder", google_dork_builder),
    "11": ("Fast Multi-Threaded Username OSINT", fast_username_osint),
    "12": ("HTTP Security Headers & WAF / CDN Detector", headers_and_waf_audit),
    "13": ("Deep WhatsApp Public Link & Dork Helper", deep_whatsapp_osint),
    "14": ("Base64 & URL Encoder / Decoder", codec_utility),
    "15": ("500-Option Operational Registry Explorer", registry_500_explorer),
}


def main():
    while True:
        banner()
        for k in sorted(MENU.keys(), key=int):
            console.print(f"[{k:>2}] {MENU[k][0]}")
        console.print("[ 0] Exit")

        choice = console.input("\n[bold cyan]Select option: [/bold cyan]").strip()
        if choice == "0":
            console.print("[bold red]Exiting ELVORIX-OSINT. Stay ethical![/bold red]")
            sys.exit(0)
        elif choice in MENU:
            MENU[choice][1]()
        else:
            console.print("[red][-] Invalid option.[/red]")

        console.input("\n[dim]Press Enter to return to menu...[/dim]")


if __name__ == "__main__":
    main()
