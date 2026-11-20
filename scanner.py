import os
import re
import sys
import json
import hashlib
import xml.etree.ElementTree as ET
from urllib.parse import quote

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
            "[bold red]ELVORIX-OSINT[/bold red] [bold white]- Modular Reconnaissance & Forensics Suite[/bold white]\n"
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


def phone_osint():
    console.print("\n[bold yellow][1] Phone Number OSINT Intelligence[/bold yellow]")
    raw = console.input("Enter phone with country code (e.g., +919876543210): ").strip()
    try:
        parsed = phonenumbers.parse(raw, None)
        e164 = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164)
        intl = phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL)
        digits = re.sub(r"\D", "", e164)
        region = geocoder.description_for_number(parsed, "en") or "Unknown"
        sim_carrier = carrier.name_for_number(parsed, "en") or "Unknown / Ported"
        tz_list = timezone.time_zones_for_number(parsed)
        ntype = get_number_type_label(parsed)

        data = {
            "e164": e164,
            "international": intl,
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


def web_paths_audit():
    console.print("\n[bold yellow][4] Web Public Files & Endpoints Audit[/bold yellow]")
    domain = console.input("Enter domain (e.g., example.com): ").strip()
    if not domain:
        console.print("[red][-] Domain cannot be empty.[/red]")
        return

    clean_domain = domain.replace("https://", "").replace("http://", "").split("/")[0].strip()
    rules = load_json_rules(os.path.join("data", "web_checks.json"))
    matches = run_rule_batch(rules, clean_domain, workers=10)
    for m in matches:
        console.print(f"    [bold green][+] {m['name']:<22}:[/bold green] {m['final_url']} (HTTP {m['status']})")
    console.print(f"\n[bold cyan][*] Accessible endpoints: {len(matches)}/{len(rules)}[/bold cyan]")


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
    console.print(table)


def youtube_channel_osint():
    console.print("\n[bold yellow][6] YouTube Channel Public Metadata & RSS OSINT[/bold yellow]")
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

        avatar_m = re.search(r'<meta\s+property="og:image"\s+content="(https://[^"]+)"', html)
        avatar_url = avatar_m.group(1) if avatar_m else "Not found in static HTML"

        console.print(f"[green][+] Channel Name :[/green] {title}")
        console.print(f"[green][+] Handle       :[/green] @{handle}")
        console.print(f"[green][+] Channel ID   :[/green] {id_m or 'Not found in static HTML'}")
        console.print(f"[green][+] Avatar URL   :[/green] {avatar_url}")

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
                    console.print(f"    {idx}. [{pub}] {v_title} -> https://www.youtube.com/watch?v={v_id}")
    except Exception as e:
        console.print(f"[red][-] YouTube OSINT error: {e}[/red]")


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


def jwt_decoder_tool():
    console.print("\n[bold yellow][8] JWT Header & Payload Decoder[/bold yellow]")
    token = console.input("Paste JWT token: ").strip()
    decoded = decode_jwt_unverified(token)
    if "error" in decoded:
        console.print(f"[red][-] {decoded['error']}[/red]")
        return
    console.print(json.dumps(decoded, indent=2))


def hash_tool():
    console.print("\n[bold yellow][9] Hash Generator (MD5 / SHA1 / SHA256 / SHA512)[/bold yellow]")
    text = console.input("Enter text: ")
    b = text.encode("utf-8")
    console.print(f"MD5    : {hashlib.md5(b).hexdigest()}")
    console.print(f"SHA1   : {hashlib.sha1(b).hexdigest()}")
    console.print(f"SHA256 : {hashlib.sha256(b).hexdigest()}")
    console.print(f"SHA512 : {hashlib.sha512(b).hexdigest()}")


def google_dork_builder():
    console.print("\n[bold yellow][10] Targeted OSINT Search Query Builder[/bold yellow]")
    target = console.input("Enter domain, handle, or keyword: ").strip()
    queries = [
        f"site:{target}",
        f'"{target}" filetype:pdf OR filetype:xlsx OR filetype:csv',
        f'"{target}" site:github.com OR site:gitlab.com',
        f'"{target}" intitle:"index of"',
    ]
    for q in queries:
        console.print(f"• {q} -> https://www.google.com/search?q={quote(q)}")


MENU = {
    "1": ("Phone Number OSINT", phone_osint),
    "2": ("Multi-Platform Username OSINT (JSON Rules)", username_batch_osint),
    "3": ("Deep Domain Recon (DNS, SSL, RDAP, crt.sh, Wayback)", domain_deep_osint),
    "4": ("Web Public Endpoints Audit (JSON Rules)", web_paths_audit),
    "5": ("IP Intelligence Lookup", ip_lookup),
    "6": ("YouTube Channel Metadata & RSS OSINT", youtube_channel_osint),
    "7": ("Local File Forensics (Magic Bytes, EXIF, Strings)", file_forensics),
    "8": ("JWT Header/Payload Decoder", jwt_decoder_tool),
    "9": ("Cryptographic Hash Generator", hash_tool),
    "10": ("OSINT Search Query Builder", google_dork_builder),
}


def main():
    while True:
        banner()
        for k in sorted(MENU.keys(), key=int):
            console.print(f"[{k:>2}] {MENU[k][0]}")
        console.print("[ 0] Exit")

        choice = console.input("\n[bold cyan]Select option: [/bold cyan]").strip()
        if choice == "0":
            console.print("[bold red]Exiting ELVORIX-OSINT.[/bold red]")
            sys.exit(0)
        elif choice in MENU:
            MENU[choice][1]()
        else:
            console.print("[red][-] Invalid option.[/red]")

        console.input("\n[dim]Press Enter to continue...[/dim]")


if __name__ == "__main__":
    main()
