import os
import re
import ssl
import json
import socket
from datetime import datetime
from urllib.parse import urlparse, quote
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests

USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def load_json_rules(filepath: str) -> list:
    if not os.path.isfile(filepath):
        return []
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, list) else []


def save_json_report(target_name: str, module_name: str, payload: dict) -> str:
    os.makedirs("reports", exist_ok=True)
    safe_target = re.sub(r"[^a-zA-Z0-9_.-]", "_", target_name)[:40] or "target"
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    filepath = os.path.join("reports", f"{module_name}_{safe_target}_{ts}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(
            {
                "timestamp": datetime.now().isoformat(),
                "suite": "ELVORIX-OSINT",
                "module": module_name,
                "target": target_name,
                "results": payload,
            },
            f,
            indent=2,
            ensure_ascii=False,
        )
    return filepath


def fetch_ip_data(ip_query: str = "") -> dict | None:
    target = ip_query.strip()
    sources = [
        f"http://ip-api.com/json/{target}?fields=status,message,country,regionName,city,zip,lat,lon,timezone,isp,org,as,query,hosting,proxy",
        f"https://ipapi.co/{target + '/' if target else ''}json/",
        f"https://ipinfo.io/{target + '/' if target else ''}json",
    ]

    for url in sources:
        try:
            resp = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=6)
            if resp.status_code != 200:
                continue
            data = resp.json()

            if "status" in data:
                if data.get("status") == "success":
                    return {
                        "ip": data.get("query"),
                        "city": data.get("city"),
                        "region": data.get("regionName"),
                        "country": data.get("country"),
                        "postal": data.get("zip"),
                        "lat": data.get("lat"),
                        "lon": data.get("lon"),
                        "timezone": data.get("timezone"),
                        "isp": data.get("isp"),
                        "org": data.get("org"),
                        "asn": data.get("as"),
                        "proxy_hosting": f"Proxy: {data.get('proxy')} | Hosting: {data.get('hosting')}",
                    }
                continue

            if "ip" in data and not data.get("error"):
                return {
                    "ip": data.get("ip"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country_name"),
                    "postal": data.get("postal"),
                    "lat": data.get("latitude"),
                    "lon": data.get("longitude"),
                    "timezone": data.get("timezone"),
                    "isp": data.get("org"),
                    "org": data.get("org"),
                    "asn": data.get("asn"),
                    "proxy_hosting": "N/A",
                }

            if "ip" in data and "loc" in data:
                loc_parts = str(data.get("loc", ",")).split(",")
                return {
                    "ip": data.get("ip"),
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "postal": data.get("postal"),
                    "lat": loc_parts[0] if len(loc_parts) > 0 else "N/A",
                    "lon": loc_parts[1] if len(loc_parts) > 1 else "N/A",
                    "timezone": data.get("timezone"),
                    "isp": data.get("org"),
                    "org": data.get("org"),
                    "asn": data.get("org"),
                    "proxy_hosting": "N/A",
                }
        except Exception:
            continue
    return None


def deep_domain_audit(raw_domain: str) -> dict:
    domain = urlparse(raw_domain).netloc if "://" in raw_domain else raw_domain.split("/")[0].strip()
    report = {
        "domain": domain,
        "ipv4": [],
        "ipv6": [],
        "reverse_dns": None,
        "ssl": {},
        "security_headers": {},
        "rdap": {},
        "crtsh_subdomains": [],
        "wayback_snapshot": None,
    }

    try:
        report["ipv4"] = sorted({x[4][0] for x in socket.getaddrinfo(domain, None, socket.AF_INET)})
    except Exception:
        pass
    try:
        report["ipv6"] = sorted({x[4][0] for x in socket.getaddrinfo(domain, None, socket.AF_INET6)})
    except Exception:
        pass

    if report["ipv4"]:
        try:
            report["reverse_dns"] = socket.gethostbyaddr(report["ipv4"][0])[0]
        except Exception:
            pass

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=6) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                issuer = dict(x[0] for x in cert.get("issuer", []))
                subject = dict(x[0] for x in cert.get("subject", []))
                sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
                report["ssl"] = {
                    "common_name": subject.get("commonName"),
                    "issuer": issuer.get("organizationName"),
                    "valid_from": cert.get("notBefore"),
                    "valid_until": cert.get("notAfter"),
                    "san_count": len(sans),
                    "sans_sample": sans[:15],
                }
    except Exception as e:
        report["ssl"] = {"error": str(e)}

    try:
        resp = requests.get(f"https://{domain}", headers={"User-Agent": USER_AGENT}, timeout=8)
        important_headers = [
            "Server",
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Frame-Options",
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Permissions-Policy",
        ]
        report["security_headers"] = {
            "status_code": resp.status_code,
            "final_url": resp.url,
            "headers": {h: resp.headers.get(h, "MISSING") for h in important_headers},
        }
    except Exception as e:
        report["security_headers"] = {"error": str(e)}

    try:
        r_rdap = requests.get(f"https://rdap.org/domain/{domain}", headers={"User-Agent": USER_AGENT}, timeout=8)
        if r_rdap.status_code == 200:
            rd = r_rdap.json()
            events = {ev.get("eventAction"): ev.get("eventDate") for ev in rd.get("events", [])}
            nameservers = [ns.get("ldhName") for ns in rd.get("nameservers", []) if ns.get("ldhName")]
            report["rdap"] = {
                "handle": rd.get("handle"),
                "status": rd.get("status", []),
                "events": events,
                "nameservers": nameservers,
            }
    except Exception:
        pass

    try:
        r_crt = requests.get(
            f"https://crt.sh/?q=%25.{quote(domain)}&output=json",
            headers={"User-Agent": USER_AGENT},
            timeout=10,
        )
        if r_crt.status_code == 200:
            subs = set()
            for item in r_crt.json():
                for line in str(item.get("name_value", "")).splitlines():
                    clean = line.strip().lstrip("*.")
                    if clean.endswith(domain):
                        subs.add(clean)
            report["crtsh_subdomains"] = sorted(subs)[:50]
    except Exception:
        pass

    try:
        r_wb = requests.get(
            f"http://archive.org/wayback/available?url={quote(domain)}",
            headers={"User-Agent": USER_AGENT},
            timeout=6,
        )
        if r_wb.status_code == 200:
            closest = r_wb.json().get("archived_snapshots", {}).get("closest")
            if closest:
                report["wayback_snapshot"] = {
                    "timestamp": closest.get("timestamp"),
                    "url": closest.get("url"),
                }
    except Exception:
        pass

    return report


def run_rule_batch(rules: list, target_value: str, workers: int = 15) -> list:
    headers = {"User-Agent": USER_AGENT, "Accept-Language": "en-US,en;q=0.9"}
    matches = []

    def eval_rule(rule):
        url = rule["url_template"].format(target=quote(target_value))
        markers = [m.lower() for m in rule.get("not_found_markers", [])]
        try:
            resp = requests.get(url, headers=headers, timeout=6, allow_redirects=True)
            if resp.status_code != 200:
                return None
            body = resp.text.lower()
            if any(m in body for m in markers):
                return None
            reject_sub = rule.get("reject_redirect_contains")
            if reject_sub and reject_sub.lower() in resp.url.lower():
                return None
            return {"name": rule["name"], "url": url, "final_url": resp.url, "status": resp.status_code}
        except Exception:
            return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(eval_rule, r) for r in rules]
        for fut in as_completed(futures):
            res = fut.result()
            if res:
                matches.append(res)

    return sorted(matches, key=lambda x: x["name"].lower())
