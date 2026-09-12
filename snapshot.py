#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
 SNAPSHOT — Kairyx Security Solutions · Fulfillment engine for the $297 scan

 Turns a domain into a branded external-security report:
   DNS / SPF / DMARC · SSL certificate · HTTP security headers → risk score.

 USAGE:
   python3 snapshot.py example.com                 # scan + write report.html
   python3 snapshot.py example.com --out out.html  # custom output path
   python3 snapshot.py --queue                     # process paid sales (fulfillment)
   python3 snapshot.py example.com --no-db          # skip Supabase write

 SETUP:
   pip install -r requirements.txt   (dnspython optional; falls back to nslookup)
   Env (optional): SUPABASE_URL, SUPABASE_KEY (service_role), RESEND_API_KEY,
                   FROM_EMAIL, BOOKING_URL, COMPANY_NAME, WEBSITE
═══════════════════════════════════════════════════════════════════════════
"""

import os
import ssl
import sys
import json
import socket
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from urllib.request import Request, urlopen
from urllib.error import URLError, HTTPError

import nexus_env  # noqa: F401 — auto-sniffs .env anywhere + normalizes keys + mkdirs


# ── config ──────────────────────────────────────────────────────────────────
class C:
    SUPABASE_URL  = os.getenv('SUPABASE_URL', '')
    SUPABASE_KEY  = os.getenv('SUPABASE_KEY', '')
    RESEND_API_KEY = os.getenv('RESEND_API_KEY', '')
    FROM_EMAIL    = os.getenv('FROM_EMAIL', 'Kairyx Security <security@bugreaper-x.ca>')
    REPLY_TO      = os.getenv('REPLY_TO', 'kairyx@bugreaper-x.ca')
    BOOKING_URL   = os.getenv('BOOKING_URL', 'https://cal.com/kairyx/security-snapshot')
    COMPANY_NAME  = os.getenv('COMPANY_NAME', 'Kairyx Security Solutions')
    WEBSITE       = os.getenv('WEBSITE', 'https://bugreaper-x.ca')

cfg = C()
TIMEOUT = 8


# ── DNS helpers (dnspython if present, else nslookup) ────────────────────────
def _dns(domain: str, rtype: str):
    try:
        import dns.resolver  # type: ignore
        r = dns.resolver.resolve(domain, rtype, lifetime=TIMEOUT)
        return [x.to_text().strip('"') for x in r]
    except Exception:
        pass
    try:
        out = subprocess.run(
            ["nslookup", "-type=" + rtype, domain],
            capture_output=True, text=True, timeout=TIMEOUT,
        ).stdout
        vals = []
        for line in out.splitlines():
            line = line.strip()
            if rtype == "TXT" and '"' in line:
                vals.append(line.split('"', 1)[1].rsplit('"', 1)[0])
            elif rtype == "MX" and "mail exchanger" in line.lower():
                vals.append(line.split("=")[-1].strip())
            elif rtype == "A" and line.lower().startswith("address"):
                vals.append(line.split(":")[-1].strip())
        return vals
    except Exception:
        return []


def check_dns(domain: str) -> dict:
    # Performance Optimization: Concurrently resolve independent DNS query types (A, MX, TXT, _dmarc TXT)
    # using ThreadPoolExecutor. Reduces total check_dns latency from sum(T_dns) to max(T_dns) (~4x speedup).
    with ThreadPoolExecutor(max_workers=4) as executor:
        f_a     = executor.submit(_dns, domain, "A")
        f_mx    = executor.submit(_dns, domain, "MX")
        f_txt   = executor.submit(_dns, domain, "TXT")
        f_dmarc = executor.submit(_dns, "_dmarc." + domain, "TXT")
        a     = f_a.result()
        mx    = f_mx.result()
        txt   = f_txt.result()
        dmarc = f_dmarc.result()

    spf = next((t for t in txt if t.lower().startswith("v=spf1")), "")
    dmarc_rec = next((t for t in dmarc if t.lower().startswith("v=dmarc1")), "")
    return {
        "resolves": bool(a),
        "has_mail": bool(mx),
        "spf": spf,
        "dmarc": dmarc_rec,
    }


# ── SSL certificate ──────────────────────────────────────────────────────────
def check_ssl(domain: str) -> dict:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ss:
                cert = ss.getpeercert()
        exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
        days = (exp - datetime.now(timezone.utc)).days
        issuer = dict(x[0] for x in cert.get("issuer", [])).get("organizationName", "Unknown")
        return {"valid": True, "days_to_expiry": days, "issuer": issuer}
    except Exception as e:
        return {"valid": False, "error": str(e)[:120]}


# ── HTTP security headers ────────────────────────────────────────────────────
def check_headers(domain: str) -> dict:
    res = {"https_ok": False, "redirects_https": False}
    try:
        req = Request("https://" + domain, headers={"User-Agent": "KairyxSnapshot/1.0"})
        with urlopen(req, timeout=TIMEOUT) as r:
            res["https_ok"] = True
            h = {k.lower(): v for k, v in r.headers.items()}
        res["hsts"]     = "strict-transport-security" in h
        res["csp"]      = "content-security-policy" in h
        res["xfo"]      = "x-frame-options" in h
        res["xcto"]     = "x-content-type-options" in h
        res["referrer"] = "referrer-policy" in h
    except (URLError, HTTPError, ssl.SSLError, socket.timeout, Exception):
        pass
    try:
        req = Request("http://" + domain, headers={"User-Agent": "KairyxSnapshot/1.0"})
        with urlopen(req, timeout=TIMEOUT) as r:
            res["redirects_https"] = r.url.startswith("https://")
    except Exception:
        pass
    return res


# ── scoring ──────────────────────────────────────────────────────────────────
def score(dns_r: dict, ssl_r: dict, hdr: dict) -> tuple:
    """Return (risk_score 0-100, band, issues[]). Higher score = more exposed."""
    issues, pts = [], 0

    def add(sev, p, title, detail, fix):
        nonlocal pts
        pts += p
        issues.append({"severity": sev, "title": title, "detail": detail, "fix": fix})

    if not dns_r.get("spf"):
        add("high", 18, "No SPF record",
            "Anyone can send email that appears to come from your domain — a common vector for invoice fraud and phishing your clients.",
            "Publish an SPF TXT record listing your legitimate mail servers.")
    if not dns_r.get("dmarc"):
        add("high", 18, "No DMARC policy",
            "Without DMARC, spoofed email using your name is not rejected or reported.",
            "Add a DMARC TXT record at _dmarc (start with p=none to monitor, then enforce).")
    if not ssl_r.get("valid"):
        add("critical", 25, "TLS/SSL problem",
            f"Secure connection to the site failed ({ssl_r.get('error','no valid certificate')}). Visitors may see warnings or be exposed to interception.",
            "Install/renew a valid TLS certificate (Let's Encrypt is free).")
    else:
        d = ssl_r.get("days_to_expiry", 999)
        if d < 0:
            add("critical", 20, "SSL certificate expired", "The certificate has expired; browsers will block the site.", "Renew immediately.")
        elif d < 15:
            add("medium", 10, "SSL certificate expiring soon", f"Certificate expires in {d} days.", "Renew now and enable auto-renewal.")
    if hdr.get("https_ok") and not hdr.get("redirects_https"):
        add("medium", 10, "HTTP not forced to HTTPS", "Visitors on http:// are not redirected to the secure site.", "Add a 301 redirect from http to https.")
    for key, p, name, why in [
        ("hsts", 6, "HSTS", "forces browsers to always use HTTPS"),
        ("csp", 6, "Content-Security-Policy", "limits injected/malicious scripts"),
        ("xfo", 5, "X-Frame-Options", "prevents clickjacking"),
        ("xcto", 4, "X-Content-Type-Options", "stops MIME-type attacks"),
        ("referrer", 3, "Referrer-Policy", "controls data leaked in referrers"),
    ]:
        if hdr.get("https_ok") and not hdr.get(key):
            add("low", p, f"Missing {name} header", f"This header {why}.", f"Add the {name} response header.")

    sc = min(pts, 100)
    band = "Low" if sc < 25 else "Medium" if sc < 50 else "High" if sc < 75 else "Critical"
    return sc, band, issues


# ── report ───────────────────────────────────────────────────────────────────
_CSS = """
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#1a1a1a;max-width:720px;margin:0 auto;padding:32px;line-height:1.6}
.hdr{border-bottom:3px solid #2563eb;padding-bottom:16px;margin-bottom:24px}
.hdr h1{margin:0;font-size:22px}.hdr p{margin:4px 0 0;color:#666;font-size:13px}
.score{display:flex;align-items:center;gap:20px;background:#f8fafc;border-radius:10px;padding:20px;margin:20px 0}
.badge{font-size:40px;font-weight:800;padding:14px 22px;border-radius:10px;color:#fff}
.i-critical{border-left:4px solid #b91c1c}.i-high{border-left:4px solid #ea580c}
.i-medium{border-left:4px solid #ca8a04}.i-low{border-left:4px solid #2563eb}
.issue{background:#fff;border:1px solid #eee;border-radius:8px;padding:14px 16px;margin:10px 0}
.issue h3{margin:0 0 4px;font-size:15px}.issue .fix{color:#065f46;font-size:13px;margin-top:6px}
.sev{font-size:11px;text-transform:uppercase;font-weight:700;letter-spacing:.5px}
.cta{background:#2563eb;color:#fff;padding:14px 26px;text-decoration:none;border-radius:8px;font-weight:700;display:inline-block;margin:8px 0}
.foot{color:#999;font-size:11px;border-top:1px solid #eee;margin-top:28px;padding-top:14px}
"""

_BAND_COLOR = {"Low": "#16a34a", "Medium": "#ca8a04", "High": "#ea580c", "Critical": "#b91c1c"}


def render_html(domain: str, sc: int, band: str, issues: list) -> str:
    color = _BAND_COLOR.get(band, "#2563eb")
    when = datetime.now(timezone.utc).strftime("%B %d, %Y")
    rows = ""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for it in sorted(issues, key=lambda x: order.get(x["severity"], 9)):
        rows += (
            f'<div class="issue i-{it["severity"]}">'
            f'<div class="sev" style="color:{_BAND_COLOR.get(it["severity"].capitalize(),"#2563eb")}">{it["severity"]}</div>'
            f'<h3>{it["title"]}</h3><div>{it["detail"]}</div>'
            f'<div class="fix">✔ Fix: {it["fix"]}</div></div>'
        )
    if not issues:
        rows = '<div class="issue i-low"><h3>No major external issues found</h3>' \
               '<div>Your public-facing basics look solid. A deeper internal review is still recommended.</div></div>'
    summary = (
        f"We found <strong>{len(issues)} issue(s)</strong> in {domain}'s public security posture. "
        f"Overall exposure is rated <strong style='color:{color}'>{band}</strong>. "
        "The items below are ordered by how much risk they carry to your business and clients."
    )
    return (
        f'<!DOCTYPE html><html><head><meta charset="utf-8"><title>Security Snapshot — {domain}</title>'
        f'<style>{_CSS}</style></head><body>'
        f'<div class="hdr"><h1>Security Snapshot</h1>'
        f'<p>{domain} · {when} · Prepared by {cfg.COMPANY_NAME}</p></div>'
        f'<div class="score"><div class="badge" style="background:{color}">{sc}</div>'
        f'<div><div style="font-size:13px;color:#666">EXPOSURE SCORE (0 = safest)</div>'
        f'<div style="font-size:20px;font-weight:700;color:{color}">{band} risk</div></div></div>'
        f'<p>{summary}</p>{rows}'
        f'<h3>What happens next</h3>'
        f'<p>Fixing the items above closes the gaps an attacker would find first. Want us to walk you '
        f'through them and re-scan after — or take the fixes off your plate on a monthly retainer?</p>'
        f'<a class="cta" href="{cfg.BOOKING_URL}">Book a 15-minute review call</a>'
        f'<div class="foot">{cfg.COMPANY_NAME} · <a href="{cfg.WEBSITE}">{cfg.WEBSITE}</a> · '
        f'This report reflects externally observable configuration only, as of {when}.</div>'
        f'</body></html>'
    )


# ── scan orchestration ───────────────────────────────────────────────────────
def scan(domain: str) -> dict:
    domain = domain.strip().lower().replace("https://", "").replace("http://", "").strip("/")
    # Performance Optimization: Run independent network I/O checks (DNS, SSL, HTTP headers)
    # concurrently using ThreadPoolExecutor to reduce total scan latency from T_dns+T_ssl+T_hdr
    # down to max(T_dns, T_ssl, T_hdr) (~3x-4x latency reduction).
    with ThreadPoolExecutor(max_workers=3) as executor:
        f_dns = executor.submit(check_dns, domain)
        f_ssl = executor.submit(check_ssl, domain)
        f_hdr = executor.submit(check_headers, domain)
        dns_r = f_dns.result()
        ssl_r = f_ssl.result()
        hdr   = f_hdr.result()

    sc, band, issues = score(dns_r, ssl_r, hdr)
    return {
        "domain": domain, "risk_score": sc, "risk_band": band,
        "issues": issues,
        "findings": {"dns": dns_r, "ssl": ssl_r, "headers": hdr},
        "report_html": render_html(domain, sc, band, issues),
    }


# ── persistence (optional) ───────────────────────────────────────────────────
def _db():
    if not (cfg.SUPABASE_URL and cfg.SUPABASE_KEY):
        return None
    try:
        from supabase import create_client
        return create_client(cfg.SUPABASE_URL, cfg.SUPABASE_KEY)
    except Exception as e:
        print(f"[!] Supabase unavailable: {e}")
        return None


def save_snapshot(client, r: dict, sale_id=None, lead_id=None) -> str:
    row = {
        "domain": r["domain"], "risk_score": r["risk_score"], "risk_band": r["risk_band"],
        "findings": r["findings"], "report_html": r["report_html"], "status": "generated",
    }
    if sale_id: row["sale_id"] = sale_id
    if lead_id: row["lead_id"] = lead_id
    out = client.table("snapshots").insert(row).execute()
    return (out.data or [{}])[0].get("id", "")


def email_report(to: str, domain: str, html: str) -> bool:
    if not cfg.RESEND_API_KEY:
        return False
    try:
        import resend
        resend.api_key = cfg.RESEND_API_KEY
        resend.Emails.send({
            "from": cfg.FROM_EMAIL, "to": [to], "reply_to": cfg.REPLY_TO,
            "subject": f"Your Security Snapshot — {domain}", "html": html,
        })
        return True
    except Exception as e:
        print(f"[!] email failed: {e}")
        return False


# ── queue mode: fulfill paid sales ───────────────────────────────────────────
def run_queue():
    client = _db()
    if not client:
        print("[✗] Supabase required for --queue (SUPABASE_URL + service_role KEY).")
        return
    sales = (client.table("sales").select("*")
             .eq("status", "paid").not_.is_("domain", "null").limit(25).execute()).data or []
    print(f"[i] {len(sales)} paid sale(s) awaiting a Snapshot.")
    for s in sales:
        dom = s["domain"]
        print(f"  → scanning {dom} for {s.get('customer_email','?')}")
        r = scan(dom)
        try:
            snap_id = save_snapshot(client, r, sale_id=s["id"])
            delivered = email_report(s["customer_email"], dom, r["report_html"]) if s.get("customer_email") else False
            client.table("snapshots").update({"status": "sent" if delivered else "generated"}).eq("id", snap_id).execute()
            client.table("sales").update({"status": "delivered" if delivered else "scanning"}).eq("id", s["id"]).execute()
            print(f"    [{ '✓ delivered' if delivered else '• generated (no email sent)' }] score={r['risk_score']} ({r['risk_band']})")
        except Exception as e:
            print(f"    [✗] {e}")


# ── CLI ──────────────────────────────────────────────────────────────────────
def main():
    p = argparse.ArgumentParser(description="Kairyx Security Snapshot generator")
    p.add_argument("domain", nargs="?", help="Domain to scan")
    p.add_argument("--out", default="", help="Output HTML path (default: snapshots_out/<domain>_<date>.html)")
    p.add_argument("--no-db", action="store_true", help="Skip Supabase write")
    p.add_argument("--queue", action="store_true", help="Fulfill paid sales")
    a = p.parse_args()

    if a.queue:
        run_queue()
        return
    if not a.domain:
        p.print_help()
        return

    r = scan(a.domain)
    print("=" * 55)
    print(f"  SNAPSHOT — {r['domain']}")
    print("=" * 55)
    print(f"  Exposure score: {r['risk_score']}/100  ({r['risk_band']} risk)")
    for it in r["issues"]:
        print(f"   [{it['severity'].upper():8}] {it['title']}")
    if not r["issues"]:
        print("   No major external issues found.")
    out_path = a.out or os.path.join("snapshots_out", f"{r['domain']}_{datetime.now().strftime('%Y%m%d')}.html")
    os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(r["report_html"])
    print(f"\n  Report written: {out_path}")

    if not a.no_db:
        client = _db()
        if client:
            try:
                sid = save_snapshot(client, r)
                print(f"  Saved to snapshots (id: {sid})")
            except Exception as e:
                print(f"  [!] DB write skipped: {e}")


if __name__ == "__main__":
    main()
