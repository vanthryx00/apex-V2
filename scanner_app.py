#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
 SCANNER APP — Kairyx internal Scan Runner (operator dashboard)

 A local web UI to:
   • run a Security Snapshot on any domain on demand
   • see paid orders waiting for fulfillment and deliver them in one click
   • browse recent snapshots and open any report

 Reuses snapshot.py as the scan engine — no duplicated logic.

 RUN:
   pip install -r requirements.txt
   python scanner_app.py            # → http://localhost:8800
   (optional) set ADMIN_TOKEN=secret to require ?key=secret on every page

 Config (Supabase + Resend keys) is auto-loaded from .env via nexus_env.
═══════════════════════════════════════════════════════════════════════════
"""
import os
import html
import datetime

import nexus_env  # noqa: F401 — auto-loads .env + mkdirs
import snapshot   # scan engine: scan(), _db(), save_snapshot(), email_report()

from flask import Flask, request, Response, redirect, send_from_directory

ADMIN_TOKEN = os.getenv("ADMIN_TOKEN", "")
PORT = int(os.getenv("SCANNER_PORT", "8800"))
OUT = "snapshots_out"

app = Flask(__name__)

CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;background:#0b1220;color:#e6ecf7}
.wrap{max-width:960px;margin:0 auto;padding:26px}
h1{font-size:22px;display:flex;align-items:center;gap:10px}
.dot{width:12px;height:12px;border-radius:3px;background:#2563eb;box-shadow:0 0 0 4px rgba(37,99,235,.25)}
.sub{color:#8fa1c2;font-size:14px;margin:4px 0 22px}
.card{background:#111a2e;border:1px solid #1e2a44;border-radius:14px;padding:20px;margin:16px 0}
.card h2{font-size:16px;margin-bottom:12px;color:#cdd8ef}
input[type=text],input[type=email]{background:#0b1220;border:1px solid #2a3a5c;color:#fff;border-radius:9px;padding:12px 14px;font-size:15px;width:100%}
.row{display:flex;gap:10px;flex-wrap:wrap}
.row>*{flex:1;min-width:180px}
.btn{background:#2563eb;color:#fff;border:0;border-radius:9px;padding:12px 18px;font-weight:700;cursor:pointer;font-size:15px}
.btn:hover{background:#1d4ed8}
.btn.small{padding:8px 12px;font-size:13px}
table{width:100%;border-collapse:collapse;font-size:14px}
th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #1e2a44}
th{color:#8fa1c2;font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.4px}
.link{color:#7aa2f7;font-weight:600}
.badge{display:inline-block;color:#fff;font-weight:800;border-radius:8px;padding:4px 12px}
.b-Low{background:#16a34a}.b-Medium{background:#ca8a04}.b-High{background:#ea580c}.b-Critical{background:#b91c1c}
.flash{background:#0e2a1a;border:1px solid #1f7a4d;color:#7ff0b0;border-radius:9px;padding:12px 14px;margin:12px 0}
.flash.err{background:#2a0e0e;border-color:#7a1f1f;color:#f0a0a0}
.issue{background:#0b1220;border:1px solid #1e2a44;border-left-width:4px;border-radius:8px;padding:12px 14px;margin:8px 0}
.i-critical{border-left-color:#b91c1c}.i-high{border-left-color:#ea580c}.i-medium{border-left-color:#ca8a04}.i-low{border-left-color:#2563eb}
.sev{font-size:11px;text-transform:uppercase;font-weight:700;color:#8fa1c2}
iframe{width:100%;height:640px;border:1px solid #1e2a44;border-radius:10px;background:#fff;margin-top:10px}
a.back{color:#8fa1c2;font-size:14px}
"""


def _guard():
    return not (ADMIN_TOKEN and request.args.get("key") != ADMIN_TOKEN)


def _qs():
    return f"?key={ADMIN_TOKEN}" if ADMIN_TOKEN else ""


def _page(body, flash="", err=False):
    fl = f"<div class='flash {'err' if err else ''}'>{html.escape(flash)}</div>" if flash else ""
    return ("<!DOCTYPE html><html><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>Kairyx Scan Runner</title><style>" + CSS + "</style></head><body><div class='wrap'>"
            "<h1><span class='dot'></span> Kairyx Scan Runner</h1>"
            "<div class='sub'>Internal operator console — run Security Snapshots & fulfill orders</div>"
            + fl + body + "</div></body></html>")


@app.get("/health")
def health():
    return {"status": "ok", "supabase": bool(os.getenv("SUPABASE_URL")), "resend": bool(os.getenv("RESEND_API_KEY"))}, 200


@app.get("/")
def dashboard():
    if not _guard():
        return Response("Unauthorized", 401)

    scan_form = (
        "<div class='card'><h2>Run a scan</h2>"
        f"<form method='post' action='/scan{_qs()}'><div class='row'>"
        "<input type='text' name='domain' placeholder='example.com' required>"
        "<button class='btn' style='flex:0 0 auto'>Run Security Snapshot</button>"
        "</div></form></div>"
    )

    client = snapshot._db()
    if not client:
        return _page(scan_form + "<div class='card'><h2>Orders & history</h2>"
                     "<p class='sub'>Supabase not configured — set SUPABASE_URL + service_role key in .env to see paid orders and history.</p></div>")

    # paid orders awaiting fulfillment
    paid = "<tr><td colspan='3' class='sub'>None waiting.</td></tr>"
    try:
        rows = (client.table("sales").select("*").eq("status", "paid")
                .not_.is_("domain", "null").limit(25).execute()).data or []
        if rows:
            paid = ""
            for s in rows:
                paid += ("<tr><td>" + html.escape(str(s.get("domain") or "")) + "</td><td>"
                         + html.escape(str(s.get("customer_email") or "")) + "</td><td>"
                         f"<form method='post' action='/fulfill/{s['id']}{_qs()}'>"
                         "<button class='btn small'>Scan + email</button></form></td></tr>")
    except Exception as e:
        paid = f"<tr><td colspan='3' class='flash err'>{html.escape(str(e))}</td></tr>"

    # recent snapshots
    hist = "<tr><td colspan='4' class='sub'>No snapshots yet.</td></tr>"
    try:
        snaps = (client.table("snapshots").select("id,domain,risk_score,risk_band,created_at")
                 .order("created_at", desc=True).limit(12).execute()).data or []
        if snaps:
            hist = ""
            for s in snaps:
                band = s.get("risk_band") or "Low"
                hist += ("<tr><td>" + html.escape(str(s.get("domain") or "")) + "</td>"
                         f"<td>{s.get('risk_score')}</td>"
                         f"<td><span class='badge b-{html.escape(band)}'>{html.escape(band)}</span></td>"
                         f"<td><a class='link' href='/report/{s['id']}{_qs()}'>view report</a></td></tr>")
    except Exception as e:
        hist = f"<tr><td colspan='4' class='flash err'>{html.escape(str(e))}</td></tr>"

    body = (scan_form
            + "<div class='card'><h2>Paid orders awaiting fulfillment</h2><table>"
              "<tr><th>Domain</th><th>Customer</th><th>Action</th></tr>" + paid + "</table></div>"
            + "<div class='card'><h2>Recent snapshots</h2><table>"
              "<tr><th>Domain</th><th>Score</th><th>Risk</th><th>Report</th></tr>" + hist + "</table></div>")
    return _page(body)


@app.post("/scan")
def run_scan():
    if not _guard():
        return Response("Unauthorized", 401)
    domain = (request.form.get("domain") or "").strip()
    if not domain:
        return redirect("/" + _qs())
    r = snapshot.scan(domain)

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    fname = f"{r['domain']}_{ts}.html"
    try:
        os.makedirs(OUT, exist_ok=True)
        with open(os.path.join(OUT, fname), "w", encoding="utf-8") as f:
            f.write(r["report_html"])
    except Exception:
        pass

    client = snapshot._db()
    if client:
        try:
            snapshot.save_snapshot(client, r)
        except Exception:
            pass

    issues = ""
    for it in r["issues"]:
        issues += (f"<div class='issue i-{it['severity']}'><div class='sev'>{html.escape(it['severity'])}</div>"
                   f"<b>{html.escape(it['title'])}</b><div class='sub'>{html.escape(it['detail'])}</div></div>")
    if not r["issues"]:
        issues = "<div class='issue i-low'>No major external issues found.</div>"

    band = r["risk_band"]
    body = (f"<a class='back' href='/{_qs()}'>← back to dashboard</a>"
            f"<div class='card'><h2>Result — {html.escape(r['domain'])}</h2>"
            f"<p>Exposure score: <span class='badge b-{html.escape(band)}'>{r['risk_score']} · {html.escape(band)}</span></p>"
            + issues +
            "<h2 style='margin-top:18px'>Email this report</h2>"
            f"<form method='post' action='/email{_qs()}'><input type='hidden' name='file' value='{html.escape(fname)}'>"
            f"<input type='hidden' name='domain' value='{html.escape(r['domain'])}'><div class='row'>"
            "<input type='email' name='to' placeholder='client@example.com' required>"
            "<button class='btn' style='flex:0 0 auto'>Send report</button></div></form>"
            f"<iframe src='/report/file/{html.escape(fname)}{_qs()}'></iframe></div>")
    return _page(body)


@app.post("/fulfill/<sale_id>")
def fulfill(sale_id):
    if not _guard():
        return Response("Unauthorized", 401)
    client = snapshot._db()
    if not client:
        return _page("", "Supabase not configured.", err=True)
    try:
        rows = (client.table("sales").select("*").eq("id", sale_id).limit(1).execute()).data or []
        if not rows:
            return redirect("/" + _qs())
        s = rows[0]
        r = snapshot.scan(s["domain"])
        snap_id = snapshot.save_snapshot(client, r, sale_id=s["id"])
        delivered = snapshot.email_report(s["customer_email"], s["domain"], r["report_html"]) if s.get("customer_email") else False
        client.table("snapshots").update({"status": "sent" if delivered else "generated"}).eq("id", snap_id).execute()
        client.table("sales").update({"status": "delivered" if delivered else "scanning"}).eq("id", s["id"]).execute()
        msg = f"{s['domain']}: score {r['risk_score']} ({r['risk_band']}) — " + ("emailed to " + s['customer_email'] if delivered else "generated (no email)")
        return _page("<a class='back' href='/" + _qs() + "'>← back</a>", msg)
    except Exception as e:
        return _page("<a class='back' href='/" + _qs() + "'>← back</a>", str(e), err=True)


@app.post("/email")
def email_report():
    if not _guard():
        return Response("Unauthorized", 401)
    to = (request.form.get("to") or "").strip()
    fname = os.path.basename(request.form.get("file") or "")
    domain = request.form.get("domain") or ""
    try:
        with open(os.path.join(OUT, fname), "r", encoding="utf-8") as f:
            report_html = f.read()
        ok = snapshot.email_report(to, domain, report_html)
        msg = f"Report for {domain} sent to {to}." if ok else "Email failed — check RESEND_API_KEY / FROM_EMAIL."
        return _page("<a class='back' href='/" + _qs() + "'>← back</a>", msg, err=not ok)
    except Exception as e:
        return _page("<a class='back' href='/" + _qs() + "'>← back</a>", str(e), err=True)


@app.get("/report/file/<name>")
def report_file(name):
    if not _guard():
        return Response("Unauthorized", 401)
    return send_from_directory(OUT, os.path.basename(name))


@app.get("/report/<snapshot_id>")
def report_db(snapshot_id):
    if not _guard():
        return Response("Unauthorized", 401)
    client = snapshot._db()
    if not client:
        return Response("Supabase not configured", 500)
    rows = (client.table("snapshots").select("report_html,domain").eq("id", snapshot_id).limit(1).execute()).data or []
    if not rows:
        return Response("Not found", 404)
    return Response(rows[0].get("report_html") or "<p>No report stored.</p>", mimetype="text/html")


if __name__ == "__main__":
    if not ADMIN_TOKEN:
        print("[!] ADMIN_TOKEN not set — dashboard is open to anyone who can reach this port. Fine for localhost only.")
    print(f"[i] Kairyx Scan Runner on http://localhost:{PORT}")
    try:
        from waitress import serve
        serve(app, host="127.0.0.1", port=PORT)
    except ImportError:
        app.run(host="127.0.0.1", port=PORT)
