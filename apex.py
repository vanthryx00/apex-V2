#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
 APEX Revenue Engine v2 — Kairyx Security Solutions
 Fort Saskatchewan, Alberta

 Cold email outreach → Resend delivery → Supabase tracking

 USAGE:
   python3 apex.py setup                    # Check config
   python3 apex.py test you@email.com       # Test Resend
   python3 apex.py blast --dry-run          # Preview emails
   python3 apex.py blast --seed-only        # Send to seed leads
   python3 apex.py blast --limit 10         # Send step 1 to 10 Supabase leads
   python3 apex.py followup --dry-run       # Preview due follow-ups (steps 2-4)
   python3 apex.py followup --limit 10      # Send due follow-ups
   python3 apex.py stats                    # Pipeline stats

 SETUP:
   1. Set RESEND_API_KEY in environment
   2. Verify bugreaper-x.ca domain in Resend
   3. Optional: Set SUPABASE_URL + SUPABASE_KEY for tracking
═══════════════════════════════════════════════════════════════════════════
"""

import os
import sys
import time
import argparse
from datetime import datetime, timezone
from typing import Dict, List

# Load .env automatically so config works in any shell (Git Bash, CMD, PowerShell).
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass


# ═══════════════════════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

class Config:
    RESEND_API_KEY   = os.getenv('RESEND_API_KEY', '')
    FROM_EMAIL       = os.getenv('FROM_EMAIL', 'Kairyx Security <security@bugreaper-x.ca>')
    REPLY_TO         = os.getenv('REPLY_TO', 'kairyx@bugreaper-x.ca')
    SUPABASE_URL     = os.getenv('SUPABASE_URL', '')
    SUPABASE_KEY     = os.getenv('SUPABASE_KEY', '')
    BOOKING_URL      = os.getenv('BOOKING_URL', 'https://cal.com/kairyx/security-snapshot')
    COMPANY_NAME     = os.getenv('COMPANY_NAME', 'Kairyx Security Solutions')
    SENDER_NAME      = os.getenv('SENDER_NAME', 'Kairyx Security')
    WEBSITE          = os.getenv('WEBSITE', 'https://bugreaper-x.ca')
    PHYSICAL_ADDRESS = os.getenv('PHYSICAL_ADDRESS', 'Fort Saskatchewan, AB T8L, Canada')

config = Config()


# ═══════════════════════════════════════════════════════════════════════════
# SEED LEADS — confirmed targets, always available without Supabase
# ═══════════════════════════════════════════════════════════════════════════

SEEDS = [
    {"email": "office@freedomlaw.ca",          "name": "Freedom Law",                     "contact": "",     "type": "legal"},
    {"email": "dan@mdlawgroup.ca",             "name": "MD Law Group",                    "contact": "Dan",  "type": "legal"},
    {"email": "info@karislaw.ca",              "name": "Karis Law Office",                "contact": "",     "type": "legal"},
    {"email": "hans@fortlaw.ca",               "name": "Fort Law Office",                 "contact": "Hans", "type": "legal"},
    {"email": "info@wladr.ca",                 "name": "Wilson Law & Dispute Resolution", "contact": "",     "type": "legal"},
    {"email": "info@jenkins-law.com",          "name": "JJM Barristers & Solicitors",     "contact": "",     "type": "legal"},
    {"email": "info@givens.ca",                "name": "Givens LLP",                      "contact": "",     "type": "financial"},
    {"email": "edmontonwestdental@gmail.com",  "name": "Edmonton West Dental Clinic",     "contact": "",     "type": "healthcare"},
    {"email": "OrchardsDentalClinic@gmail.com","name": "Orchards Dental",                 "contact": "",     "type": "healthcare"},
    {"email": "info@clareviewdental.com",      "name": "Clareview Dental Clinic",         "contact": "",     "type": "healthcare"},
    {"email": "uptown@nationaldental.ca",      "name": "Uptown Dental Centre",            "contact": "",     "type": "healthcare"},
    {"email": "smilezone.office@gmail.com",    "name": "Smile Zone",                      "contact": "",     "type": "healthcare"},
    {"email": "info@dentistsatnorthgate.ca",   "name": "The Dentists at Northgate",       "contact": "",     "type": "healthcare"},
    {"email": "service@f12.net",               "name": "F12.net",                         "contact": "",     "type": "it_services"},
    {"email": "info@fabledsolutions.com",      "name": "Fabled Solutions",                "contact": "",     "type": "it_services"},
    {"email": "info@cloudyne.ca",              "name": "Cloudyne Technologies",           "contact": "",     "type": "it_services"},
    {"email": "mike@giantbyte.com",            "name": "GiantByte Software",              "contact": "Mike", "type": "it_services"},
]


# ═══════════════════════════════════════════════════════════════════════════
# EMAIL TEMPLATES
# ═══════════════════════════════════════════════════════════════════════════

def _footer(biz: str) -> str:
    """CASL-compliant footer with unsubscribe + physical address."""
    return (
        '<hr style="border:none;border-top:1px solid #eee;margin:20px 0;">'
        '<p style="font-size:11px;color:#999;line-height:1.4;">'
        f'You\'re receiving this because {biz} is listed publicly online.<br>'
        f'<a href="mailto:unsubscribe@bugreaper-x.ca?subject=Unsubscribe" style="color:#999;">Unsubscribe</a>'
        f'&nbsp;|&nbsp; {config.COMPANY_NAME} &nbsp;|&nbsp; {config.PHYSICAL_ADDRESS}</p>'
    )


def _button(text: str) -> str:
    """CTA button."""
    return (
        f'<p style="margin:25px 0;"><a href="{config.BOOKING_URL}" '
        'style="background:#2563eb;color:#fff;padding:12px 24px;text-decoration:none;'
        'border-radius:6px;font-weight:bold;display:inline-block;">'
        f'{text}</a></p>'
    )


def _signature() -> str:
    return (
        f'{config.SENDER_NAME}<br>{config.COMPANY_NAME}<br>'
        f'<a href="{config.WEBSITE}">{config.WEBSITE}</a>'
    )


def _wrap(body: str, biz: str) -> str:
    """Wrap body content in a full HTML email."""
    return (
        '<!DOCTYPE html><html><head><meta charset="utf-8"></head>'
        '<body style="font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',Arial,sans-serif;'
        'line-height:1.6;color:#333;max-width:600px;margin:0 auto;padding:20px;">'
        f'{body}{_footer(biz)}</body></html>'
    )


def _greeting(contact: str) -> str:
    return f"Hi {contact}," if contact else "Hi,"


def _legal_template(lead: Dict) -> Dict:
    n = lead["name"]
    g = _greeting(lead.get("contact", ""))
    body = (
        f'<p>{g}</p>'
        '<p>Law firms handle some of the most sensitive data in Canada — client files, '
        'financial records, privileged communications. That makes firms like '
        f'{n} a prime target for ransomware.</p>'
        '<p>I run security assessments for Alberta businesses. This week I\'m offering a '
        '<strong>one-time vulnerability scan for $297</strong> — no subscription, no upsell.</p>'
        '<p>What you get:</p>'
        '<ul style="line-height:1.8;"><li>Full external vulnerability assessment</li>'
        '<li>Detailed report with prioritized fix recommendations</li>'
        '<li>48-hour turnaround</li></ul>'
        f'{_button("Book a Free 15-Min Call")}'
        f'<p>Or just reply to this email.</p><p>{_signature()}</p>'
    )
    return {"subject": f"Quick security question for {n}", "html": _wrap(body, n)}


def _healthcare_template(lead: Dict) -> Dict:
    n = lead["name"]
    g = _greeting(lead.get("contact", ""))
    body = (
        f'<p>{g}</p>'
        '<p>Dental and healthcare clinics in Alberta are under increasing scrutiny for how '
        'they handle patient data. The Privacy Commissioner has been stepping up enforcement, '
        'and a single PIPEDA violation can cost more than most practices expect.</p>'
        f'<p>I help clinics like {n} identify security gaps before they become breaches.</p>'
        '<p>This week I\'m offering a <strong>one-time security scan for $297</strong> — covers '
        'your external exposure, data handling risks, and a plain-English report on what to '
        'fix first.</p>'
        f'{_button("Book a Free 15-Min Call")}'
        f'<p>Or just reply here.</p><p>{_signature()}</p>'
    )
    return {"subject": f"PIPEDA compliance question for {n}", "html": _wrap(body, n)}


def _financial_template(lead: Dict) -> Dict:
    n = lead["name"]
    g = _greeting(lead.get("contact", ""))
    body = (
        f'<p>{g}</p>'
        '<p>Accounting and financial firms are prime targets — you hold tax records, banking '
        'details, and client financial data that attackers actively hunt for.</p>'
        f'<p>I help firms like {n} find security gaps before they turn into breaches.</p>'
        '<p>This week I\'m offering a <strong>one-time security scan for $297</strong> — no '
        'subscription, no upsell, 48-hour turnaround.</p>'
        f'{_button("Book a Free 15-Min Call")}'
        f'<p>Or just reply here.</p><p>{_signature()}</p>'
    )
    return {"subject": f"Security question for {n}", "html": _wrap(body, n)}


def _it_template(lead: Dict) -> Dict:
    n = lead["name"]
    g = _greeting(lead.get("contact", ""))
    body = (
        f'<p>{g}</p>'
        f'<p>You already know security matters — but even IT shops benefit from an outside set '
        f'of eyes. A second-opinion scan catches the gaps internal teams stop seeing.</p>'
        '<p>This week I\'m offering a <strong>one-time external vulnerability scan for $297</strong> '
        '— independent assessment, prioritized report, 48-hour turnaround.</p>'
        f'{_button("Book a Free 15-Min Call")}'
        f'<p>Or just reply here.</p><p>{_signature()}</p>'
    )
    return {"subject": f"Second-opinion security scan for {n}", "html": _wrap(body, n)}


def _default_template(lead: Dict) -> Dict:
    n = lead["name"]
    g = _greeting(lead.get("contact", ""))
    body = (
        f'<p>{g}</p>'
        f'<p>Businesses like {n} are increasingly targeted by ransomware and data breaches. '
        'Most don\'t find out where they\'re exposed until it\'s too late.</p>'
        '<p>This week I\'m offering a <strong>one-time security scan for $297</strong> — a full '
        'external assessment with a plain-English report on what to fix first.</p>'
        f'{_button("Book a Free 15-Min Call")}'
        f'<p>Or just reply here.</p><p>{_signature()}</p>'
    )
    return {"subject": f"Security question for {n}", "html": _wrap(body, n)}


TEMPLATES = {
    "legal":       _legal_template,
    "healthcare":  _healthcare_template,
    "financial":   _financial_template,
    "it_services": _it_template,
}


def _normalize_type(v: str) -> str:
    """Map a free-text `vertical` (from Supabase) to a template key."""
    v = (v or "").lower()
    if any(k in v for k in ("law", "legal", "barrister", "solicitor")):
        return "legal"
    if any(k in v for k in ("dent", "health", "medical", "clinic", "care")):
        return "healthcare"
    if any(k in v for k in ("account", "financ", "tax", "bookkeep", "insur")):
        return "financial"
    if any(k in v for k in ("tech", "software", "cloud", "msp", "managed", "it_services")):
        return "it_services"
    return v


def generate_email(lead: Dict) -> Dict:
    """Generate subject + html for a lead based on its type/vertical."""
    template_fn = TEMPLATES.get(_normalize_type(lead.get("type", "")), _default_template)
    return template_fn(lead)


# ═══════════════════════════════════════════════════════════════════════════
# FOLLOW-UP SEQUENCE (steps 2–4)
# ═══════════════════════════════════════════════════════════════════════════

MAX_STEPS = 4
# Days that must elapse after the PREVIOUS email before the given step is due.
SEQUENCE_GAP_DAYS = {2: 3, 3: 4, 4: 7}   # step2 +3d, step3 +4d, step4 +7d


def _parse_ts(s: str):
    """Parse a Supabase timestamptz string into a UTC-aware datetime."""
    if not s:
        return None
    s = s.strip().replace(" ", "T")
    if s.endswith("+00"):
        s = s[:-3] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


def _followup(lead: Dict, step: int) -> Dict:
    """Short follow-up email for steps 2–4 (references the initial $297 offer)."""
    n = lead["name"]
    g = _greeting(lead.get("contact", ""))
    if step == 2:
        body = (
            f'<p>{g}</p>'
            f'<p>Floating this back to the top of your inbox — security rarely feels urgent '
            f'until it has to be.</p>'
            f'<p>The one-time <strong>$297 security scan</strong> for {n} is still open this '
            f'week. Worth 15 minutes?</p>'
            f'{_button("Book a Free 15-Min Call")}'
            f'<p>Or reply "not now" and I\'ll close the loop.</p><p>{_signature()}</p>'
        )
        subject = f"Re: security scan for {n}"
    elif step == 3:
        body = (
            f'<p>{g}</p>'
            f'<p>A quick sense of what these scans catch: exposed login portals, expired '
            f'certificates, and email settings that let someone send mail <em>as</em> your '
            f'domain. Most firms have at least one open.</p>'
            f'<p>Want me to check {n}? $297, plain-English report in 48 hours.</p>'
            f'{_button("Book a Free 15-Min Call")}'
            f'<p>{_signature()}</p>'
        )
        subject = f"What a security scan finds for {n}"
    else:  # step 4 — polite breakup (CASL-friendly close)
        body = (
            f'<p>{g}</p>'
            f'<p>I\'ll stop here so I\'m not cluttering your inbox. If protecting {n}\'s data '
            f'ever moves up the list, the $297 scan offer stands — just reply to this email.</p>'
            f'<p>Wishing you a breach-free year.</p><p>{_signature()}</p>'
        )
        subject = f"Closing the loop — {n}"
    return {"subject": subject, "html": _wrap(body, n)}


# ═══════════════════════════════════════════════════════════════════════════
# MAILER — Resend delivery
# ═══════════════════════════════════════════════════════════════════════════

class Mailer:
    def __init__(self):
        self.available = False
        self.resend = None
        if not config.RESEND_API_KEY:
            print("[!] RESEND_API_KEY not set — set it in your environment")
            return
        try:
            import resend
            resend.api_key = config.RESEND_API_KEY
            self.resend = resend
            self.available = True
        except ImportError:
            print("[!] Resend not installed — run: pip install resend")

    def send(self, to: str, subject: str, html: str, tags: List[Dict] = None) -> Dict:
        if not self.available:
            return {"status": "failed", "error": "resend not available", "to": to}
        try:
            params = {
                "from": config.FROM_EMAIL,
                "to": [to],
                "subject": subject,
                "html": html,
                "reply_to": config.REPLY_TO,
            }
            if tags:
                params["tags"] = tags
            result = self.resend.Emails.send(params)
            return {"status": "sent", "id": result.get("id", ""), "to": to}
        except Exception as e:
            return {"status": "failed", "error": str(e), "to": to}

    def test(self, to: str) -> bool:
        r = self.send(
            to,
            "APEX Engine — Test Email",
            "<p>Resend + bugreaper-x.ca is working.</p>"
            f"<p><small>{datetime.utcnow().isoformat()} UTC</small></p>",
            [{"name": "campaign", "value": "test"}],
        )
        if r["status"] == "sent":
            print(f"[✓] Test email sent to {to} (id: {r['id']})")
            return True
        print(f"[✗] Test failed: {r.get('error')}")
        return False


# ═══════════════════════════════════════════════════════════════════════════
# DATABASE — Supabase (optional)
# ═══════════════════════════════════════════════════════════════════════════

class Database:
    def __init__(self):
        self.available = False
        self.client = None
        if config.SUPABASE_URL and config.SUPABASE_KEY:
            try:
                from supabase import create_client
                self.client = create_client(config.SUPABASE_URL, config.SUPABASE_KEY)
                self.available = True
            except ImportError:
                print("[!] Supabase not installed — run: pip install supabase")
            except Exception as e:
                print(f"[!] Supabase connection failed: {e}")

    # Only these statuses are eligible for a send (skips sent/replied/won/unsubscribed).
    SENDABLE = ("new", "queued")

    def get_leads(self, limit: int = 50) -> List[Dict]:
        if not self.available:
            return []
        try:
            result = (self.client.table('leads')
                      .select('*')
                      .in_('status', list(self.SENDABLE))
                      .not_.is_('contact_email', 'null')
                      .limit(limit)
                      .execute())
            return [{
                "id": l["id"],
                "email": l["contact_email"],
                "name": l.get("business_name", "Business"),
                "contact": l.get("contact_name") or "",
                "type": l.get("vertical", "business"),
            } for l in (result.data or []) if l.get("contact_email")]
        except Exception as e:
            print(f"[!] Supabase read error: {e}")
            return []

    def mark_sent(self, lead_id, subject: str = "") -> bool:
        if not self.available:
            return False
        try:
            self.client.table('leads').update({
                'status': 'sent',
                'last_contacted_at': datetime.utcnow().isoformat(),
            }).eq('id', lead_id).execute()
            # Append to the outreach audit log (matches live outreach_log schema).
            self.client.table('outreach_log').insert({
                'lead_id': lead_id,
                'channel': 'email',
                'subject': subject,
                'result': 'sent',
            }).execute()
            return True
        except Exception as e:
            print(f"[!] mark_sent error: {e}")
            return False

    def mark_followup(self, lead_id, subject: str, step: int) -> bool:
        if not self.available:
            return False
        try:
            self.client.table('outreach_log').insert({
                'lead_id': lead_id,
                'channel': 'email',
                'subject': subject,
                'result': f'sent_step_{step}',
            }).execute()
            self.client.table('leads').update({
                'last_contacted_at': datetime.now(timezone.utc).isoformat(),
            }).eq('id', lead_id).execute()
            return True
        except Exception as e:
            print(f"[!] mark_followup error: {e}")
            return False

    def get_due_followups(self, limit: int = 50) -> List[Dict]:
        """Leads mid-sequence whose next step is now due (driven by outreach_log)."""
        if not self.available:
            return []
        try:
            leads = (self.client.table('leads').select('*')
                     .eq('status', 'sent')
                     .not_.is_('contact_email', 'null')
                     .limit(500).execute()).data or []
            if not leads:
                return []
            ids = [l['id'] for l in leads]
            logs = (self.client.table('outreach_log')
                    .select('lead_id,sent_at')
                    .in_('lead_id', ids).execute()).data or []
            hist: Dict = {}
            for r in logs:
                hist.setdefault(r['lead_id'], []).append(r.get('sent_at'))
            now = datetime.now(timezone.utc)
            due: List[Dict] = []
            for l in leads:
                times = sorted(t for t in hist.get(l['id'], []) if t)
                count = len(times)
                if count == 0 or count >= MAX_STEPS:
                    continue
                next_step = count + 1
                gap = SEQUENCE_GAP_DAYS.get(next_step, 9999)
                last = _parse_ts(times[-1])
                if last and (now - last).days >= gap:
                    due.append({
                        "lead": {
                            "id": l["id"],
                            "email": l["contact_email"],
                            "name": l.get("business_name", "Business"),
                            "contact": l.get("contact_name") or "",
                            "type": l.get("vertical", "business"),
                        },
                        "step": next_step,
                    })
                if len(due) >= limit:
                    break
            return due
        except Exception as e:
            print(f"[!] followup query error: {e}")
            return []

    def stats(self) -> Dict:
        if not self.available:
            return {}
        try:
            total = self.client.table('leads').select('id', count='exact').execute()
            sent = self.client.table('leads').select('id', count='exact').eq(
                'status', 'sent').execute()
            return {
                "total": total.count or 0,
                "sent": sent.count or 0,
                "remaining": (total.count or 0) - (sent.count or 0),
            }
        except Exception as e:
            print(f"[!] stats error: {e}")
            return {}


# ═══════════════════════════════════════════════════════════════════════════
# COMMANDS
# ═══════════════════════════════════════════════════════════════════════════

def cmd_setup():
    print("=" * 55)
    print("  APEX SETUP CHECK")
    print("=" * 55)
    checks = [
        ("RESEND_API_KEY", bool(config.RESEND_API_KEY)),
        ("FROM_EMAIL", bool(config.FROM_EMAIL)),
        ("BOOKING_URL", bool(config.BOOKING_URL)),
        ("SUPABASE_URL", bool(config.SUPABASE_URL)),
        ("SUPABASE_KEY", bool(config.SUPABASE_KEY)),
    ]
    for name, ok in checks:
        mark = "✓" if ok else "✗"
        note = "" if ok else "  (not set)"
        print(f"  [{mark}] {name}{note}")
    print()
    try:
        import resend  # noqa
        print("  [✓] resend package installed")
    except ImportError:
        print("  [✗] resend package missing — pip install resend")
    print(f"\n  Seed leads available: {len(SEEDS)}")
    print("  Ready to test:  python3 apex.py test you@email.com")


def cmd_test(email: str):
    Mailer().test(email)


def cmd_blast(args):
    mailer = Mailer()
    if not mailer.available and not args.dry_run:
        print("[✗] Mailer not available. Set RESEND_API_KEY and pip install resend.")
        return

    db = Database()

    # Build the lead list
    if args.seed_only or not db.available:
        leads = list(SEEDS)
        source = "seed leads"
    else:
        leads = db.get_leads(limit=args.limit)
        source = "Supabase"
        if not leads:
            print("[!] No unsent Supabase leads; falling back to seeds.")
            leads = list(SEEDS)
            source = "seed leads"

    if args.limit and len(leads) > args.limit:
        leads = leads[:args.limit]

    print("=" * 55)
    print(f"  BLAST — {len(leads)} leads from {source}"
          + ("  (DRY RUN)" if args.dry_run else ""))
    print("=" * 55)

    sent = 0
    for i, lead in enumerate(leads, 1):
        email = generate_email(lead)
        print(f"\n[{i}/{len(leads)}] {lead['name']}  <{lead['email']}>")
        print(f"    Subject: {email['subject']}")

        if args.dry_run:
            print("    [dry run — not sent]")
            continue

        result = mailer.send(
            lead["email"], email["subject"], email["html"],
            tags=[{"name": "type", "value": lead.get("type", "business")}],
        )
        if result["status"] == "sent":
            sent += 1
            print(f"    [✓] sent (id: {result['id']})")
            if lead.get("id") is not None:
                db.mark_sent(lead["id"], email["subject"])
        else:
            print(f"    [✗] {result.get('error')}")

        time.sleep(2)  # rate limit

    if not args.dry_run:
        print(f"\n[✓] Blast complete: {sent}/{len(leads)} sent")


def cmd_followup(args):
    mailer = Mailer()
    if not mailer.available and not args.dry_run:
        print("[✗] Mailer not available. Set RESEND_API_KEY and pip install resend.")
        return
    db = Database()
    if not db.available:
        print("[✗] Follow-ups need send history — set SUPABASE_URL + SUPABASE_KEY (service_role).")
        return

    due = db.get_due_followups(limit=args.limit or 50)
    print("=" * 55)
    print(f"  FOLLOW-UPS — {len(due)} due" + ("  (DRY RUN)" if args.dry_run else ""))
    print("=" * 55)
    if not due:
        print("  Nothing due right now.")
        return

    sent = 0
    for i, item in enumerate(due, 1):
        lead, step = item["lead"], item["step"]
        email = _followup(lead, step)
        print(f"\n[{i}/{len(due)}] step {step}  {lead['name']}  <{lead['email']}>")
        print(f"    Subject: {email['subject']}")

        if args.dry_run:
            print("    [dry run — not sent]")
            continue

        result = mailer.send(
            lead["email"], email["subject"], email["html"],
            tags=[{"name": "step", "value": str(step)}],
        )
        if result["status"] == "sent":
            sent += 1
            print(f"    [✓] sent (id: {result['id']})")
            db.mark_followup(lead["id"], email["subject"], step)
        else:
            print(f"    [✗] {result.get('error')}")
        time.sleep(2)

    if not args.dry_run:
        print(f"\n[✓] Follow-ups complete: {sent}/{len(due)} sent")


def cmd_stats():
    db = Database()
    if not db.available:
        print("[!] Supabase not configured — no stats available.")
        print(f"    Seed leads on hand: {len(SEEDS)}")
        return
    s = db.stats()
    print("=" * 55)
    print("  PIPELINE STATS")
    print("=" * 55)
    print(f"  Total leads:  {s.get('total', 0)}")
    print(f"  Emailed:      {s.get('sent', 0)}")
    print(f"  Remaining:    {s.get('remaining', 0)}")


# ═══════════════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(description="APEX Revenue Engine v2")
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("setup", help="Check configuration")

    t = sub.add_parser("test", help="Send a test email")
    t.add_argument("email", help="Recipient address")

    b = sub.add_parser("blast", help="Send outreach emails (step 1)")
    b.add_argument("--dry-run", action="store_true", help="Preview without sending")
    b.add_argument("--seed-only", action="store_true", help="Use built-in seed leads")
    b.add_argument("--limit", type=int, default=0, help="Max emails to send")

    fu = sub.add_parser("followup", help="Send due follow-ups (steps 2-4)")
    fu.add_argument("--dry-run", action="store_true", help="Preview without sending")
    fu.add_argument("--limit", type=int, default=0, help="Max follow-ups to send")

    sub.add_parser("stats", help="Show pipeline stats")

    args = parser.parse_args()

    if args.command == "setup":
        cmd_setup()
    elif args.command == "test":
        cmd_test(args.email)
    elif args.command == "blast":
        cmd_blast(args)
    elif args.command == "followup":
        cmd_followup(args)
    elif args.command == "stats":
        cmd_stats()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
