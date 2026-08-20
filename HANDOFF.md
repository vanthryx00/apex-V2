# KAIRYX EMPIRE — HANDOFF
**Date:** 2026-08-19 · **Leads/DB:** Vanthryx (`npxpshffkpbqroxegvsj`) · **Domain:** bugreaper-x.ca (verified)

## The money chain is now built end-to-end
```
MyClaw ─▶ leads (Vanthryx) ─▶ apex.py blast (step 1)
                                   └▶ apex.py followup (steps 2–4)
                                          └▶ reply / books call
                                                 └▶ Stripe $297
                                                        └▶ stripe_webhook.py ─▶ sales
                                                               └▶ snapshot.py --queue
                                                                      └▶ scan + branded report ─▶ emailed ─▶ delivered
```

## Done & verified this session
- **Security (Vanthryx): 2 critical exposures → 0.** RLS + policies on every table, `handle_new_user` locked down, sensitive tables removed from the anon API. 3 migrations applied and re-scanned.
- **APEX outreach (`apex.py`):** fixed the schema mismatch that was silently skipping all 15 of your real leads (it queried `email`/`email_sent`; your table uses `contact_email`/`status`). Now reads the real schema, logs every send to `outreach_log`, and has a full **4-step follow-up sequence** (`followup` command). `.env.example` + `requirements.txt` added.
- **Fulfillment (`snapshot.py`, new):** scans a domain (DNS/SPF/DMARC, SSL, security headers) → 0–100 exposure score → branded report → writes to `snapshots`, can email via Resend. `--queue` mode auto-fulfills paid sales. Live-tested.
- **Revenue rail:** `sales` + `snapshots` tables created & secured; `stripe_webhook.py` records signature-verified payments into `sales`.
- **Email:** bugreaper-x.ca verified in Resend, sending enabled.

## Files in this folder
`apex.py` · `snapshot.py` · `stripe_webhook.py` · `.env.example` · `requirements.txt` · `HANDOFF.md`

## What ONLY YOU can do (I can't — secrets, OAuth, your servers)
1. **Fill `.env`** (`cp .env.example .env`): `RESEND_API_KEY`, `SUPABASE_KEY` = Vanthryx **service_role** key, and `STRIPE_WEBHOOK_SECRET`. Secrets never pass through me.
2. **Install:** `pip install -r requirements.txt`
3. **First send:** `python apex.py blast --dry-run --limit 15` → then `python apex.py blast --limit 10`. (Firing real cold email is your call to make.)
4. **Automate cadence** (cron / Task Scheduler): `python apex.py followup` daily · `python snapshot.py --queue` every few minutes.
5. **Stripe (live):** this session only saw your **test** account — confirm the live $297 product + payment link, add `domain` to the Checkout **metadata**, and create a webhook endpoint pointing at `stripe_webhook.py`.
6. **Deploy** `stripe_webhook.py` (:8801) + the queue worker on the bugreaper Ubuntu box — I can't reach your terminal from here.
7. **Authorize the `etjcir…` Supabase account** in your Claude connector settings if you want me to audit it like I did Vanthryx.
8. **Dashboard toggles:** enable Auth "leaked-password protection"; optional `DROP TABLE "Auto ai Crypto ai stock exchange"` to clear the last cosmetic finding.

## Still parked (see PARK.md)
Auto-AI-Crypto · public bounty platform · OmniMind extras · IP Shield — no build hours until each has a named revenue path.

## One-line status
**Everything buildable is built and verified.** What's left is secrets, one Stripe live check, and deploys — all things that need your hands, not mine.
