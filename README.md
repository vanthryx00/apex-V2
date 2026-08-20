# Kairyx APEX — Outreach + Security Snapshot Engine

Cold-outreach and fulfillment engine for the $297 Security Snapshot offer
(Kairyx Security Solutions, Fort Saskatchewan, AB).

```
leads (Supabase) ─▶ apex.py blast ─▶ apex.py followup ─▶ reply / $297 checkout
       └▶ stripe_webhook.py ─▶ sales ─▶ snapshot.py --queue ─▶ scan + emailed report
```

## Components
| File | What it does |
|------|--------------|
| `apex.py` | Cold email outreach via Resend + Supabase tracking, with a 4-step follow-up sequence |
| `snapshot.py` | Scans a domain (DNS/SPF/DMARC, SSL, security headers) → risk score → branded report; `--queue` fulfills paid sales |
| `stripe_webhook.py` | Receives Stripe payments (signature-verified) and records paid Snapshots into `sales` |

## Setup
```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
cp .env.example .env          # then fill in real keys — see below
```

### Environment (`.env`)
Copy `.env.example` and set: `RESEND_API_KEY`, `SUPABASE_URL`, `SUPABASE_KEY`
(**service_role** key — RLS blocks the anon key), plus `STRIPE_WEBHOOK_SECRET`
for the webhook. **Never commit `.env`** — it's gitignored.

## Usage
```bash
python apex.py setup                     # verify config
python apex.py blast --dry-run --limit 15   # preview step-1 outreach
python apex.py blast --limit 10             # send step 1
python apex.py followup --dry-run           # preview due follow-ups (steps 2-4)
python apex.py followup                     # send due follow-ups
python snapshot.py example.com              # one-off scan → report.html
python snapshot.py --queue                  # fulfill paid Snapshots
python stripe_webhook.py                    # run the webhook receiver (:8801)
```

## Data
Supabase project `npxpshffkpbqroxegvsj` (ca-central-1). Tables: `leads`,
`outreach_log`, `outreach_drafts`, `exposure_signals`, `sales`, `snapshots`.
RLS is enabled on all; the app uses the service_role key.

## License
Proprietary — © Kairyx Security Solutions. All rights reserved.
