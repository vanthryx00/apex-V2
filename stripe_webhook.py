#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
 STRIPE WEBHOOK — Kairyx Security Solutions

 Receives Stripe payment events, verifies the signature, and records each
 paid $297 Snapshot into Supabase `sales` (status=paid). A separate worker
 (`python3 snapshot.py --queue`) then scans the domain and emails the report.

 RUN:
   pip install -r requirements.txt
   export STRIPE_WEBHOOK_SECRET=whsec_...   SUPABASE_URL=...  SUPABASE_KEY=<service_role>
   python3 stripe_webhook.py                 # serves on :8801 via waitress

 Then point a Stripe webhook endpoint at  https://<host>/stripe/webhook
 for events: checkout.session.completed, payment_intent.succeeded
 Put the buyer's domain in the Checkout metadata as `domain` (or a custom field).
═══════════════════════════════════════════════════════════════════════════
"""

import os
import json
import logging
from flask import Flask, request, jsonify

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("stripe_webhook")

WEBHOOK_SECRET = os.getenv("STRIPE_WEBHOOK_SECRET", "")
SUPABASE_URL   = os.getenv("SUPABASE_URL", "")
SUPABASE_KEY   = os.getenv("SUPABASE_KEY", "")
PORT           = int(os.getenv("PORT", "8801"))

app = Flask(__name__)


def _supabase():
    if not (SUPABASE_URL and SUPABASE_KEY):
        return None
    try:
        from supabase import create_client
        return create_client(SUPABASE_URL, SUPABASE_KEY)
    except Exception as e:
        log.error("supabase init failed: %s", e)
        return None


def _extract_domain(obj: dict) -> str:
    md = obj.get("metadata") or {}
    if md.get("domain"):
        return md["domain"]
    for f in obj.get("custom_fields", []) or []:
        if f.get("key") in ("domain", "website"):
            return (f.get("text") or {}).get("value", "")
    # last resort: derive from customer email domain
    email = (obj.get("customer_details") or {}).get("email") or obj.get("receipt_email") or ""
    return email.split("@")[-1] if "@" in email else ""


def _record_sale(event: dict) -> bool:
    client = _supabase()
    if not client:
        log.warning("no Supabase; sale not recorded")
        return False
    obj = event["data"]["object"]
    cust = obj.get("customer_details") or {}
    row = {
        "stripe_event_id": event["id"],
        "stripe_session_id": obj.get("id") if obj.get("object") == "checkout.session" else None,
        "stripe_payment_intent_id": obj.get("payment_intent") or (obj.get("id") if obj.get("object") == "payment_intent" else None),
        "customer_email": cust.get("email") or obj.get("receipt_email"),
        "customer_name": cust.get("name"),
        "amount_cents": obj.get("amount_total") or obj.get("amount") or obj.get("amount_received"),
        "currency": obj.get("currency", "cad"),
        "product": "Security Snapshot",
        "domain": _extract_domain(obj),
        "status": "paid",
    }
    try:
        client.table("sales").upsert(row, on_conflict="stripe_event_id").execute()
        log.info("recorded sale event=%s domain=%s email=%s", event["id"], row["domain"], row["customer_email"])
        return True
    except Exception as e:
        log.error("sale insert failed: %s", e)
        return False


@app.get("/health")
def health():
    return jsonify(status="ok", supabase=bool(SUPABASE_URL and SUPABASE_KEY),
                   signature_check=bool(WEBHOOK_SECRET)), 200


@app.post("/stripe/webhook")
def webhook():
    payload = request.get_data()
    sig = request.headers.get("Stripe-Signature", "")

    if WEBHOOK_SECRET:
        try:
            import stripe
            event = stripe.Webhook.construct_event(payload, sig, WEBHOOK_SECRET)
        except Exception as e:
            log.warning("signature verification failed: %s", e)
            return jsonify(error="invalid signature"), 400
    else:
        # No secret configured — accept but log loudly. Set STRIPE_WEBHOOK_SECRET in prod.
        log.warning("STRIPE_WEBHOOK_SECRET not set — skipping signature verification")
        try:
            event = json.loads(payload)
        except Exception:
            return jsonify(error="bad payload"), 400

    etype = event.get("type", "")
    if etype in ("checkout.session.completed", "payment_intent.succeeded"):
        _record_sale(event)
    else:
        log.info("ignored event type=%s", etype)

    return jsonify(received=True), 200


if __name__ == "__main__":
    if not WEBHOOK_SECRET:
        log.warning("Starting WITHOUT STRIPE_WEBHOOK_SECRET — do not use in production.")
    try:
        from waitress import serve
        log.info("serving on 0.0.0.0:%d", PORT)
        serve(app, host="0.0.0.0", port=PORT)
    except ImportError:
        app.run(host="0.0.0.0", port=PORT)
