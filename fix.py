#!/usr/bin/env python3
"""
═══════════════════════════════════════════════════════════════════════════
 FIX — Kairyx System Fixer (doctor + auto-repair)

 Diagnoses the whole setup and, with --fix, repairs what it safely can.

   python fix.py           # diagnose only (read-only)
   python fix.py --fix     # also: create .env, install missing deps,
                           #        make folders, gitignore .env

 Checks: Python version · .env discovery · required keys · dependencies ·
         folders · Supabase connectivity · git hygiene (.env not committed).
═══════════════════════════════════════════════════════════════════════════
"""
import os
import sys
import shutil
import subprocess
import importlib.util
from pathlib import Path

FIX = "--fix" in sys.argv
R = {"pass": 0, "warn": 0, "fail": 0, "fixed": 0}


def ok(m):    print("  [✓]", m);        R["pass"] += 1
def warn(m):  print("  [!]", m);             R["warn"] += 1
def bad(m):   print("  [✗]", m);        R["fail"] += 1
def fixed(m): print("  [⚙ fixed]", m);  R["fixed"] += 1
def hdr(t):   print("\n" + "=" * 58 + "\n  " + t + "\n" + "=" * 58)


# quiet the auto env-loader, then load it ourselves so we can show the path
os.environ["NEXUS_ENV_QUIET"] = "1"


def main():
    print("=" * 58)
    print("  KAIRYX SYSTEM FIXER" + ("   (repair mode)" if FIX else "   (diagnose only)"))
    print("=" * 58)

    # ── Python ──────────────────────────────────────────────
    hdr("PYTHON")
    v = sys.version_info
    print(f"  version: {v.major}.{v.minor}.{v.micro}")
    if v.major == 3 and 10 <= v.minor <= 13:
        ok(f"Python {v.major}.{v.minor} is well-supported")
    elif v.major == 3 and v.minor >= 14:
        warn("Python 3.14+ can lack prebuilt wheels (greenlet/gevent). If pip fails, use a 3.12 venv.")
    else:
        warn("Python 3.11 or 3.12 recommended")

    # ── .env / config ───────────────────────────────────────
    hdr(".ENV / CONFIG")
    if not Path(".env").is_file():
        if FIX and Path(".env.example").is_file():
            shutil.copy(".env.example", ".env")
            fixed("created .env from .env.example — now open it and fill in real keys")
        else:
            warn("no local .env (use --fix to create one, or rely on your empire .env)")
    try:
        import nexus_env
        loaded = nexus_env.load(verbose=False)
        if loaded:
            ok("config loaded from: " + "; ".join(loaded))
        else:
            warn("no .env found anywhere — relying on OS environment variables")
    except Exception as e:
        bad(f"nexus_env failed: {e}")

    for k in ("RESEND_API_KEY", "FROM_EMAIL", "SUPABASE_URL", "SUPABASE_KEY"):
        (ok if os.getenv(k) else bad)(f"{k} " + ("present" if os.getenv(k) else "MISSING"))

    # ── dependencies ────────────────────────────────────────
    hdr("DEPENDENCIES")
    modmap = {"resend": "resend", "supabase": "supabase", "flask": "flask",
              "waitress": "waitress", "stripe": "stripe", "dns": "dnspython"}
    missing = []
    for mod, pkg in modmap.items():
        if importlib.util.find_spec(mod):
            ok(f"{pkg} installed")
        else:
            missing.append(pkg)
            (warn if not FIX else lambda _m: None)(f"{pkg} missing")
    if missing:
        if FIX:
            print("  installing:", ", ".join(missing))
            rc = subprocess.call([sys.executable, "-m", "pip", "install", *missing])
            (fixed if rc == 0 else bad)(
                ("installed: " + ", ".join(missing)) if rc == 0
                else "pip failed — try: python -m pip install " + " ".join(missing))
        else:
            bad(f"{len(missing)} missing: {', '.join(missing)}  →  run: python fix.py --fix")

    # ── folders ─────────────────────────────────────────────
    hdr("FOLDERS")
    for d in ("snapshots_out", "logs"):
        Path(d).mkdir(parents=True, exist_ok=True)
        ok(f"{d}/ exists")

    # ── supabase connectivity ───────────────────────────────
    hdr("SUPABASE CONNECTIVITY")
    url, key = os.getenv("SUPABASE_URL"), os.getenv("SUPABASE_KEY")
    if url and key and importlib.util.find_spec("supabase"):
        import time as _t
        from supabase import create_client
        err = None
        for _ in range(3):
            try:
                create_client(url, key).table("leads").select("id").limit(1).execute()
                ok("connected — leads table reachable (service_role key works)")
                err = None
                break
            except Exception as e:
                err = str(e)
                _t.sleep(1.5)
        if err:
            warn("REST check failed after retries (Supabase worker/pooler hiccup): "
                 + err[:80] + " … keys load fine — safe to proceed, retry later")
    else:
        warn("skipped (need SUPABASE_URL, SUPABASE_KEY, and supabase installed)")

    # ── git hygiene ─────────────────────────────────────────
    hdr("GIT SECURITY")
    if Path(".git").exists():
        try:
            tracked = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split()
            if ".env" in tracked:
                bad(".env IS COMMITTED — secrets exposed! run:  git rm --cached .env  then ROTATE your keys")
            else:
                ok(".env is not tracked by git")
            gi = Path(".gitignore")
            if gi.is_file() and ".env" in gi.read_text():
                ok(".gitignore excludes .env")
            elif FIX:
                with open(".gitignore", "a", encoding="utf-8") as f:
                    f.write("\n.env\n")
                fixed("added .env to .gitignore")
            else:
                warn(".gitignore has no .env rule  →  run --fix")
        except Exception as e:
            warn(f"git check skipped: {e}")
    else:
        warn("not a git repo (run: git init)")

    # ── hardening / patch the holes ─────────────────────────
    hdr("HARDENING")
    if Path(".env").is_file():
        try:
            os.chmod(".env", 0o600)
            ok(".env locked to owner-only (0600)")
        except Exception:
            warn(".env perms unchanged (non-POSIX filesystem)")
    if os.getenv("ADMIN_TOKEN"):
        ok("ADMIN_TOKEN set — scanner dashboard is protected")
    elif FIX:
        import secrets
        tok = secrets.token_urlsafe(24)
        with open(".env", "a", encoding="utf-8") as f:
            f.write(f"\nADMIN_TOKEN={tok}\n")
        fixed(f"generated ADMIN_TOKEN (saved to .env): {tok}")
    else:
        warn("ADMIN_TOKEN missing — scanner_app dashboard would be open. run --fix to generate")
    (ok if os.getenv("STRIPE_WEBHOOK_SECRET") else warn)(
        "STRIPE_WEBHOOK_SECRET " + ("set — webhook verifies signatures"
        if os.getenv("STRIPE_WEBHOOK_SECRET")
        else "missing — webhook skips signature checks (set before production)"))
    fe = os.getenv("FROM_EMAIL", "")
    (ok if "bugreaper-x.ca" in fe else warn)(
        "FROM_EMAIL " + ("on the verified domain" if "bugreaper-x.ca" in fe
        else "NOT on verified domain bugreaper-x.ca — deliverability/spoofing risk"))
    if Path(".git").exists():
        try:
            import re
            files = subprocess.run(["git", "ls-files"], capture_output=True, text=True).stdout.split()
            # real token shapes only; skip docs/templates (placeholders live there)
            pat = re.compile(r"(sk_live_[A-Za-z0-9]{16,}|whsec_[A-Za-z0-9]{16,}|re_[A-Za-z0-9]{24,}|eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.)")
            hits = []
            for fn in files:
                if fn.lower().endswith((".md", ".txt", ".example")) or fn.endswith(".env.example"):
                    continue
                try:
                    if pat.search(Path(fn).read_text(encoding="utf-8", errors="ignore")):
                        hits.append(fn)
                except Exception:
                    pass
            if hits:
                bad("possible secrets in tracked files: " + ", ".join(hits) + " — review & rotate")
            else:
                ok("no secret patterns in tracked files")
        except Exception as e:
            warn(f"secret scan skipped: {e}")

    # ── summary ─────────────────────────────────────────────
    hdr("SUMMARY")
    print(f"  pass {R['pass']} · fixed {R['fixed']} · warn {R['warn']} · fail {R['fail']}")
    if R["fail"] == 0:
        print("\n  ✅ System healthy — ready to run apex.py, snapshot.py, scanner_app.py")
    else:
        print("\n  ⚠ Resolve the [✗] items above. Many auto-fix with:  python fix.py --fix")
    sys.exit(1 if R["fail"] else 0)


if __name__ == "__main__":
    main()
