#!/usr/bin/env python3
"""
nexus_env.py — shared environment auto-loader for the Kairyx / NEXUS empire.

Import it ONCE at the very top of any script:

    import nexus_env      # noqa: F401  (auto-runs on import)

What it does:
  1. AUTO-SNIFF: finds a .env no matter where it lives — EMPIRE_ENV override,
     current dir, the script's own dir, ~/empire/.env, ~/.env, known per-user
     empire folders (lalad / bugre / kairyx), and every parent directory.
     All found files are merged (first found wins; real OS env vars always win).
  2. ALIAS-MAP: fills the canonical names the code expects from common variants
     (e.g. SUPABASE_SERVICE_KEY -> SUPABASE_KEY, RESEND_KEY -> RESEND_API_KEY).
  3. MKDIR: creates the output folders the scripts write to (snapshots_out, logs).

Zero dependencies (pure stdlib) so it works before anything is pip-installed.
Set NEXUS_ENV_QUIET=1 to silence the startup line.
"""
import os
from pathlib import Path

# canonical -> [accepted aliases]
_ALIASES = {
    "SUPABASE_URL":          ["SUPABASE_PROJECT_URL", "SUPA_URL", "SB_URL"],
    "SUPABASE_KEY":          ["SUPABASE_SERVICE_KEY", "SUPABASE_SERVICE_ROLE_KEY",
                              "SUPABASE_SERVICE_ROLE", "SERVICE_ROLE_KEY",
                              "SUPABASE_SECRET", "SB_SERVICE_KEY", "SUPABASE_ANON_KEY"],
    "RESEND_API_KEY":        ["RESEND_KEY", "RESEND_TOKEN", "RESEND_API"],
    "FROM_EMAIL":            ["SENDER_EMAIL", "MAIL_FROM", "EMAIL_FROM"],
    "REPLY_TO":              ["REPLY_EMAIL", "MAIL_REPLY_TO"],
    "STRIPE_WEBHOOK_SECRET": ["STRIPE_WEBHOOK_SIGNING_SECRET", "STRIPE_SIGNING_SECRET",
                              "WEBHOOK_SECRET", "STRIPE_WH_SECRET"],
    "STRIPE_SECRET_KEY":     ["STRIPE_API_KEY", "STRIPE_KEY", "STRIPE_SK"],
    "BOOKING_URL":           ["CALENDAR_URL", "CAL_URL"],
}

# folders the scripts expect to exist
_ENSURE_DIRS = ("snapshots_out", "logs")


def _candidate_paths():
    here = Path(__file__).resolve().parent
    cwd = Path.cwd()
    home = Path.home()
    cands = []
    ev = os.getenv("EMPIRE_ENV")
    if ev:
        cands.append(Path(ev))
    cands += [cwd / ".env", here / ".env", home / "empire" / ".env", home / ".env"]
    for user in ("lalad", "bugre", "kairyx"):
        cands.append(Path(f"C:/Users/{user}/empire/.env"))
        cands.append(Path(f"C:/Users/{user}/apex-v2/.env"))
    for base in (cwd, here):
        for parent in [base] + list(base.parents):
            cands.append(parent / ".env")
    # de-dup, preserve order
    seen, out = set(), []
    for c in cands:
        try:
            key = str(c.resolve())
        except Exception:
            key = str(c)
        if key not in seen:
            seen.add(key)
            out.append(c)
    return out


def _parse(path: Path) -> dict:
    data = {}
    try:
        for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            if line.lower().startswith("export "):
                line = line[7:]
            k, v = line.split("=", 1)
            k = k.strip()
            v = v.strip().strip('"').strip("'")
            if k:
                data[k] = v
    except Exception:
        pass
    return data


def load(verbose: bool = True):
    loaded_from, merged = [], {}
    for path in _candidate_paths():
        if path.is_file():
            d = _parse(path)
            if d:
                loaded_from.append(str(path))
                for k, v in d.items():
                    merged.setdefault(k, v)      # first file found wins
    for k, v in merged.items():
        os.environ.setdefault(k, v)              # never clobber a real OS env var

    mapped = []
    for canon, aliases in _ALIASES.items():
        if not os.getenv(canon):
            for a in aliases:
                if os.getenv(a):
                    os.environ[canon] = os.environ[a]
                    mapped.append(f"{canon}<-{a}")
                    break

    ensure_dirs()

    if verbose:
        if loaded_from:
            print(f"[env] loaded: {'; '.join(loaded_from)}")
        else:
            print("[env] no .env found — using OS environment variables only")
        if mapped:
            print(f"[env] aliased: {', '.join(mapped)}")
    return loaded_from


def ensure_dirs():
    for d in _ENSURE_DIRS:
        try:
            Path(d).mkdir(parents=True, exist_ok=True)
        except Exception:
            pass


# auto-run on import
load(verbose=os.getenv("NEXUS_ENV_QUIET") != "1")
