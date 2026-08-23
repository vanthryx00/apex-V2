# Run KAIRYX APEX from a portable drive (USB / external HDD)

The goal: plug the drive into any Windows PC and run — no install, works even
when the drive letter changes (E: today, F: tomorrow). `run.bat` handles the
drive-letter problem by locating itself; you just add a portable Python.

## One-time setup (do this once, on the drive)

1. **Put the code on the drive.** Either copy the `apex-v2` folder over, or:
   ```
   E:\> git clone https://github.com/vanthryx00/apex-V2.git apex-v2
   ```

2. **Add a portable Python 3.12** (a venv is NOT drive-portable — use a
   self-contained build):
   - Download **WinPython 3.12** (portable) from winpython.github.io
   - Extract it, find its inner `python-3.12.x` folder
   - Copy that folder into the drive as: `apex-v2\python\`
     so that **`apex-v2\python\python.exe`** exists.
   - (Skip this step if you'll only ever run on PCs that already have Python 3.12.)

3. **Add your secrets.** Copy your `.env` next to the scripts:
   `apex-v2\.env`  (never commit it — it's gitignored). `nexus_env.py`
   auto-finds it there.

## Every time — just double-click `run.bat`
- First launch installs dependencies once (into the bundled Python) and marks
  `.deps_ok`, so later launches are instant.
- You get a menu: doctor/fix, setup check, dry-run, send batch, follow-ups,
  scanner dashboard, single-domain scan.

## Notes
- **Drive letter changes are fine** — `run.bat` does `cd /d "%~dp0"` (its own
  folder) so nothing is hardcoded.
- **Python 3.14 warning:** some packages lack 3.14 wheels. Use a **3.12**
  portable build to avoid compile errors.
- The `python\` folder and `.deps_ok` are gitignored — they stay on the drive,
  not in the repo.
- Command-line equivalents (if you skip the menu), from inside the folder:
  ```
  python\python.exe fix.py --fix
  python\python.exe apex.py blast --dry-run --limit 15
  python\python.exe scanner_app.py
  ```
