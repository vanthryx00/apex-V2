@echo off
REM ============================================================
REM  KAIRYX APEX — portable launcher
REM  Works from ANY drive letter (USB / external HDD).
REM  Uses a bundled Python at .\python\python.exe if present,
REM  otherwise falls back to system "python".
REM ============================================================
setlocal enabledelayedexpansion
cd /d "%~dp0"

if exist "%~dp0python\python.exe" (
  set "PY=%~dp0python\python.exe"
) else (
  set "PY=python"
)

REM first run: install dependencies once, mark with .deps_ok
if not exist "%~dp0.deps_ok" (
  echo Installing dependencies with "!PY!" ...
  "!PY!" -m pip install -r requirements.txt
  if !errorlevel! equ 0 (
     type nul > "%~dp0.deps_ok"
  ) else (
     echo.
     echo Dependency install failed. If on Python 3.14, use a 3.12 portable build.
     pause
  )
)

:menu
cls
echo ================================================
echo    KAIRYX APEX  -  portable launcher
echo    Folder: %CD%
echo    Python: !PY!
echo ================================================
echo    1^) Doctor + auto-fix       (fix.py --fix)
echo    2^) Setup check             (apex.py setup)
echo    3^) Outreach DRY-RUN        (previews, no send)
echo    4^) SEND batch of 10        (real emails!)
echo    5^) Follow-ups due          (steps 2-4)
echo    6^) Scanner dashboard       (localhost:8800)
echo    7^) Scan a single domain
echo    0^) Exit
echo.
set /p c=Choose:
if "%c%"=="1" ( "!PY!" fix.py --fix & pause & goto menu )
if "%c%"=="2" ( "!PY!" apex.py setup & pause & goto menu )
if "%c%"=="3" ( "!PY!" apex.py blast --dry-run --limit 15 & pause & goto menu )
if "%c%"=="4" ( "!PY!" apex.py blast --limit 10 & pause & goto menu )
if "%c%"=="5" ( "!PY!" apex.py followup & pause & goto menu )
if "%c%"=="6" ( "!PY!" scanner_app.py & pause & goto menu )
if "%c%"=="7" ( set /p d=Domain: ^& "!PY!" snapshot.py !d! ^& pause ^& goto menu )
if "%c%"=="0" ( exit /b )
goto menu
