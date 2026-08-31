## 2025-02-18 - Fast-path DNS resolution & stdlib socket lookup
**Learning:** When optional DNS packages like `dnspython` are missing, repeatedly importing inside functions raises `ModuleNotFoundError` on every DNS query. Subprocessing `nslookup` for A-record resolution adds process fork overhead (~215ms vs ~15ms). Using standard library `socket.gethostbyname_ex` returns all resolved IP addresses directly from native C resolution.
**Action:** Module-level check optional dependencies and leverage `socket.gethostbyname_ex` for standard DNS A-record lookups before subprocess fallback.
