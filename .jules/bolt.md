# Bolt's Journal - Critical Learnings

## 2025-09-07 - Parallelizing Independent Network I/O in Security Snapshot
**Learning:** In domain scanning workflows (`snapshot.py`), independent network checks (DNS resolution via nslookup/dnspython, TLS/SSL handshake & certificate parsing, and HTTP/HTTPS header requests) were previously executed sequentially in `scan()`. Concurrent execution using `concurrent.futures.ThreadPoolExecutor(max_workers=3)` reduces total scan runtime from ~0.44s to ~0.18s (~50%+ speedup) per domain while preserving complete API compatibility and error handling.
**Action:** When performing multiple independent network or I/O checks for a target (e.g. DNS, SSL, HTTP headers), always execute them concurrently with `ThreadPoolExecutor`.
