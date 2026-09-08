# Bolt's Journal - Critical Learnings

## 2025-05-18 - Concurrent Network I/O in Security Scanning
**Learning:** Sequential DNS lookups, SSL checks, and HTTP header queries in `snapshot.py` compounded network latencies, especially when DNS commands or HTTP checks stalled or timed out. Moving independent sub-checks to `concurrent.futures.ThreadPoolExecutor` reduced total scan wall-clock time by over 50-60% without breaking synchronous engine API contracts.
**Action:** When performing independent network I/O calls in Python CLI or fulfillment workers, use `ThreadPoolExecutor` to execute queries concurrently.
