## 2025-05-18 - Domain Scan Concurrent Check Execution
**Learning:** External security scanning (`snapshot.scan`) involves three independent I/O-bound operations: DNS checks, SSL certificate handshake, and HTTP security header inspection. Sequential execution accumulated network wait times (summing latencies to 0.5s–25s). Executing these three phases concurrently using Python stdlib `concurrent.futures.ThreadPoolExecutor(max_workers=3)` reduced total scan latency to `max(T_dns, T_ssl, T_hdr)`, delivering a 50%–90% speedup per scan without external dependencies.
**Action:** When executing multiple independent network or I/O checks in Python scripts, wrap them in `ThreadPoolExecutor` to eliminate sequential latency bottlenecks.

## 2025-05-18 - Concurrent DNS Record Queries
**Learning:** `check_dns` sequentially issued up to four DNS queries (`A`, `MX`, `TXT`, and `_dmarc` TXT), accumulating round-trip network delays for each record lookup. By executing all four DNS queries concurrently with `ThreadPoolExecutor(max_workers=4)`, the total DNS phase latency dropped from `T_a + T_mx + T_txt + T_dmarc` to `max(T_a, T_mx, T_txt, T_dmarc)`, yielding a ~3x-4x speedup during DNS resolution.
**Action:** When querying multiple DNS record types for a domain, parallelize the queries with a `ThreadPoolExecutor` instead of calling them sequentially.

## 2025-05-18 - Concurrent HTTP Security Header and Redirect Checks
**Learning:** `check_headers` sequentially issued two independent HTTP network requests (`https://` security header check and `http://` redirect check), accumulating round-trip network delays and potential timeouts. Parallelizing both HTTP calls with `ThreadPoolExecutor(max_workers=2)` reduced header inspection latency from `T_https + T_http` to `max(T_https, T_http)`, yielding a ~2x latency improvement for header checks.
**Action:** When performing HTTP security checks on a domain (such as header verification and HTTP-to-HTTPS redirect checks), execute them concurrently with `ThreadPoolExecutor`.
