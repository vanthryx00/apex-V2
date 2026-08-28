import unittest
import time
from unittest.mock import patch
import snapshot

class TestSnapshot(unittest.TestCase):
    def test_score(self):
        dns_r = {"spf": "v=spf1 include:_spf.google.com ~all", "dmarc": "v=DMARC1; p=none;"}
        ssl_r = {"valid": True, "days_to_expiry": 30, "issuer": "Let's Encrypt"}
        hdr = {
            "https_ok": True,
            "redirects_https": True,
            "hsts": True,
            "csp": False,
            "xfo": True,
            "xcto": True,
            "referrer": False,
        }
        sc, band, issues = snapshot.score(dns_r, ssl_r, hdr)
        self.assertIsInstance(sc, int)
        self.assertIn(band, ["Low", "Medium", "High", "Critical"])
        self.assertEqual(len(issues), 2)  # Missing CSP and Referrer-Policy

    @patch("snapshot._dns")
    def test_check_dns_parallel(self, mock_dns):
        def dummy_dns(domain, rtype):
            time.sleep(0.05)
            if rtype == "A":
                return ["93.184.216.34"]
            elif rtype == "MX":
                return ["mail.example.com"]
            elif rtype == "TXT" and domain == "example.com":
                return ["v=spf1 ~all"]
            elif rtype == "TXT" and domain == "_dmarc.example.com":
                return ["v=DMARC1; p=reject;"]
            return []

        mock_dns.side_effect = dummy_dns
        start_time = time.perf_counter()
        res = snapshot.check_dns("example.com")
        elapsed = time.perf_counter() - start_time

        self.assertTrue(res["resolves"])
        self.assertTrue(res["has_mail"])
        self.assertEqual(res["spf"], "v=spf1 ~all")
        self.assertEqual(res["dmarc"], "v=DMARC1; p=reject;")
        # Parallel execution of 4 calls sleeping 0.05s should take ~0.05-0.10s instead of 0.20s
        self.assertLess(elapsed, 0.15)

    @patch("snapshot.check_dns")
    @patch("snapshot.check_ssl")
    @patch("snapshot.check_headers")
    def test_scan_parallel(self, mock_hdr, mock_ssl, mock_dns):
        def dummy_dns(domain):
            time.sleep(0.05)
            return {"resolves": True, "has_mail": True, "spf": "v=spf1 ~all", "dmarc": "v=DMARC1; p=reject;"}

        def dummy_ssl(domain):
            time.sleep(0.05)
            return {"valid": True, "days_to_expiry": 30, "issuer": "Test"}

        def dummy_hdr(domain):
            time.sleep(0.05)
            return {"https_ok": True, "redirects_https": True, "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True}

        mock_dns.side_effect = dummy_dns
        mock_ssl.side_effect = dummy_ssl
        mock_hdr.side_effect = dummy_hdr

        start_time = time.perf_counter()
        res = snapshot.scan("example.com")
        elapsed = time.perf_counter() - start_time

        self.assertEqual(res["domain"], "example.com")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["risk_band"], "Low")
        # Parallel execution of 3 calls sleeping 0.05s should take ~0.05-0.10s instead of 0.15s
        self.assertLess(elapsed, 0.12)

if __name__ == "__main__":
    unittest.main()
