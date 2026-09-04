#!/usr/bin/env python3
import unittest
from unittest.mock import patch
import snapshot

class TestSnapshot(unittest.TestCase):
    def test_score_calculation(self):
        dns_r = {"resolves": True, "has_mail": True, "spf": "", "dmarc": ""}
        ssl_r = {"valid": False, "error": "certificate expired"}
        hdr = {"https_ok": True, "redirects_https": False}
        sc, band, issues = snapshot.score(dns_r, ssl_r, hdr)
        self.assertGreater(sc, 0)
        self.assertIn(band, ["Low", "Medium", "High", "Critical"])
        self.assertTrue(any("No SPF record" in i["title"] for i in issues))
        self.assertTrue(any("No DMARC policy" in i["title"] for i in issues))

    @patch("snapshot.check_dns")
    @patch("snapshot.check_ssl")
    @patch("snapshot.check_headers")
    def test_scan_concurrent_stubs(self, mock_headers, mock_ssl, mock_dns):
        mock_dns.return_value = {
            "resolves": True,
            "has_mail": True,
            "spf": "v=spf1 include:_spf.google.com ~all",
            "dmarc": "v=DMARC1; p=reject;",
        }
        mock_ssl.return_value = {
            "valid": True,
            "days_to_expiry": 60,
            "issuer": "Let's Encrypt",
        }
        mock_headers.return_value = {
            "https_ok": True,
            "redirects_https": True,
            "hsts": True,
            "csp": True,
            "xfo": True,
            "xcto": True,
            "referrer": True,
        }

        result = snapshot.scan("example.com")
        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_band"], "Low")
        self.assertEqual(len(result["issues"]), 0)
        self.assertIn("Security Snapshot", result["report_html"])

if __name__ == "__main__":
    unittest.main()
