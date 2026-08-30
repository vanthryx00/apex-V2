#!/usr/bin/env python3
"""
Unit tests for snapshot.py scanning engine and parallel execution.
"""
import unittest
from unittest.mock import patch
import snapshot


class TestSnapshotEngine(unittest.TestCase):

    def test_score_calculation(self):
        dns_r = {"spf": "", "dmarc": ""}
        ssl_r = {"valid": True, "days_to_expiry": 30}
        hdr = {"https_ok": True, "redirects_https": True, "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True}

        sc, band, issues = snapshot.score(dns_r, ssl_r, hdr)

        # 18 (SPF) + 18 (DMARC) = 36 points -> Medium risk band
        self.assertEqual(sc, 36)
        self.assertEqual(band, "Medium")
        self.assertEqual(len(issues), 2)
        self.assertEqual(issues[0]["title"], "No SPF record")
        self.assertEqual(issues[1]["title"], "No DMARC policy")

    def test_render_html(self):
        html_out = snapshot.render_html("example.com", 36, "Medium", [
            {"severity": "high", "title": "No SPF record", "detail": "Test detail", "fix": "Test fix"}
        ])
        self.assertIn("example.com", html_out)
        self.assertIn("No SPF record", html_out)
        self.assertIn("Medium risk", html_out)

    @patch("snapshot.check_dns")
    @patch("snapshot.check_ssl")
    @patch("snapshot.check_headers")
    def test_scan_parallel_execution(self, mock_hdr, mock_ssl, mock_dns):
        mock_dns.return_value = {"resolves": True, "has_mail": True, "spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=none"}
        mock_ssl.return_value = {"valid": True, "days_to_expiry": 60, "issuer": "Test Issuer"}
        mock_hdr.return_value = {"https_ok": True, "redirects_https": True, "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True}

        res = snapshot.scan("example.com")

        self.assertEqual(res["domain"], "example.com")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["risk_band"], "Low")
        self.assertEqual(len(res["issues"]), 0)
        self.assertTrue(mock_dns.called)
        self.assertTrue(mock_ssl.called)
        self.assertTrue(mock_hdr.called)


if __name__ == "__main__":
    unittest.main()
