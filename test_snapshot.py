#!/usr/bin/env python3
"""
Unit tests for snapshot.py (Kairyx Security Snapshot engine)
"""

import unittest
from unittest.mock import patch, MagicMock
import snapshot


class TestSnapshotEngine(unittest.TestCase):

    def test_score_calculation(self):
        dns_clean = {"resolves": True, "has_mail": True, "spf": "v=spf1 include:_spf.example.com ~all", "dmarc": "v=DMARC1; p=reject"}
        ssl_clean = {"valid": True, "days_to_expiry": 120, "issuer": "DigiCert"}
        hdr_clean = {"https_ok": True, "redirects_https": True, "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True}

        sc, band, issues = snapshot.score(dns_clean, ssl_clean, hdr_clean)
        self.assertEqual(sc, 0)
        self.assertEqual(band, "Low")
        self.assertEqual(len(issues), 0)

    def test_score_issues(self):
        dns_bad = {"resolves": True, "has_mail": True, "spf": "", "dmarc": ""}
        ssl_bad = {"valid": False, "error": "certificate has expired"}
        hdr_bad = {"https_ok": True, "redirects_https": False}

        sc, band, issues = snapshot.score(dns_bad, ssl_bad, hdr_bad)
        self.assertGreaterEqual(sc, 60)
        self.assertIn(band, ("High", "Critical"))
        self.assertGreater(len(issues), 0)

    def test_render_html(self):
        html = snapshot.render_html("example.com", 34, "Medium", [
            {"severity": "medium", "title": "HTTP not forced to HTTPS", "detail": "Test detail", "fix": "Test fix"}
        ])
        self.assertIn("Security Snapshot", html)
        self.assertIn("example.com", html)
        self.assertIn("34", html)
        self.assertIn("Medium risk", html)

    @patch("snapshot.check_dns")
    @patch("snapshot.check_ssl")
    @patch("snapshot.check_headers")
    def test_scan_concurrent_execution(self, mock_hdr, mock_ssl, mock_dns):
        mock_dns.return_value = {"resolves": True, "has_mail": True, "spf": "v=spf1", "dmarc": "v=dmarc1"}
        mock_ssl.return_value = {"valid": True, "days_to_expiry": 60, "issuer": "Test Issuer"}
        mock_hdr.return_value = {"https_ok": True, "redirects_https": True, "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True}

        res = snapshot.scan("http://EXAMPLE.COM/")
        self.assertEqual(res["domain"], "example.com")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["risk_band"], "Low")
        mock_dns.assert_called_once_with("example.com")
        mock_ssl.assert_called_once_with("example.com")
        mock_hdr.assert_called_once_with("example.com")


if __name__ == "__main__":
    unittest.main()
