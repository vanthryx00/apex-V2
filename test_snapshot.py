#!/usr/bin/env python3
import unittest
from unittest.mock import patch
import snapshot


class TestSnapshot(unittest.TestCase):
    def test_score_calculation(self):
        # All good
        dns_r = {"resolves": True, "has_mail": True, "spf": "v=spf1 ...", "dmarc": "v=dmarc1 ..."}
        ssl_r = {"valid": True, "days_to_expiry": 100}
        hdr = {
            "https_ok": True, "redirects_https": True,
            "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True
        }
        sc, band, issues = snapshot.score(dns_r, ssl_r, hdr)
        self.assertEqual(sc, 0)
        self.assertEqual(band, "Low")
        self.assertEqual(len(issues), 0)

        # Missing SPF & DMARC
        dns_bad = {"resolves": True, "has_mail": True, "spf": "", "dmarc": ""}
        sc_bad, band_bad, issues_bad = snapshot.score(dns_bad, ssl_r, hdr)
        self.assertEqual(sc_bad, 36)
        self.assertEqual(band_bad, "Medium")
        self.assertEqual(len(issues_bad), 2)

    @patch("snapshot.check_dns")
    @patch("snapshot.check_ssl")
    @patch("snapshot.check_headers")
    def test_scan_orchestration(self, mock_hdr, mock_ssl, mock_dns):
        mock_dns.return_value = {"resolves": True, "has_mail": True, "spf": "v=spf1", "dmarc": "v=dmarc1"}
        mock_ssl.return_value = {"valid": True, "days_to_expiry": 60, "issuer": "Let's Encrypt"}
        mock_hdr.return_value = {"https_ok": True, "redirects_https": True, "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True}

        res = snapshot.scan("https://example.com/")
        self.assertEqual(res["domain"], "example.com")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["risk_band"], "Low")
        self.assertIn("Security Snapshot", res["report_html"])
        mock_dns.assert_called_once_with("example.com")
        mock_ssl.assert_called_once_with("example.com")
        mock_hdr.assert_called_once_with("example.com")


if __name__ == "__main__":
    unittest.main()
