#!/usr/bin/env python3
import unittest
from unittest.mock import patch, MagicMock
import snapshot


class TestSnapshot(unittest.TestCase):

    def test_score_calculation(self):
        dns_r = {"spf": "", "dmarc": ""}
        ssl_r = {"valid": False, "error": "connection refused"}
        hdr = {"https_ok": False}
        sc, band, issues = snapshot.score(dns_r, ssl_r, hdr)
        self.assertGreaterEqual(sc, 60)
        self.assertIn(band, ["High", "Critical"])
        self.assertTrue(len(issues) >= 3)

    def test_render_html(self):
        html_out = snapshot.render_html("example.com", 20, "Low", [])
        self.assertIn("Security Snapshot — example.com", html_out)
        self.assertIn("Low risk", html_out)

    @patch("snapshot._dns")
    def test_check_dns(self, mock_dns):
        def _mock_dns_side_effect(domain, rtype):
            if rtype == "A":
                return ["1.2.3.4"]
            elif rtype == "MX":
                return ["mail.example.com"]
            elif rtype == "TXT":
                if domain.startswith("_dmarc."):
                    return ["v=DMARC1; p=none"]
                return ["v=spf1 include:_spf.example.com ~all"]
            return []

        mock_dns.side_effect = _mock_dns_side_effect

        res = snapshot.check_dns("example.com")
        self.assertTrue(res["resolves"])
        self.assertTrue(res["has_mail"])
        self.assertEqual(res["spf"], "v=spf1 include:_spf.example.com ~all")
        self.assertEqual(res["dmarc"], "v=DMARC1; p=none")

    @patch("snapshot.check_dns")
    @patch("snapshot.check_ssl")
    @patch("snapshot.check_headers")
    def test_scan_returns_expected_structure(self, mock_hdr, mock_ssl, mock_dns):
        mock_dns.return_value = {"resolves": True, "has_mail": True, "spf": "v=spf1 ...", "dmarc": "v=dmarc1 ..."}
        mock_ssl.return_value = {"valid": True, "days_to_expiry": 100, "issuer": "Let's Encrypt"}
        mock_hdr.return_value = {"https_ok": True, "redirects_https": True, "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True}

        res = snapshot.scan("http://example.com/")
        self.assertEqual(res["domain"], "example.com")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["risk_band"], "Low")
        self.assertIn("report_html", res)


if __name__ == "__main__":
    unittest.main()
