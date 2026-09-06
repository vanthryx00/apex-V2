import unittest
from unittest.mock import patch, MagicMock
import snapshot


class TestSnapshot(unittest.TestCase):

    def test_score_calculation(self):
        dns_r = {"spf": "v=spf1 include:_spf.google.com ~all", "dmarc": "v=DMARC1; p=none;"}
        ssl_r = {"valid": True, "days_to_expiry": 60, "issuer": "DigiCert Inc"}
        hdr = {
            "https_ok": True,
            "redirects_https": True,
            "hsts": True,
            "csp": True,
            "xfo": True,
            "xcto": True,
            "referrer": True,
        }
        sc, band, issues = snapshot.score(dns_r, ssl_r, hdr)
        self.assertEqual(sc, 0)
        self.assertEqual(band, "Low")
        self.assertEqual(len(issues), 0)

    def test_score_issues_accumulation(self):
        dns_r = {"spf": "", "dmarc": ""}
        ssl_r = {"valid": False, "error": "certificate expired"}
        hdr = {"https_ok": False, "redirects_https": False}
        sc, band, issues = snapshot.score(dns_r, ssl_r, hdr)
        self.assertGreater(sc, 0)
        self.assertIn(band, ("High", "Critical"))
        self.assertGreater(len(issues), 0)

    @patch("snapshot._dns")
    def test_check_dns(self, mock_dns):
        def _mock_dns_side_effect(domain, rtype):
            if rtype == "A":
                return ["93.184.216.34"]
            if rtype == "MX":
                return ["mail.example.com"]
            if rtype == "TXT" and not domain.startswith("_dmarc"):
                return ["v=spf1 include:_spf.example.com ~all"]
            if rtype == "TXT" and domain.startswith("_dmarc"):
                return ["v=DMARC1; p=reject;"]
            return []

        mock_dns.side_effect = _mock_dns_side_effect
        dns_res = snapshot.check_dns("example.com")
        self.assertTrue(dns_res["resolves"])
        self.assertTrue(dns_res["has_mail"])
        self.assertIn("v=spf1", dns_res["spf"])
        self.assertIn("v=DMARC1", dns_res["dmarc"])

    def test_render_html(self):
        issues = [{
            "severity": "high",
            "title": "No SPF record",
            "detail": "Test detail",
            "fix": "Test fix",
        }]
        html_out = snapshot.render_html("example.com", 36, "Medium", issues)
        self.assertIn("Security Snapshot", html_out)
        self.assertIn("example.com", html_out)
        self.assertIn("No SPF record", html_out)

    @patch("snapshot.check_dns")
    @patch("snapshot.check_ssl")
    @patch("snapshot.check_headers")
    def test_scan_orchestration(self, mock_hdr, mock_ssl, mock_dns):
        mock_dns.return_value = {"resolves": True, "has_mail": True, "spf": "v=spf1", "dmarc": "v=DMARC1"}
        mock_ssl.return_value = {"valid": True, "days_to_expiry": 100, "issuer": "Test CA"}
        mock_hdr.return_value = {
            "https_ok": True,
            "redirects_https": True,
            "hsts": True,
            "csp": True,
            "xfo": True,
            "xcto": True,
            "referrer": True,
        }

        res = snapshot.scan("https://example.com/")
        self.assertEqual(res["domain"], "example.com")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["risk_band"], "Low")
        self.assertEqual(len(res["issues"]), 0)


if __name__ == "__main__":
    unittest.main()
