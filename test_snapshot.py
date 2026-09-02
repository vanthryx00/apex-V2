import unittest
from unittest.mock import patch, MagicMock
import snapshot


class TestSnapshot(unittest.TestCase):

    def test_score_calculation(self):
        dns_r = {"spf": "", "dmarc": ""}
        ssl_r = {"valid": True, "days_to_expiry": 10}
        hdr = {"https_ok": True, "redirects_https": False}

        sc, band, issues = snapshot.score(dns_r, ssl_r, hdr)
        self.assertGreater(sc, 0)
        self.assertIn(band, ["Low", "Medium", "High", "Critical"])
        self.assertIsInstance(issues, list)
        self.assertGreater(len(issues), 0)

    def test_render_html(self):
        html = snapshot.render_html("example.com", 50, "Medium", [])
        self.assertIn("Security Snapshot — example.com", html)
        self.assertIn("example.com", html)

    @patch("snapshot.check_dns")
    @patch("snapshot.check_ssl")
    @patch("snapshot.check_headers")
    def test_scan(self, mock_headers, mock_ssl, mock_dns):
        mock_dns.return_value = {"resolves": True, "has_mail": True, "spf": "v=spf1", "dmarc": "v=DMARC1"}
        mock_ssl.return_value = {"valid": True, "days_to_expiry": 100, "issuer": "Let's Encrypt"}
        mock_headers.return_value = {"https_ok": True, "redirects_https": True, "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True}

        res = snapshot.scan("http://example.com/")
        self.assertEqual(res["domain"], "example.com")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["risk_band"], "Low")
        self.assertIn("report_html", res)


if __name__ == "__main__":
    unittest.main()
