import unittest
from unittest.mock import patch, MagicMock
import snapshot


class TestSnapshot(unittest.TestCase):

    @patch("snapshot._dns")
    def test_check_dns(self, mock_dns):
        def side_effect(domain, rtype):
            if rtype == "A":
                return ["1.2.3.4"]
            elif rtype == "MX":
                return ["mail.example.com"]
            elif rtype == "TXT":
                if domain.startswith("_dmarc"):
                    return ["v=DMARC1; p=reject;"]
                return ["v=spf1 include:_spf.example.com ~all"]
            return []

        mock_dns.side_effect = side_effect

        res = snapshot.check_dns("example.com")
        self.assertTrue(res["resolves"])
        self.assertTrue(res["has_mail"])
        self.assertIn("v=spf1", res["spf"])
        self.assertIn("v=DMARC1", res["dmarc"])

    @patch("ssl.create_default_context")
    @patch("socket.create_connection")
    def test_check_ssl_valid(self, mock_conn, mock_ctx):
        mock_sock = MagicMock()
        mock_conn.return_value.__enter__.return_value = mock_sock
        mock_ss = MagicMock()
        mock_ctx.return_value.wrap_socket.return_value.__enter__.return_value = mock_ss
        mock_ss.getpeercert.return_value = {
            "notAfter": "Dec 31 23:59:59 2030 GMT",
            "issuer": ((("organizationName", "Test Authority"),),),
        }

        res = snapshot.check_ssl("example.com")
        self.assertTrue(res["valid"])
        self.assertEqual(res["issuer"], "Test Authority")
        self.assertGreater(res["days_to_expiry"], 0)

    @patch("snapshot.urlopen")
    def test_check_headers(self, mock_urlopen):
        mock_resp = MagicMock()
        mock_resp.headers.items.return_value = [
            ("Strict-Transport-Security", "max-age=31536000"),
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Frame-Options", "DENY"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
        ]
        mock_resp.url = "https://example.com"
        mock_urlopen.return_value.__enter__.return_value = mock_resp

        res = snapshot.check_headers("example.com")
        self.assertTrue(res["https_ok"])
        self.assertTrue(res["hsts"])
        self.assertTrue(res["csp"])
        self.assertTrue(res["xfo"])
        self.assertTrue(res["xcto"])
        self.assertTrue(res["referrer"])

    def test_score_perfect(self):
        dns_r = {"spf": "v=spf1 ...", "dmarc": "v=DMARC1 ..."}
        ssl_r = {"valid": True, "days_to_expiry": 100}
        hdr = {"https_ok": True, "redirects_https": True, "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True}

        sc, band, issues = snapshot.score(dns_r, ssl_r, hdr)
        self.assertEqual(sc, 0)
        self.assertEqual(band, "Low")
        self.assertEqual(len(issues), 0)

    def test_score_vulnerabilities(self):
        dns_r = {"spf": "", "dmarc": ""}
        ssl_r = {"valid": False, "error": "certificate expired"}
        hdr = {"https_ok": False}

        sc, band, issues = snapshot.score(dns_r, ssl_r, hdr)
        self.assertGreater(sc, 50)
        self.assertIn(band, ("High", "Critical"))
        self.assertGreater(len(issues), 0)

    def test_render_html(self):
        html = snapshot.render_html("example.com", 25, "Medium", [{"severity": "medium", "title": "Test Issue", "detail": "Test Detail", "fix": "Fix it"}])
        self.assertIn("Security Snapshot — example.com", html)
        self.assertIn("Test Issue", html)
        self.assertIn("Medium risk", html)

    @patch("snapshot.check_dns")
    @patch("snapshot.check_ssl")
    @patch("snapshot.check_headers")
    def test_scan(self, mock_hdr, mock_ssl, mock_dns):
        mock_dns.return_value = {"resolves": True, "has_mail": True, "spf": "v=spf1", "dmarc": "v=DMARC1"}
        mock_ssl.return_value = {"valid": True, "days_to_expiry": 60, "issuer": "Let's Encrypt"}
        mock_hdr.return_value = {"https_ok": True, "redirects_https": True, "hsts": True, "csp": False, "xfo": True, "xcto": True, "referrer": True}

        res = snapshot.scan("https://example.com/")
        self.assertEqual(res["domain"], "example.com")
        self.assertIn("report_html", res)
        self.assertIn("risk_score", res)


if __name__ == "__main__":
    unittest.main()
