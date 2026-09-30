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

    @patch("snapshot.urlopen")
    def test_check_headers(self, mock_urlopen):
        mock_response_https = MagicMock()
        mock_response_https.__enter__.return_value = mock_response_https
        mock_response_https.headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "no-referrer",
        }

        mock_response_http = MagicMock()
        mock_response_http.__enter__.return_value = mock_response_http
        mock_response_http.url = "https://example.com"

        def urlopen_side_effect(req, timeout=None):
            if req.full_url.startswith("https://"):
                return mock_response_https
            else:
                return mock_response_http

        mock_urlopen.side_effect = urlopen_side_effect

        res = snapshot.check_headers("example.com")
        self.assertTrue(res["https_ok"])
        self.assertTrue(res["redirects_https"])
        self.assertTrue(res["hsts"])
        self.assertTrue(res["csp"])
        self.assertTrue(res["xfo"])
        self.assertTrue(res["xcto"])
        self.assertTrue(res["referrer"])

    def test_get_ssl_context_caching(self):
        ctx1 = snapshot._get_ssl_context()
        ctx2 = snapshot._get_ssl_context()
        self.assertIs(ctx1, ctx2)

    @patch("socket.create_connection")
    def test_check_ssl_success(self, mock_create_conn):
        mock_sock = MagicMock()
        mock_ss = MagicMock()
        mock_create_conn.return_value.__enter__.return_value = mock_sock

        # Mock wrap_socket on the cached SSLContext
        ctx = snapshot._get_ssl_context()
        with patch.object(ctx, "wrap_socket", return_value=mock_ss):
            mock_ss.__enter__.return_value = mock_ss
            mock_ss.getpeercert.return_value = {
                "notAfter": "Jan 01 00:00:00 2099 UTC",
                "issuer": ((("organizationName", "Test CA"),),),
            }

            res = snapshot.check_ssl("example.com")
            self.assertTrue(res["valid"])
            self.assertEqual(res["issuer"], "Test CA")
            self.assertGreater(res["days_to_expiry"], 0)

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
