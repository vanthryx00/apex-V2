import unittest
import snapshot

class TestSnapshot(unittest.TestCase):
    def test_score_calculation(self):
        dns_clean = {"resolves": True, "has_mail": True, "spf": "v=spf1 include:_spf.google.com ~all", "dmarc": "v=DMARC1; p=reject;"}
        ssl_clean = {"valid": True, "days_to_expiry": 100, "issuer": "Let's Encrypt"}
        hdr_clean = {"https_ok": True, "redirects_https": True, "hsts": True, "csp": True, "xfo": True, "xcto": True, "referrer": True}

        sc, band, issues = snapshot.score(dns_clean, ssl_clean, hdr_clean)
        self.assertEqual(sc, 0)
        self.assertEqual(band, "Low")
        self.assertEqual(len(issues), 0)

    def test_score_vulnerabilities(self):
        dns_vuln = {"resolves": True, "has_mail": False, "spf": "", "dmarc": ""}
        ssl_vuln = {"valid": False, "error": "connection refused"}
        hdr_vuln = {"https_ok": False, "redirects_https": False}

        sc, band, issues = snapshot.score(dns_vuln, ssl_vuln, hdr_vuln)
        self.assertGreaterEqual(sc, 60)
        self.assertIn(band, ["High", "Critical"])
        self.assertGreaterEqual(len(issues), 3)

    def test_scan_returns_expected_keys(self):
        res = snapshot.scan("example.com")
        self.assertEqual(res["domain"], "example.com")
        self.assertIn("risk_score", res)
        self.assertIn("risk_band", res)
        self.assertIn("issues", res)
        self.assertIn("findings", res)
        self.assertIn("report_html", res)
        self.assertIn("<!DOCTYPE html>", res["report_html"])

if __name__ == "__main__":
    unittest.main()
