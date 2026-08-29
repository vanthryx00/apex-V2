import unittest
from unittest.mock import patch
import snapshot

class TestSnapshotScan(unittest.TestCase):
    @patch('snapshot.check_dns')
    @patch('snapshot.check_ssl')
    @patch('snapshot.check_headers')
    def test_scan_concurrent(self, mock_headers, mock_ssl, mock_dns):
        mock_dns.return_value = {
            "resolves": True,
            "has_mail": True,
            "spf": "v=spf1 include:_spf.google.com ~all",
            "dmarc": "v=DMARC1; p=none;",
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

        result = snapshot.scan("https://example.com/")

        self.assertEqual(result["domain"], "example.com")
        self.assertEqual(result["risk_score"], 0)
        self.assertEqual(result["risk_band"], "Low")
        self.assertEqual(len(result["issues"]), 0)
        self.assertIn("example.com", result["report_html"])
        mock_dns.assert_called_once_with("example.com")
        mock_ssl.assert_called_once_with("example.com")
        mock_headers.assert_called_once_with("example.com")

if __name__ == "__main__":
    unittest.main()
