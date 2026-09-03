import unittest
from unittest.mock import patch
import snapshot

class TestSnapshot(unittest.TestCase):
    @patch('snapshot.check_dns')
    @patch('snapshot.check_ssl')
    @patch('snapshot.check_headers')
    def test_scan_concurrent_results(self, mock_hdr, mock_ssl, mock_dns):
        mock_dns.return_value = {
            "resolves": True,
            "has_mail": True,
            "spf": "v=spf1 include:_spf.google.com ~all",
            "dmarc": "v=DMARC1; p=none;",
        }
        mock_ssl.return_value = {
            "valid": True,
            "days_to_expiry": 100,
            "issuer": "Let's Encrypt",
        }
        mock_hdr.return_value = {
            "https_ok": True,
            "redirects_https": True,
            "hsts": True,
            "csp": True,
            "xfo": True,
            "xcto": True,
            "referrer": True,
        }

        res = snapshot.scan("example.com")
        self.assertEqual(res["domain"], "example.com")
        self.assertEqual(res["risk_score"], 0)
        self.assertEqual(res["risk_band"], "Low")
        self.assertEqual(len(res["issues"]), 0)

        mock_dns.assert_called_once_with("example.com")
        mock_ssl.assert_called_once_with("example.com")
        mock_hdr.assert_called_once_with("example.com")

if __name__ == '__main__':
    unittest.main()
