import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app

class TargetValidationTests(unittest.TestCase):
    def test_adds_https_when_scheme_missing(self):
        with patch("app.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("93.184.216.34", 443))]):
            self.assertEqual(app.validate_target("example.com"), "https://example.com")

    def test_blocks_localhost(self):
        with self.assertRaises(ValueError):
            app.validate_target("http://localhost")

    def test_blocks_private_ip(self):
        with self.assertRaises(ValueError):
            app.validate_target("http://192.168.1.10")

    def test_blocks_credentials(self):
        with self.assertRaises(ValueError):
            app.validate_target("https://user:pass@example.com")

    def test_blocks_custom_port(self):
        with self.assertRaises(ValueError):
            app.validate_target("https://example.com:8443")

    def test_blocks_private_dns_result(self):
        with patch("app.socket.getaddrinfo", return_value=[(2, 1, 6, "", ("127.0.0.1", 443))]):
            with self.assertRaises(ValueError):
                app.validate_target("https://example.com")

class RedirectHandlerRegressionTests(unittest.TestCase):
    def test_redirect_handler_is_accepted_by_urllib(self):
        # Regression: build_opener previously raised TypeError because the
        # custom class did not inherit from HTTPRedirectHandler.
        opener = app.build_opener(
            app._NoRedirectHandler(),
            app.HTTPSHandler(context=app.ssl.create_default_context()),
            app.HTTPHandler(),
        )
        self.assertIsNotNone(opener)

    def test_redirect_handler_refuses_redirects(self):
        handler = app._NoRedirectHandler()
        self.assertIsNone(handler.redirect_request(None, None, 302, "Found", {}, "https://example.org/"))


class HeaderAnalysisTests(unittest.TestCase):
    def test_missing_headers_create_findings(self):
        findings = app.analyze_headers({})
        titles = [f["title"] for f in findings]
        self.assertIn("Missing content-security-policy", titles)
        self.assertIn("Missing strict-transport-security", titles)

    def test_present_headers_are_not_reported_missing(self):
        findings = app.analyze_headers({
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "camera=()",
        })
        self.assertEqual(findings, [])

    def test_disclosed_server_header_is_informational(self):
        findings = app.analyze_headers({"Server": "example-server"})
        self.assertTrue(any(f["title"] == "Server header is disclosed" for f in findings))

class SecurityPostureTests(unittest.TestCase):
    def test_no_findings_produce_high_security_score(self):
        summary = app.summarize_findings([])
        self.assertGreaterEqual(summary["security_score"], 90)
        self.assertEqual(summary["risk_level"], "low")

    def test_missing_headers_reduce_security_score(self):
        findings = app.analyze_headers({})
        summary = app.summarize_findings(findings)
        self.assertLess(summary["security_score"], 60)
        self.assertIn(summary["risk_level"], {"medium", "high", "critical"})

class TLSInspectionTests(unittest.TestCase):
    def test_tls_summary_reports_expiry_and_validity(self):
        cert = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("commonName", "Example CA"),),),
            "notBefore": "Jun  1 00:00:00 2024 GMT",
            "notAfter": "Jun  1 00:00:00 2030 GMT",
        }
        summary = app.assess_tls("example.com", cert=cert)
        self.assertTrue(summary["valid"])
        self.assertIn("example.com", summary["subject"])
        self.assertGreater(summary["days_remaining"], 0)

if __name__ == "__main__":
    unittest.main()
