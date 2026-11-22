"""
Unit Tests for Phase 2 - Baseera Sec Vulnerability Detectors
Verifies accuracy, edge cases, false positive resistance, and evidence collection.
"""
import unittest
import httpx
from core.verifier.engine.sql_detector import SQLDetector
from core.verifier.engine.xss_detector import XSSDetector
from core.verifier.engine.cmdi_detector import CMDiDetector
from core.verifier.engine.traversal_detector import TraversalDetector
from core.verifier.engine.ssti_detector import SSTIDetector
from core.verifier.engine.idor_detector import IDORDetector
from core.verifier.engine.ssrf_detector import SSRFDetector


class TestVulnerabilityDetectors(unittest.IsolatedAsyncioTestCase):

    async def test_xss_positive_dom_tag(self):
        # Mock client returning unescaped tag in HTML
        async def mock_handler(request):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                content=b"<html><body><h1>Search Results</h1><baseeraxss731 id='poc'></body></html>"
            )

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            res = await XSSDetector.audit_parameter("http://testapp.local/search?q=test", "q", "GET", client)
            self.assertIsNotNone(res)
            self.assertTrue(res.get("is_vulnerable"))
            self.assertEqual(res.get("type"), "Reflected Cross-Site Scripting (XSS)")

    async def test_xss_negative_html_comment(self):
        # Mock client reflecting inside HTML comment
        async def mock_handler(request):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                content=b"<html><body><!-- user input: <baseeraxss731 id='poc'> --></body></html>"
            )

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            res = await XSSDetector.audit_parameter("http://testapp.local/search?q=test", "q", "GET", client)
            self.assertIsNotNone(res)
            self.assertFalse(res.get("is_vulnerable"))
            self.assertIn("Comment", res.get("type"))

    async def test_xss_negative_html_encoded(self):
        # Mock client reflecting entity-encoded probe
        async def mock_handler(request):
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html"},
                content=b"<html><body>Hello &lt;baseeraxss731 id=&#39;poc&#39;&gt;</body></html>"
            )

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            res = await XSSDetector.audit_parameter("http://testapp.local/search?q=test", "q", "GET", client)
            self.assertIsNotNone(res)
            self.assertFalse(res.get("is_vulnerable"))
            self.assertIn("Sanitized", res.get("type"))

    async def test_cmdi_positive_evaluation(self):
        # Mock client: returns clean baseline, evaluates arithmetic expr when injected
        async def mock_handler(request):
            url_str = str(request.url)
            if "expr" in url_str:
                return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=b"PING output:\n67385\n1 packets transmitted")
            return httpx.Response(200, headers={"Content-Type": "text/plain"}, content=b"PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.")

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            res = await CMDiDetector.audit_parameter("http://testapp.local/ping?ip=127.0.0.1", "ip", "127.0.0.1", "GET", client)
            self.assertIsNotNone(res)
            self.assertTrue(res.get("is_vulnerable"))
            self.assertEqual(res.get("type"), "OS Command Injection (CWE-78)")

    async def test_cmdi_negative_verbatim_echo(self):
        # Mock client mirroring the probe string verbatim
        async def mock_handler(request):
            url_str = str(request.url)
            return httpx.Response(
                200,
                headers={"Content-Type": "text/plain"},
                content=f"Error processing address: {url_str}".encode()
            )

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            res = await CMDiDetector.audit_parameter("http://testapp.local/ping?ip=127.0.0.1", "ip", "127.0.0.1", "GET", client)
            # Should not report positive vulnerability on verbatim mirror
            self.assertTrue(res is None or not res.get("is_vulnerable"))

    async def test_traversal_positive(self):
        async def mock_handler(request):
            url_str = str(request.url)
            if "passwd" in url_str:
                return httpx.Response(200, content=b"root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n")
            return httpx.Response(200, content=b"Welcome to documentation index page.")

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            res = await TraversalDetector.audit_parameter("http://testapp.local/view?file=index.html", "file", "index.html", "GET", client)
            self.assertIsNotNone(res)
            self.assertTrue(res.get("is_vulnerable"))
            self.assertEqual(res.get("type"), "Path Traversal & Arbitrary File Read (CWE-22)")

    async def test_idor_requires_two_valid_accounts_and_own_resource(self):
        # User A's secret profile accessed by User B
        async def mock_handler(request):
            auth = request.headers.get("Authorization", "")
            return httpx.Response(200, content=b'{"id": 42, "email": "victim_alice@corp.internal", "balance": 9500.00}')

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as client:
            res = await IDORDetector.audit_parameter(
                target_url="http://testapp.local/api/profile?user_id=42",
                param_name="user_id",
                current_val="42",
                method="GET",
                client=client,
                secondary_client_headers={"Authorization": "Bearer token_attacker_bob_999"}
            )
            self.assertIsNotNone(res)
            self.assertFalse(res.get("is_vulnerable"))
            self.assertEqual(res.get("status"), "DUAL_ACCOUNT_REQUIRED")


if __name__ == "__main__":
    unittest.main()
