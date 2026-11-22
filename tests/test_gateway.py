"""
Unit Tests for Baseera Sec RequestGateway (Scope Enforcement & Network Hardening)
"""
import unittest
import asyncio
from core.network.request_gateway import (
    RequestGateway,
    ScopeViolationError,
    BudgetExceededError,
    ScanBudget
)


class TestRequestGateway(unittest.IsolatedAsyncioTestCase):

    async def test_scheme_validation(self):
        gw = RequestGateway("http://example.com")
        with self.assertRaises(ScopeViolationError):
            gw.validate_destination("ftp://example.com/file")
        with self.assertRaises(ScopeViolationError):
            gw.validate_destination("file:///etc/passwd")

    async def test_domain_scope_enforcement(self):
        dns_map = {"app.example.com": "93.184.216.34", "api.example.com": "93.184.216.34"}
        gw = RequestGateway("https://app.example.com", allowed_domains=["example.com"], dns_mapping=dns_map)
        # Should allow subdomain of allowed domain
        host, ip, port = gw.validate_destination("https://api.example.com/test")
        self.assertEqual(host, "api.example.com")

        # Should block external domains
        with self.assertRaises(ScopeViolationError):
            gw.validate_destination("https://evil.attacker.org/test")

    async def test_private_and_loopback_ip_blocking(self):
        gw = RequestGateway("http://example.com", allow_internal_targets=False)
        # Block localhost / loopback
        with self.assertRaises(ScopeViolationError):
            gw.validate_destination("http://localhost:8080")
        with self.assertRaises(ScopeViolationError):
            gw.validate_destination("http://127.0.0.1:8765")
        with self.assertRaises(ScopeViolationError):
            gw.validate_destination("http://169.254.169.254/latest/meta-data/")

    async def test_dry_run_mode(self):
        gw = RequestGateway("http://example.com", dry_run=True)
        res = await gw.request("GET", "http://example.com/test")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"DRY-RUN", res.content)

    async def test_budget_exceeded(self):
        budget = ScanBudget(max_requests=2)
        gw = RequestGateway("http://example.com", budget=budget, dry_run=True)
        await gw.request("GET", "http://example.com/1")
        await gw.request("GET", "http://example.com/2")
        with self.assertRaises(BudgetExceededError):
            await gw.request("GET", "http://example.com/3")

    async def test_cancellation(self):
        gw = RequestGateway("http://example.com", dry_run=True)
        gw.cancel_scan()
        with self.assertRaises(asyncio.CancelledError):
            await gw.request("GET", "http://example.com/test")


if __name__ == "__main__":
    unittest.main()
