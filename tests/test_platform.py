"""
Baseera Sec - Platform Verification & Health Check Tests
Unit and component tests verifying engine orchestrator, verifiers, parsers, and standards.
"""

import unittest
import os
import sys

# Ensure core is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(CURRENT_DIR)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.auth.auth_manager import AuthManager, AuthConfig
from core.recon.api.api_parser import APISchemaParser
from core.verifier.engine.ssti_detector import SSTIDetector
from core.verifier.engine.fp_guard import ZeroFPGuard
from core.standards.cvss_epss import StandardsCalculator


class TestBaseeraSecComponents(unittest.TestCase):

    def test_auth_manager_session_generation(self):
        cfg = AuthConfig(auth_type="bearer", bearer_token="test_jwt_token_123")
        auth = AuthManager(cfg)
        headers = auth.inject_auth_headers({})
        self.assertIn("Authorization", headers)
        self.assertEqual(headers["Authorization"], "Bearer test_jwt_token_123")

    def test_ssti_detector_probes(self):
        self.assertGreater(len(SSTIDetector.SSTI_PROBES), 0)
        probe, expected, desc = SSTIDetector.SSTI_PROBES[0]
        self.assertIn("7*7", probe)
        self.assertEqual(expected, "49")

    def test_fp_guard_filtering(self):
        self.assertTrue(ZeroFPGuard.is_benign_third_party_resource("https://code.jquery.com/jquery-3.6.0.min.js"))
        self.assertTrue(ZeroFPGuard.is_infrastructure_cookie("AWSALB"))
        self.assertTrue(ZeroFPGuard.is_infrastructure_cookie("cf_clearance"))
        self.assertFalse(ZeroFPGuard.is_infrastructure_cookie("PHPSESSID"))

    def test_cvss_epss_priority(self):
        p_crit = StandardsCalculator.calculate_priority(9.8, 0.85)
        self.assertIn("P1", p_crit)
        p_low = StandardsCalculator.calculate_priority(3.1, 0.01)
        self.assertIn("P4", p_low)

    def test_api_schema_parser(self):
        import json
        sample_swagger = {
            "swagger": "2.0",
            "paths": {
                "/users/{id}": {
                    "get": {
                        "parameters": [{"name": "id", "in": "path", "type": "integer"}]
                    }
                }
            }
        }
        endpoints = APISchemaParser.parse_schema_content(json.dumps(sample_swagger), "https://api.example.com")
        self.assertEqual(len(endpoints), 1)
        self.assertEqual(endpoints[0].method, "GET")


if __name__ == "__main__":
    unittest.main()
