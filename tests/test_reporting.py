"""
Unit Tests for Phase 5 - Reporting Engine (HTML, SARIF, TXT, and PDF Security)
"""
import unittest
import json
from core.reporting.enterprise_reporter import EnterpriseReporter


class TestReportingEngine(unittest.TestCase):

    def setUp(self):
        self.sample_project = {
            "name": "Test Web Application",
            "target_url": "https://testapp.local",
            "target_type": "Web Application",
            "methodology": "PTES"
        }
        self.sample_vulns = [
            {
                "vuln_code": "VULN-001",
                "title": "SQL Injection in User Search",
                "severity": "CRITICAL",
                "cvss_score": 9.8,
                "cwe_id": "CWE-89",
                "cve_id": "N/A",
                "target_endpoint": "https://testapp.local/users?id=1",
                "description": "SQL syntax break allows raw query injection.",
                "poc_evidence": "<script>alert('xss_in_evidence')</script> -- DBMS Error: MySQL syntax error",
                "remediation_roadmap": "Use PDO prepared statements."
            }
        ]
        self.sample_compliance = {
            "asvs_level1_score": 91.7,
            "cis_controls_score": 82.5
        }

    def test_html_report_escaping(self):
        html_out = EnterpriseReporter.generate_html_report(
            self.sample_project,
            self.sample_vulns,
            [],
            self.sample_compliance,
            lang="ar"
        )
        self.assertIn("Content-Security-Policy", html_out)
        # Ensure raw unescaped script tag in evidence is sanitized
        self.assertNotIn("<script>alert('xss_in_evidence')</script>", html_out)
        self.assertIn("&lt;script&gt;alert(&#x27;xss_in_evidence&#x27;)&lt;/script&gt;", html_out)

    def test_sarif_generation(self):
        sarif_str = EnterpriseReporter.generate_sarif({
            "target_url": "https://testapp.local",
            "vulnerabilities": self.sample_vulns
        })
        sarif_doc = json.loads(sarif_str)
        self.assertEqual(sarif_doc["version"], "2.1.0")
        self.assertIn("runs", sarif_doc)
        results = sarif_doc["runs"][0]["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["ruleId"], "VULN-001")

    def test_txt_report_generation(self):
        txt_out = EnterpriseReporter.generate_txt_report(
            self.sample_project,
            self.sample_vulns,
            [],
            self.sample_compliance
        )
        self.assertIn("BASEERA SEC - ENTERPRISE VAPT SECURITY ASSESSMENT REPORT", txt_out)
        self.assertIn("VULN-001", txt_out)
        self.assertIn("SQL Injection in User Search", txt_out)

    def test_nullable_and_invalid_metrics_are_reported_as_unavailable(self):
        incomplete_vulns = [{
            "vuln_code": "VULN-NULL",
            "title": None,
            "severity": None,
            "cvss_score": "not-a-number",
            "cwe_id": None,
            "cve_id": None,
            "epss_score": None,
            "mitre_technique_id": None,
            "owasp_category": None,
            "asvs_level": None,
            "asvs_requirement_id": None,
            "cis_control_id": None,
            "description": None,
            "poc_evidence": None,
            "remediation_roadmap": None,
            "target_endpoint": None,
        }]
        compliance = {"asvs_level1_score": None, "cis_controls_score": None}

        html_out = EnterpriseReporter.generate_html_report(
            {}, incomplete_vulns, [], compliance
        )
        txt_out = EnterpriseReporter.generate_txt_report(
            {}, incomplete_vulns, [], compliance
        )
        sarif = json.loads(EnterpriseReporter.generate_sarif({
            "vulnerabilities": incomplete_vulns
        }))

        self.assertIn("N/A / 10", html_out)
        self.assertIn("ASVS Level:</strong> N/A (N/A)", html_out)
        self.assertIn("N/A%", html_out)
        self.assertNotIn("CWE-200", html_out)
        self.assertIn("Peak CVSS Score                : N/A / 10.0", txt_out)
        self.assertIn("CVSS N/A", txt_out)
        self.assertIn("N/A%", txt_out)
        rule = sarif["runs"][0]["tool"]["driver"]["rules"][0]
        self.assertEqual(rule["properties"]["cwe"], "N/A")
        self.assertIsNone(rule["properties"]["cvss"])

    def test_zero_epss_is_preserved_when_available(self):
        html_out = EnterpriseReporter.generate_html_report(
            {},
            [{"cve_id": "CVE-2026-1234", "epss_score": 0.0}],
            [],
            {},
        )

        self.assertIn("<strong>EPSS:</strong> 0.0%", html_out)

    def test_empty_report_does_not_claim_a_clean_tested_scope(self):
        html_out = EnterpriseReporter.generate_html_report({}, [], [], {})
        txt_out = EnterpriseReporter.generate_txt_report({}, [], [], {})

        self.assertIn("لا يُستنتج اجتيازها من غياب السجلات", html_out)
        self.assertIn("No vulnerability records are available", txt_out)
        self.assertNotIn("No active vulnerabilities confirmed in tested scope", txt_out)


if __name__ == "__main__":
    unittest.main()
