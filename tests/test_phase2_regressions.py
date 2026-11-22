from core.engine.orchestrator import _local_ai_findings
from core.recon.headers.header_auditor import HeaderAuditor
from core.standards.cvss_epss import StandardsCalculator
from core.standards.compliance import ComplianceEngine


def test_http_connection_does_not_report_missing_hsts():
    findings = HeaderAuditor.audit({}, "http://example.test")

    assert not any("HSTS" in finding.title for finding in findings)
    assert any("HTTP" in finding.title for finding in findings)


def test_https_connection_reports_missing_hsts():
    findings = HeaderAuditor.audit({}, "https://example.test")

    assert any("HSTS" in finding.title for finding in findings)


def test_missing_asvs_id_does_not_break_compliance_mapping():
    result = ComplianceEngine.calculate_compliance([{
        "asvs_requirement_id": None,
        "cwe_id": "CWE-89",
        "title": "SQL Injection",
    }])

    assert "V5.3.4" in result["failed_controls_list"]
    assert result["controls_passed"] == 0
    assert result["asvs_level1_score"] is None


def test_empty_findings_do_not_claim_unverified_compliance():
    result = ComplianceEngine.calculate_compliance([])

    assert result["controls_assessed"] == 0
    assert result["asvs_level1_score"] is None
    assert result["cis_controls_score"] is None


def test_missing_risk_matrix_values_are_not_replaced_with_scores():
    point = StandardsCalculator.get_risk_matrix_data([{
        "cvss_score": None,
        "epss_score": "invalid",
        "severity": None,
    }])[0]

    assert point["x_cvss"] is None
    assert point["y_epss"] is None
    assert point["severity"] == "N/A"
    assert point["priority"] == "N/A"


def test_rule_signals_and_neural_scores_remain_separate():
    findings = _local_ai_findings({
        "rule_based_signals": ["SQL Injection Pattern"],
        "rule_based_score": 0.88,
        "malicious_probability": 0.91,
        "score_source": "heuristic_fallback",
        "model_scores": {},
        "confidence": "91%",
    })

    assert len(findings) == 1
    assert "Rule-based signals" in findings[0].evidence
    assert "Model probability" not in findings[0].evidence


def test_unverified_neural_outputs_do_not_become_audit_findings():
    findings = _local_ai_findings({
        "rule_based_signals": ["SQL Injection Pattern"],
        "rule_match_weight": 0.88,
        "malicious_probability": 0.91,
        "score_source": "UNVERIFIED_LABEL_SEMANTICS",
        "model_scores": {},
        "model_inferences": {
            "codebert": {
                "predicted_class_index": 1,
                "raw_softmax": [0.09, 0.91],
                "label_status": "LABEL_SEMANTICS_UNVERIFIED",
            },
        },
        "model_name": "Nazzoor",
        "confidence": "91%",
    })

    assert len(findings) == 1
    assert "Rule-based signals" in findings[0].evidence
    assert "Nazzoor" not in findings[0].evidence
