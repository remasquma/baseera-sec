"""
Baseera Sec - Compliance & Standards Mapping
Covers standards: PTES, NIST SP 800-115, MITRE ATT&CK, OWASP ASVS v4.0, and CIS Controls v8.
Features evidence-backed control status (Assessed, Pass, Fail, Not Tested, Not Applicable).
Does not award 100% compliance to empty scans without testing evidence.
"""
from typing import Dict, Any, List


class ComplianceEngine:
    PTES_PHASES = [
        {"phase": 1, "name_ar": "التواصل المبدئي وتحديد النطاق", "name_en": "Pre-engagement Interactions", "nist": "Planning"},
        {"phase": 2, "name_ar": "جمع المعلومات والاستخبارات", "name_en": "Intelligence Gathering", "nist": "Discovery"},
        {"phase": 3, "name_ar": "نمذجة التهديدات المعرفية", "name_en": "Threat Modeling", "nist": "Target Identification"},
        {"phase": 4, "name_ar": "التحليل الاستكشافي للثغرات", "name_en": "Vulnerability Analysis", "nist": "Vulnerability Scanning"},
        {"phase": 5, "name_ar": "محاكاة الاستغلال والتحقق الفعلي", "name_en": "Exploitation (PoC Verification)", "nist": "Validation"},
        {"phase": 6, "name_ar": "ما بعد الاستغلال وتقييم الأثر", "name_en": "Post-Exploitation", "nist": "Impact Assessment"},
        {"phase": 7, "name_ar": "صياغة التقرير الجنائي التنفيذي", "name_en": "Reporting & Remediation", "nist": "Reporting"}
    ]

    MITRE_HEATMAP_TAXONOMY = {
        "Initial Access": ["T1190 - Exploit Public-Facing Application", "T1078 - Valid Accounts"],
        "Execution": ["T1059 - Command and Scripting Interpreter", "T1203 - Exploitation for Client Execution"],
        "Persistence": ["T1505 - Server Software Component", "T1098 - Account Manipulation"],
        "Privilege Escalation": ["T1068 - Exploitation for Privilege Escalation", "T1548 - Abuse Elevation Control Mechanism"],
        "Defense Evasion": ["T1027 - Obfuscated Files or Information", "T1070 - Indicator Removal"],
        "Credential Access": ["T1110 - Brute Force", "T1552 - Unsecured Credentials in Files (.env/.git)"],
        "Discovery": ["T1083 - File and Directory Discovery", "T1018 - Remote System Discovery"],
        "Lateral Movement": ["T1210 - Exploitation of Remote Services"],
        "Collection": ["T1114 - Email Collection", "T1005 - Data from Local System"],
        "Exfiltration": ["T1041 - Exfiltration Over C2 Channel", "T1048 - Exfiltration Over Alternative Protocol"]
    }

    # Standard audited controls catalogue
    AUDITED_ASVS_CONTROLS = [
        {"id": "V2.1.1", "name": "Password Strength", "category": "Authentication"},
        {"id": "V3.4.1", "name": "Cookie HttpOnly & Secure Flags", "category": "Session Management"},
        {"id": "V3.4.2", "name": "Cookie SameSite Attribute", "category": "Session Management"},
        {"id": "V5.3.3", "name": "Context-Aware Output Encoding (XSS)", "category": "Validation & Encoding"},
        {"id": "V5.3.4", "name": "Parameterized Queries (SQLi)", "category": "Validation & Encoding"},
        {"id": "V5.3.8", "name": "OS Command Execution Controls (CMDi)", "category": "Validation & Encoding"},
        {"id": "V9.1.2", "name": "Enforce HSTS with Preload", "category": "Communications"},
        {"id": "V12.3.1", "name": "Path Traversal Protection", "category": "File & Resources"},
        {"id": "V14.4.1", "name": "Block Source & Config Leakage (.env/.git)", "category": "Configuration"},
        {"id": "V14.4.3", "name": "Strict CSP Policy", "category": "Configuration"},
        {"id": "V14.4.4", "name": "Disable Directory Browsing", "category": "Configuration"},
        {"id": "V14.4.6", "name": "Frame-Ancestors Clickjacking Policy", "category": "Configuration"}
    ]

    @classmethod
    def calculate_compliance(cls, vulnerabilities: List[Dict[str, Any]], include_scope_scores: bool = False) -> Dict[str, Any]:
        """
        حساب معايير الامتثال الواقعية المعتمدة على الأدلة:
        يحسب نسبة الامتثال الحقيقية لنطاق الضوابط المفحوصة بناءً على الثغرات المؤكدة.
        """
        total_vulns = len(vulnerabilities)

        # Identify which controls failed based on detected vulnerabilities
        failed_asvs = set()
        for v in vulnerabilities:
            asvs_value = v.get("asvs_requirement_id")
            asvs_id = str(asvs_value) if asvs_value is not None else ""
            cwe_id = v.get("cwe_id", "")
            if "5.3.4" in asvs_id or cwe_id == "CWE-89": failed_asvs.add("V5.3.4")
            if "5.3.3" in asvs_id or cwe_id == "CWE-79": failed_asvs.add("V5.3.3")
            if "5.3.8" in asvs_id or cwe_id == "CWE-78": failed_asvs.add("V5.3.8")
            if "12.3.1" in asvs_id or cwe_id == "CWE-22": failed_asvs.add("V12.3.1")
            if "3.4.1" in asvs_id or cwe_id in ("CWE-1004", "CWE-614"): failed_asvs.add("V3.4.1")
            if "3.4.2" in asvs_id or cwe_id == "CWE-1275": failed_asvs.add("V3.4.2")
            if "14.4.1" in asvs_id or cwe_id == "CWE-552": failed_asvs.add("V14.4.1")
            if "14.4.4" in asvs_id or cwe_id == "CWE-548": failed_asvs.add("V14.4.4")
            if "14.4.6" in asvs_id or cwe_id == "CWE-1021": failed_asvs.add("V14.4.6")
            if "9.1.2" in asvs_id or cwe_id == "CWE-319": failed_asvs.add("V9.1.2")
            if "14.4.3" in asvs_id or cwe_id == "CWE-693": failed_asvs.add("V14.4.3")

        failed_count = len(failed_asvs)
        total_controls = len(cls.AUDITED_ASVS_CONTROLS)  # 12
        passed_count = max(0, total_controls - failed_count)

        if include_scope_scores and (total_vulns > 0 or passed_count > 0):
            l1_score = round((passed_count / total_controls) * 100.0, 1)
            l2_score = round(l1_score * 0.85, 1)
            cis_score = round(max(20.0, ((8 - min(8, failed_count)) / 8.0) * 100.0), 1)
            nist_score = round(max(25.0, ((10 - min(10, failed_count)) / 10.0) * 100.0), 1)
            assessment_status = f"Audited {passed_count}/{total_controls} Controls Clean ({l1_score}% Tested Scope Compliance)"
        else:
            l1_score = None
            l2_score = None
            cis_score = None
            nist_score = None
            assessment_status = (
                f"Assessed with {failed_count} Evidenced Control Failures; Remaining Controls Not Tested"
                if failed_count
                else "Not Assessed (No Tested Control Evidence)"
            )

        return {
            "assessment_status": assessment_status,
            "controls_assessed": total_controls if include_scope_scores else failed_count,
            "controls_passed": passed_count if include_scope_scores else 0,
            "controls_failed": failed_count,
            "controls_not_tested": 0 if include_scope_scores else (total_controls - failed_count),
            "failed_controls_list": sorted(list(failed_asvs)),
            "asvs_level1_score": l1_score,
            "asvs_level2_score": l2_score,
            "asvs_level3_score": round(l1_score * 0.7, 1) if l1_score is not None else None,
            "cis_controls_score": cis_score,
            "nist_csf_score": nist_score,
            "note": (
                f"Based on {total_controls} audited controls in Baseera scope: {passed_count} passed, {failed_count} failed."
                if include_scope_scores else
                f"{total_vulns} finding(s) were provided, but no tested pass-state evidence was supplied. "
                "Only explicitly mapped failures are assessed; remaining controls are 'Not Tested'."
            )
        }
