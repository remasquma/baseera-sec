"""
Baseera Sec - Enterprise Report Generator
Generates hardened executive & technical reports in SARIF v2.1.0, HTML, and PDF.
Includes context-aware HTML escaping, Content Security Policy (CSP),
unique secured temporary files, and isolated browser profile rendering for PDF.
"""
import os
import json
import time
import html
import math
import tempfile
import shutil
import subprocess
from typing import Dict, Any, List, Optional


def _number_or_none(value: Any) -> Optional[float]:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


def _display_value(value: Any, fallback: str = "N/A") -> str:
    return fallback if value is None or value == "" else str(value)


class EnterpriseReporter:

    @staticmethod
    def generate_sarif(report_data: Dict[str, Any]) -> str:
        """
        توليد تقرير بصيغة SARIF v2.1.0 (معيار منظمة OASIS الدولي لأدوات الفحص الأمني)
        محدث: ضمان فرادة معرفات القواعد (Unique Rule IDs) دون أي تكرار وفق المعايير القياسية
        """
        rules_dict = {}
        results = []

        for idx, v in enumerate(report_data.get("vulnerabilities", [])):
            cwe_id = _display_value(v.get("cwe_id"))
            rule_id = v.get("vuln_code") or f"BASEERA-RULE-{idx+1:03d}"
            title = _display_value(v.get("title"))
            description = _display_value(v.get("description"))

            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": title,
                    "shortDescription": {"text": title},
                    "fullDescription": {"text": description},
                    "helpUri": (
                        f"https://cwe.mitre.org/data/definitions/{cwe_id[4:]}.html"
                        if cwe_id.startswith("CWE-") and cwe_id[4:].isdigit()
                        else "https://baseerasec.local"
                    ),
                    "properties": {
                        "cwe": cwe_id,
                        "cvss": _number_or_none(v.get("cvss_score")),
                        "epss": (
                            _number_or_none(v.get("epss_score"))
                            if v.get("cve_id") not in (None, "", "N/A")
                            else None
                        ),
                        "mitre": v.get("mitre_technique_id")
                    }
                }

            raw_uri = str(
                v.get("target_endpoint")
                or v.get("affected_url")
                or report_data.get("target_url")
                or ""
            ).strip()
            is_inline = "inline script" in raw_uri.lower() or "inline" in raw_uri.lower()
            import re
            url_match = re.search(r'https?://[^\s\'"<>]+', raw_uri)
            clean_uri = url_match.group(0) if url_match else raw_uri

            evidence_txt = _display_value(v.get("poc_evidence"), "")
            message_text = f"[Inline Script] {title}: {evidence_txt}" if is_inline else f"{title}: {evidence_txt}"

            results.append({
                "ruleId": rule_id,
                "level": "error" if v.get("severity") in ["CRITICAL", "HIGH"] else "warning",
                "message": {"text": message_text},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": clean_uri}
                    }
                }]
            })

        sarif_doc = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "Baseera Sec Cognitive VAPT",
                        "version": "2.6.0",
                        "informationUri": "https://baseerasec.local",
                        "rules": list(rules_dict.values())
                    }
                },
                "results": results
            }]
        }
        return json.dumps(sarif_doc, indent=2, ensure_ascii=False)

    @staticmethod
    def generate_html_report(project: Dict[str, Any], vulnerabilities: List[Dict[str, Any]], attacks: List[Dict[str, Any]], compliance: Dict[str, Any], lang="ar") -> str:
        """
        توليد تقرير HTML متكامل ثنائي اللغة (تنفيذي + تقني مفصل)
        مع تطبيق تشفير HTML Context-Aware و CSP لمنع أي حقن
        """
        is_ar = (lang == "ar")
        direction = "rtl" if is_ar else "ltr"
        font_family = "'Noto Sans Arabic', sans-serif" if is_ar else "'Segoe UI', Roboto, sans-serif"

        vuln_rows = ""
        for v in vulnerabilities:
            badge_color = "#ef4444" if v.get("severity") == "CRITICAL" else "#f97316" if v.get("severity") == "HIGH" else "#f59e0b"

            # HTML sanitization of untrusted scan inputs
            safe_code = html.escape(_display_value(v.get("vuln_code")))
            safe_title = html.escape(_display_value(v.get("title")))
            safe_sev = html.escape(_display_value(v.get("severity")))
            cvss_score = _number_or_none(v.get("cvss_score"))
            safe_cvss = html.escape(f"{cvss_score:.1f}" if cvss_score is not None else "N/A")
            safe_endpoint = html.escape(_display_value(
                v.get("target_endpoint") or v.get("affected_url") or project.get("target_url")
            ))
            safe_cve = html.escape(_display_value(v.get("cve_id")))
            safe_cwe = html.escape(_display_value(v.get("cwe_id")))
            safe_mitre = html.escape(_display_value(v.get("mitre_technique_id")))
            safe_owasp = html.escape(_display_value(v.get("owasp_category")))
            asvs_level = _display_value(v.get("asvs_level"))
            asvs_requirement = _display_value(v.get("asvs_requirement_id"))
            safe_asvs = html.escape(f"{asvs_level} ({asvs_requirement})")
            safe_cis = html.escape(_display_value(v.get("cis_control_id")))
            safe_desc = html.escape(_display_value(v.get("description"), ""))
            safe_evidence = html.escape(_display_value(v.get("poc_evidence"), ""))
            safe_remediation = html.escape(_display_value(v.get("remediation_roadmap"), ""))

            epss_val = v.get('epss_score')
            epss_number = _number_or_none(epss_val)
            if v.get("cve_id") not in (None, "", "N/A") and epss_number is not None:
                safe_epss = html.escape(f"{round(epss_number * 100, 1)}%")
            else:
                safe_epss = "N/A"

            vuln_rows += f"""
            <div style="background:#ffffff; border:1px solid #e2e8f0; border-radius:8px; padding:18px; margin-bottom:18px; box-shadow:0 1px 4px rgba(0,0,0,0.04);">
              <div style="display:flex; justify-content:space-between; align-items:center; border-bottom:1px solid #f1f5f9; padding-bottom:10px; margin-bottom:12px;">
                <div>
                  <span style="background:#0f172a; color:#38bdf8; padding:3px 8px; border-radius:4px; font-family:monospace; font-size:8.5pt;">{safe_code}</span>
                  <strong style="font-size:12pt; color:#0f172a; margin-right:8px;">{safe_title}</strong>
                </div>
                <span style="background:{badge_color}; color:#ffffff; padding:4px 10px; border-radius:6px; font-weight:bold; font-size:9pt;">{safe_sev} (CVSS {safe_cvss})</span>
              </div>

              <div style="font-size:8.5pt; color:#475569; margin-bottom:10px; direction:ltr; text-align:left; background:#f1f5f9; padding:4px 8px; border-radius:4px; font-family:monospace;">
                <strong>Affected Target URI:</strong> {safe_endpoint}
              </div>
              
              <div style="display:grid; grid-template-columns:repeat(4, 1fr); gap:10px; background:#f8fafc; padding:10px; border-radius:6px; font-size:8.5pt; margin-bottom:12px;">
                <div><strong>CVE:</strong> {safe_cve}</div>
                <div><strong>CWE:</strong> {safe_cwe}</div>
                <div><strong>EPSS:</strong> {safe_epss}</div>
                <div><strong>MITRE:</strong> {safe_mitre}</div>
              </div>

              <div style="display:grid; grid-template-columns:repeat(3, 1fr); gap:10px; background:#f0fdf4; padding:8px 10px; border-radius:6px; font-size:8.5pt; margin-bottom:12px;">
                <div><strong>OWASP:</strong> {safe_owasp}</div>
                <div><strong>ASVS Level:</strong> {safe_asvs}</div>
                <div><strong>CIS Control:</strong> {safe_cis}</div>
              </div>

              <p style="font-size:9.5pt; color:#334155; margin-bottom:10px;"><strong>الوصف:</strong> {safe_desc}</p>
              
              <div style="background:#090d16; color:#f87171; border-radius:6px; padding:10px 14px; font-family:monospace; font-size:8pt; direction:ltr; text-align:left; margin-bottom:10px; white-space:pre-wrap;">
                <strong>PoC Verified Evidence:</strong><br>{safe_evidence}
              </div>

              <div style="background:#eff6ff; border-right:4px solid #2563eb; padding:10px 14px; border-radius:0 6px 6px 0; font-size:9pt; color:#1e3a8a; white-space:pre-wrap;">
                <strong>خطة الترقيع والمعالجة (Remediation Roadmap):</strong><br>{safe_remediation}
              </div>
            </div>
            """

        safe_proj_name = html.escape(_display_value(project.get("name")))
        safe_proj_type = html.escape(_display_value(project.get("target_type")))
        safe_proj_url = html.escape(_display_value(project.get("target_url")))
        cvss_scores = [
            score for score in (_number_or_none(v.get("cvss_score")) for v in vulnerabilities)
            if score is not None
        ]
        peak_cvss = f"{max(cvss_scores):.1f}" if cvss_scores else "N/A"
        asvs_val = _number_or_none(compliance.get("asvs_level1_score"))
        cis_val = _number_or_none(compliance.get("cis_controls_score"))
        asvs_score_str = f"{asvs_val:.1f}%" if asvs_val is not None else "N/A%"
        cis_score_str = f"{cis_val:.1f}%" if cis_val is not None else "N/A%"

        advisory_note = compliance.get("note")
        if advisory_note:
            advisory_text = f"{advisory_note} تُعرض السجلات وفق نطاق الفحص المتاح، ولا يُستنتج اجتيازها من غياب السجلات."
        else:
            advisory_text = "يعرض هذا التقرير السجلات والأدلة المتاحة للمشروع وقت التصدير. الحقول والضوابط التي لا تتوفر لها بيانات تبقى غير مقيّمة، ولا يُستنتج اجتيازها من غياب السجلات."

        html_doc = f"""<!DOCTYPE html>
<html dir="{direction}" lang="{lang}">
<head>
  <meta charset="utf-8">
  <meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; font-src 'self';">
  <title>تقرير فحص واختبار الاختراق - {safe_proj_name}</title>
  <style>
    body {{ font-family: {font_family}; background:#f8fafc; color:#0f172a; margin:0; padding:30px; line-height:1.6; }}
    .header {{ background:#0f172a; color:white; border-radius:12px; padding:30px; margin-bottom:25px; }}
    .badge {{ display:inline-block; padding:4px 12px; border-radius:20px; font-size:8.5pt; font-weight:bold; }}
    .grid-4 {{ display:grid; grid-template-columns:repeat(4, 1fr); gap:15px; margin:20px 0; }}
    .card {{ background:white; border:1px solid #e2e8f0; border-radius:10px; padding:18px; }}
    .section-title {{ font-size:16pt; font-weight:800; border-bottom:2px solid #0284c7; padding-bottom:8px; margin:30px 0 16px 0; }}
  </style>
</head>
<body>

  <div class="header">
    <span class="badge" style="background:#0284c7;">مشروع {safe_proj_type} | منهجية PTES و NIST SP 800-115</span>
    <h1 style="margin:12px 0 6px 0; font-size:24pt;">تقرير اختبار الاختراق والتقييم الأمني الشامل</h1>
    <div style="color:#94a3b8; font-size:10pt;">الهدف المعتمد: {safe_proj_url} | تاريخ الفحص: {time.strftime('%Y-%m-%d %H:%M:%S')}</div>
  </div>

  <!-- القسم 1: الملخص التنفيذي -->
  <h2 class="section-title">1. الملخص التنفيذي (Executive Summary)</h2>
  <div class="grid-4">
    <div class="card">
      <div style="font-size:8.5pt; color:#64748b;">مؤشر الخطر العام (Risk Score)</div>
      <div style="font-size:24pt; font-weight:800; color:#ef4444;">{peak_cvss} / 10</div>
    </div>
    <div class="card">
      <div style="font-size:8.5pt; color:#64748b;">إجمالي الثغرات المؤكدة (PoC)</div>
      <div style="font-size:24pt; font-weight:800; color:#8b5cf6;">{len(vulnerabilities)}</div>
    </div>
    <div class="card">
      <div style="font-size:8.5pt; color:#64748b;">نسبة الامتثال لـ OWASP ASVS</div>
      <div style="font-size:24pt; font-weight:800; color:#10b981;">{asvs_score_str}</div>
    </div>
    <div class="card">
      <div style="font-size:8.5pt; color:#64748b;">نسبة الامتثال لـ CIS Controls v8</div>
      <div style="font-size:24pt; font-weight:800; color:#0ea5e9;">{cis_score_str}</div>
    </div>
  </div>

  <div class="card" style="margin-bottom:25px;">
    <strong>الرأي الاستشاري والامتثال الفعلي للضوابط المفحوصة:</strong>
    <p>{advisory_text}</p>
  </div>

  <!-- القسم 2: التقرير التقني المفصل -->
  <h2 class="section-title">2. التقرير التقني المفصل للثغرات (Detailed Technical Findings)</h2>
  {vuln_rows}

</body>
</html>
"""
        return html_doc

    @staticmethod
    def export_pdf(html_content: str, output_pdf_path: str) -> str:
        """
        طباعة تقرير PDF عالي الجودة باستخدام Chrome Headless
        ضمن بيئة معزولة (Disposable Profile) وملفات مؤقتة آمنة
        """
        chrome_bin = shutil.which("google-chrome") or shutil.which("chromium-browser") or shutil.which("chromium")
        if not chrome_bin:
            raise RuntimeError("Chrome or Chromium browser binary is not installed on this system.")

        temp_profile = tempfile.mkdtemp(prefix="baseera_pdf_prof_")
        temp_html_fd, temp_html_path = tempfile.mkstemp(prefix="baseera_report_", suffix=".html")

        try:
            with os.fdopen(temp_html_fd, "w", encoding="utf-8") as f:
                f.write(html_content)

            cmd = [
                chrome_bin,
                "--headless=new",
                "--disable-gpu",
                "--disable-dev-shm-usage",
                f"--user-data-dir={temp_profile}",
                "--disable-background-networking",
                "--disable-default-apps",
                "--disable-extensions",
                "--disable-sync",
                "--no-first-run",
                "--no-pdf-header-footer",
                f"--print-to-pdf={output_pdf_path}",
                temp_html_path
            ]
            subprocess.run(cmd, check=True, timeout=30)
            return output_pdf_path
        finally:
            if os.path.exists(temp_html_path):
                os.remove(temp_html_path)
            if os.path.exists(temp_profile):
                shutil.rmtree(temp_profile, ignore_errors=True)

    @staticmethod
    def generate_txt_report(project: Dict[str, Any], vulnerabilities: List[Dict[str, Any]], attacks: List[Dict[str, Any]], compliance: Dict[str, Any]) -> str:
        """
        توليد تقرير نصي شامل (Plain Text Security Report) متوافق في بياناته مع صيغ JSON و HTML و PDF
        """
        cvss_scores = [
            score for score in (_number_or_none(v.get("cvss_score")) for v in vulnerabilities)
            if score is not None
        ]
        peak_cvss = f"{max(cvss_scores):.1f}" if cvss_scores else "N/A"
        asvs_txt = f"{_number_or_none(compliance.get('asvs_level1_score')):.1f}%" if _number_or_none(compliance.get('asvs_level1_score')) is not None else "N/A%"
        cis_txt = f"{_number_or_none(compliance.get('cis_controls_score')):.1f}%" if _number_or_none(compliance.get('cis_controls_score')) is not None else "N/A%"
        lines = [
            "=" * 80,
            "BASEERA SEC - ENTERPRISE VAPT SECURITY ASSESSMENT REPORT",
            "=" * 80,
            f"Project Name   : {_display_value(project.get('name'))}",
            f"Target URL     : {_display_value(project.get('target_url'))}",
            f"Target Type    : {_display_value(project.get('target_type'))}",
            f"Methodology    : {_display_value(project.get('methodology'))}",
            f"Generated At   : {time.strftime('%Y-%m-%d %H:%M:%S UTC')}",
            "-" * 80,
            "1. EXECUTIVE SUMMARY & METRICS",
            "-" * 80,
            f"Total Verified Vulnerabilities : {len(vulnerabilities)}",
            f"Peak CVSS Score                : {peak_cvss} / 10.0",
            f"OWASP ASVS L1 Compliance       : {asvs_txt}",
            f"CIS Controls v8 Compliance     : {cis_txt}",
            "-" * 80,
            "2. DETAILED FINDINGS BREAKDOWN",
            "-" * 80,
        ]

        if not vulnerabilities:
            lines.append("No vulnerability records are available for this project.")
        else:
            for idx, v in enumerate(vulnerabilities):
                lines.extend([
                    f"[{idx+1:02d}] {_display_value(v.get('vuln_code'))} - {_display_value(v.get('title'))}",
                    f"     Severity    : {_display_value(v.get('severity'))} (CVSS {_display_value(_number_or_none(v.get('cvss_score')))})",
                    f"     CWE / CVE   : {_display_value(v.get('cwe_id'))} / {_display_value(v.get('cve_id'))}",
                    f"     OWASP Cat   : {_display_value(v.get('owasp_category'))}",
                    f"     Target URI  : {_display_value(v.get('target_endpoint') or v.get('affected_url') or project.get('target_url'))}",
                    f"     Description : {_display_value(v.get('description'))}",
                    f"     PoC Evidence: {_display_value(v.get('poc_evidence'))}",
                    f"     Remediation : {_display_value(v.get('remediation_roadmap'))}",
                    ""
                ])

        lines.extend([
            "=" * 80,
            "End of Report - Baseera Sec Cognitive Security Engine",
            "=" * 80
        ])
        return "\n".join(lines)
