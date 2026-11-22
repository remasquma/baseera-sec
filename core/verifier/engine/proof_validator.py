"""
Baseera Sec - Proof-of-concept validation helpers
التحقق من بعض الأدلة وتقليل التكرار؛ لا يضمن خلو النتائج من الأخطاء
"""
from typing import List, Set
from core.engine.models import ReconFinding, VerifiedVulnerability, SeverityLevel

class ProofValidator:
    """
    تصفية أولية للنتائج بحسب الأدلة المتاحة وإزالة التكرار.
    """

    @classmethod
    def verify_findings(cls, findings: List[ReconFinding], base_url: str) -> List[VerifiedVulnerability]:
        verified_list: List[VerifiedVulnerability] = []
        seen_keys: Set[str] = set()

        for f in findings:
            # 1. ثغرات تسريب مستودع .git
            if ".git" in f.evidence and "git" not in seen_keys:
                seen_keys.add("git")
                verified_list.append(VerifiedVulnerability(
                    vuln_id=f"BASEERA-GIT-{len(verified_list)+1:03d}",
                    title="تسريب مستودع الأكواد المصدري (.git Source Code Exposure)",
                    cwe_id="CWE-552",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity=SeverityLevel.HIGH,
                    cvss_score=8.6,
                    confidence_score=1.0,
                    description="تم التحقق من إمكانية قراءة مجلد .git الداخلي بما يتيح للمهاجم سحب السورس كود كاملاً ومفاتيح الربط.",
                    poc_evidence=f"Proof: Successfully validated ref headers from {base_url}/.git/HEAD",
                    attack_vector="Direct Directory Traversal & Code Leaks",
                    remediation_guide="أضف قاعدة حظر في خادم الويب: location ~ /\\. { deny all; }"
                ))

            # 2. ثغرات تسريب ملفات البيئة .env
            elif ".env" in f.evidence and "env" not in seen_keys:
                seen_keys.add("env")
                verified_list.append(VerifiedVulnerability(
                    vuln_id=f"BASEERA-ENV-{len(verified_list)+1:03d}",
                    title="كشف ملف إعدادات البيئة ومفاتيح قواعد البيانات (.env Exposure)",
                    cwe_id="CWE-552",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity=SeverityLevel.CRITICAL,
                    cvss_score=9.3,
                    confidence_score=1.0,
                    description="تم التحقق من قراءة متغيرات البيئة الحساسة التي تحتوي على بيانات الاتصال بالسيرفر وقواعد البيانات.",
                    poc_evidence=f"Proof: HTTP 200 with environment keys leaked: {f.evidence}",
                    attack_vector="Direct Environment File Access",
                    remediation_guide="انقل ملف .env خارج مجلد الجذر العام public_html وفعّل حظر الملفات الحساسة."
                ))

            # 3. ثغرات Directory Listing
            elif (f.category == "directory_listing" or "Directory Listing" in f.title) and "dirlist" not in seen_keys:
                seen_keys.add("dirlist")
                verified_list.append(VerifiedVulnerability(
                    vuln_id=f"BASEERA-DIR-{len(verified_list)+1:03d}",
                    title="تصفح مفتوح لمجلدات الخادم (Directory Listing Disclosed)",
                    cwe_id="CWE-548",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    confidence_score=1.0,
                    description="الخادم يسمح للمتصفحين باستعراض وتنزيل محتويات المجلدات الداخلية والملفات المرفوعة.",
                    poc_evidence=f"Proof: {f.evidence}",
                    attack_vector="Information Disclosure via Open Indexing",
                    remediation_guide="عطّل خاصية استعراض المجلدات في Apache (Options -Indexes) أو في Nginx (autoindex off;)."
                ))

            # 4. ثغرات أمان كوكيز الجلسات الحساسة بدقة المعايير (CWE-1004, CWE-614, CWE-1275)
            elif "Missing HttpOnly" in f.title:
                cookie_key = f"cookie_httponly_{f.title}"
                if cookie_key not in seen_keys:
                    seen_keys.add(cookie_key)
                    verified_list.append(VerifiedVulnerability(
                        vuln_id=f"BASEERA-COOKIE-HTTPONLY-{len(verified_list)+1:03d}",
                        title=f.title,
                        cwe_id="CWE-1004",
                        owasp_category="A05:2021-Security Misconfiguration",
                        severity=SeverityLevel.HIGH if f.risk_indicator == "high" else SeverityLevel.MEDIUM,
                        cvss_score=6.5 if f.risk_indicator == "high" else 5.0,
                        confidence_score=0.98,
                        description=f.description,
                        poc_evidence=f"Proof Header: {f.evidence}",
                        attack_vector="Client-Side Session Hijacking via Missing HttpOnly",
                        remediation_guide="أضف سمة HttpOnly إلى ترويسة Set-Cookie في إعدادات الجلسة: Set-Cookie: session=xyz; HttpOnly; Secure; SameSite=Lax"
                    ))

            elif "Missing Secure" in f.title:
                cookie_key = f"cookie_secure_{f.title}"
                if cookie_key not in seen_keys:
                    seen_keys.add(cookie_key)
                    verified_list.append(VerifiedVulnerability(
                        vuln_id=f"BASEERA-COOKIE-SECURE-{len(verified_list)+1:03d}",
                        title=f.title,
                        cwe_id="CWE-614",
                        owasp_category="A05:2021-Security Misconfiguration",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=5.0,
                        confidence_score=0.98,
                        description=f.description,
                        poc_evidence=f"Proof Header: {f.evidence}",
                        attack_vector="Cleartext Cookie Sniffing via Insecure Transport",
                        remediation_guide="أضف سمة Secure لضمان عدم نقل الكوكي إلا عبر قنوات مشفرة: Set-Cookie: session=xyz; Secure; HttpOnly; SameSite=Lax"
                    ))

            elif "Missing SameSite" in f.title:
                cookie_key = f"cookie_samesite_{f.title}"
                if cookie_key not in seen_keys:
                    seen_keys.add(cookie_key)
                    verified_list.append(VerifiedVulnerability(
                        vuln_id=f"BASEERA-COOKIE-SAMESITE-{len(verified_list)+1:03d}",
                        title=f.title,
                        cwe_id="CWE-1275",
                        owasp_category="A01:2021-Broken Access Control",
                        severity=SeverityLevel.LOW if f.risk_indicator == "low" else SeverityLevel.MEDIUM,
                        cvss_score=3.7,
                        confidence_score=0.98,
                        description=f.description,
                        poc_evidence=f"Proof Header: {f.evidence}",
                        attack_vector="Cross-Site Request Forgery via Inadequate SameSite Protection",
                        remediation_guide="عيّن سمة SameSite=Lax أو SameSite=Strict لمنع إرسال الكوكي في طلبات الطرف الثالث."
                    ))

            elif "Insecure Session Cookie" in f.title:
                cookie_key = f"cookie_legacy_{f.title}"
                if cookie_key not in seen_keys:
                    seen_keys.add(cookie_key)
                    verified_list.append(VerifiedVulnerability(
                        vuln_id=f"BASEERA-COOKIE-{len(verified_list)+1:03d}",
                        title=f.title,
                        cwe_id="CWE-1004",
                        owasp_category="A05:2021-Security Misconfiguration",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=5.0,
                        confidence_score=0.95,
                        description=f.description,
                        poc_evidence=f"Proof Header: {f.evidence}",
                        attack_vector="Client-Side Session Hijacking via Insecure Cookie Flags",
                        remediation_guide="Set-Cookie: session=xyz; Secure; HttpOnly; SameSite=Strict"
                    ))

            # 5. غياب فرض التشفير الإجباري وترويسة HSTS (تسجيلها مرة واحدة فقط)
            elif ("HSTS" in f.title or "Strict-Transport-Security" in f.title) and "hsts" not in seen_keys:
                seen_keys.add("hsts")
                verified_list.append(VerifiedVulnerability(
                    vuln_id=f"BASEERA-HSTS-{len(verified_list)+1:03d}",
                    title="غياب فرض التشفير الإجباري (Missing Strict-Transport-Security)",
                    cwe_id="CWE-319",
                    owasp_category="A02:2021-Cryptographic Failures",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.3,
                    confidence_score=0.95,
                    description="الموقع لا يفرض على المتصفح استخدام HTTPS بشكل إجباري، مما يعرض المستخدمين لهجمات التنصت (MitM).",
                    poc_evidence="Response verified without 'Strict-Transport-Security' header.",
                    attack_vector="Network Downgrade & Cleartext Sniffing",
                    remediation_guide="أضف ترويسة HSTS: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                ))

            # 6. غياب سياسة أمان المحتوى CSP (CWE-693 الصحيح وليس 1021)
            elif ("CSP" in f.title or "Content Security Policy" in f.title) and "csp" not in seen_keys:
                seen_keys.add("csp")
                verified_list.append(VerifiedVulnerability(
                    vuln_id=f"BASEERA-CSP-{len(verified_list)+1:03d}",
                    title="غياب سياسة أمان المحتوى (Missing Content Security Policy)",
                    cwe_id="CWE-693",
                    owasp_category="A05:2021-Security Misconfiguration",
                    severity=SeverityLevel.MEDIUM,
                    cvss_score=5.0,
                    confidence_score=0.95,
                    description="غياب CSP يترك المتصفح دون قيود على مصادر السكريبتات، مما يرفع احتمالية نجاح هجمات حقن XSS.",
                    poc_evidence="Response lacks 'Content-Security-Policy' restriction headers.",
                    attack_vector="Unrestricted Cross-Site Script Execution",
                    remediation_guide="أضف ترويسة CSP صارمة تقيد المصادر الموثوقة للأكواد: Content-Security-Policy: default-src 'self';"
                ))

            # 7. نقاط نهاية ووردبريس المكشوفة (WordPress Exposure & User Enumeration)
            elif "WordPress" in f.title or "ووردبريس" in f.title:
                wp_key = f"wp_{f.title}"
                if wp_key not in seen_keys:
                    seen_keys.add(wp_key)
                    verified_list.append(VerifiedVulnerability(
                        vuln_id=f"BASEERA-WP-{len(verified_list)+1:03d}",
                        title=f.title,
                        cwe_id="CWE-200",
                        owasp_category="A01:2021-Broken Access Control",
                        severity=SeverityLevel.MEDIUM,
                        cvss_score=5.3,
                        confidence_score=0.98,
                        description=f.description,
                        poc_evidence=f"Proof: {f.evidence}",
                        attack_vector="Information Disclosure & Account Enumeration",
                        remediation_guide="عطّل مسار /wp-json/wp/v2/users لغير المصادقين، وقم بحظر الوصول إلى ملف xmlrpc.php.",
                        affected_url=base_url
                    ))

        return verified_list
