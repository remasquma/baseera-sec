"""
Baseera Sec - Security Headers & Misconfigurations Auditor
Audits defensive headers with context-awareness (HTTPS status, browser policies, CORS).
Distinguishes informational hardening recommendations from exploitable misconfigurations.
"""
from typing import Dict, List, Optional
from core.engine.models import ReconFinding


class HeaderAuditor:
    @classmethod
    def audit(cls, headers: Dict[str, str], url: str = "") -> List[ReconFinding]:
        findings = []
        headers_lower = {k.lower(): v for k, v in headers.items()}
        is_https = url.lower().startswith("https://")

        # 1. Strict-Transport-Security (HSTS)
        if "strict-transport-security" not in headers_lower:
            if is_https:
                findings.append(ReconFinding(
                    category="headers",
                    title="ترويسة HSTS غير مفعلة (Strict-Transport-Security Missing)",
                    description="الخادم يعمل بـ HTTPS لكنه لا يفرض ترويسة HSTS لمنع هجمات التحويل القسري إلى HTTP (SSL Stripping).",
                    evidence="Header 'Strict-Transport-Security' is absent in HTTPS response.",
                    risk_indicator="medium"
                ))
            elif url.lower().startswith("http://"):
                findings.append(ReconFinding(
                    category="headers",
                    title="الموقع يعمل عبر HTTP غير مشفر (Insecure Plaintext HTTP)",
                    description="الموقع يعمل عبر بروتوكول HTTP غير المشفر مما يعرض حركة البيانات للتنصت.",
                    evidence=f"Endpoint: {url or 'HTTP service'}",
                    risk_indicator="medium"
                ))

        # 2. Content-Security-Policy (CSP)
        if "content-security-policy" not in headers_lower:
            findings.append(ReconFinding(
                category="headers",
                title="سياسة أمان المحتوى غير مفعلة (Content-Security-Policy Missing)",
                description="يوصى بتفعيل ترويسة CSP كخط دفاع إضافي (Defense-in-Depth) لتقييد مصادر السكريبتات.",
                evidence="Header 'Content-Security-Policy' is absent.",
                risk_indicator="medium"
            ))

        # 3. X-Frame-Options / Frame-Ancestors
        has_xfo = "x-frame-options" in headers_lower
        has_frame_ancestors = "frame-ancestors" in headers_lower.get("content-security-policy", "")
        if not has_xfo and not has_frame_ancestors:
            findings.append(ReconFinding(
                category="headers",
                title="حماية تضمين الإطارات مفقودة (X-Frame-Options Missing)",
                description="غياب X-Frame-Options أو CSP frame-ancestors قد يسمح بتضمين واجهة الموقع في إطارات iframes خارجية.",
                evidence="Neither 'X-Frame-Options' nor CSP 'frame-ancestors' present.",
                risk_indicator="medium"
            ))

        # 4. X-Content-Type-Options
        if "x-content-type-options" not in headers_lower:
            findings.append(ReconFinding(
                category="headers",
                title="ترويسة X-Content-Type-Options مفقودة (MIME Sniffing Risk)",
                description="يوصى بإضافة 'X-Content-Type-Options: nosniff' لمنع المتصفح من تخمين نوع المحتوى.",
                evidence="Header 'X-Content-Type-Options' is absent.",
                risk_indicator="low"
            ))

        # 5. Server Information Disclosure
        if "server" in headers_lower:
            server_val = headers_lower["server"]
            if any(char.isdigit() for char in server_val):
                findings.append(ReconFinding(
                    category="headers",
                    title="تسريب إصدار الخادم (Server Banner Disclosure)",
                    description="الخادم يكشف إصداره الدقيق مما يسهل على المهاجمين استهداف ثغرات الإصدار المحددة.",
                    evidence=f"Server: {server_val}",
                    risk_indicator="low"
                ))

        # 6. Insecure CORS Configuration
        acao = headers_lower.get("access-control-allow-origin", "")
        acac = headers_lower.get("access-control-allow-credentials", "")
        if acao == "*" and acac.lower() == "true":
            findings.append(ReconFinding(
                category="headers",
                title="إعدادات CORS غير متوافقة (Wildcard Origin with Credentials)",
                description="إعداد متناقض في الخادم يجمع بين Origin: * و Allow-Credentials: true (مرفوض من المتصفحات الحديثة).",
                evidence="Access-Control-Allow-Origin: * with Allow-Credentials: true",
                risk_indicator="medium"
            ))

        return findings
