"""
Baseera Sec - Deep Session & Token Security Auditor
المرحلة 3: فحص تفاصيل الكوكيز والجلسات والـ JWT والرموز الحساسة
مع فلترة دقيقة لموازنات الأحمال ومنع الإنذارات الكاذبة (False-Positive Guard)
"""
import re
import json
import base64
from typing import Dict, List, Any
from core.engine.models import ReconFinding

class SessionAuditor:
    # قائمة كوكيز موازنات الأحمال والشبكات السحابية (ليست جلسات مستخدمين ولا تمثل خطورة سرقة جلسة)
    INFRASTRUCTURE_COOKIES = {
        "awsalb", "awsalbcors", "__cf_bm", "__cfruid", "cf_clearance", 
        "cf_ob_info", "cf_use_ob", "arrafinity", "arrafinitysamesite", 
        "incap_ses", "visid_incap", "bigipserver", "_ga", "_gid", "_gat", 
        "gid", "gat", "__utma", "__utmb", "__utmc", "__utmz", "optanonconsent"
    }

    # أنماط كوكيز جلسات المستخدم الحساسة
    SENSITIVE_SESSION_PATTERNS = [
        r"(?i)sess", r"(?i)auth", r"(?i)token", r"(?i)jwt", r"(?i)id", 
        r"(?i)login", r"(?i)phpsessid", r"(?i)jsessionid", r"(?i)aspsessionid",
        r"(?i)connect\.sid", r"(?i)laravel_session", r"(?i)remember"
    ]

    @classmethod
    def audit_cookies(cls, set_cookie_headers: List[str]) -> List[ReconFinding]:
        findings = []
        audited_cookie_names = set()

        for cookie_str in set_cookie_headers:
            cookie_parts = [p.strip() for p in cookie_str.split(";")]
            cookie_name = cookie_parts[0].split("=")[0] if cookie_parts else "UnknownCookie"
            cookie_name_lower = cookie_name.lower().strip()

            if cookie_name_lower in audited_cookie_names:
                continue
            audited_cookie_names.add(cookie_name_lower)

            # تجاهل كوكيز موازنات الأحمال السحابية والـ CDN لمنع الإنذارات الكاذبة
            if cookie_name_lower in cls.INFRASTRUCTURE_COOKIES or any(cookie_name_lower.startswith(ic) for ic in ["_cf", "awsalb", "_ga"]):
                continue

            parts_lower = [p.lower() for p in cookie_parts]
            has_httponly = "httponly" in parts_lower
            has_secure = "secure" in parts_lower
            has_samesite = any("samesite" in p for p in parts_lower)

            is_sensitive_session = any(re.search(pat, cookie_name_lower) for pat in cls.SENSITIVE_SESSION_PATTERNS)

            if not has_httponly:
                findings.append(ReconFinding(
                    category="cookies",
                    title=f"غياب سمة HttpOnly عن كوكيز الجلسة (Missing HttpOnly Flag): {cookie_name}",
                    description=f"ملف تعريف ارتباط الجلسة '{cookie_name}' يفتقر إلى سمة HttpOnly. هذا يسمح لأي سكريبت عبر XSS بقراءة معرف الجلسة بالكامل وسرقة حساب المستخدم.",
                    evidence=cookie_str,
                    risk_indicator="high" if is_sensitive_session else "medium"
                ))

            if not has_secure:
                findings.append(ReconFinding(
                    category="cookies",
                    title=f"غياب سمة Secure عن كوكيز الجلسة (Missing Secure Flag): {cookie_name}",
                    description=f"ملف تعريف ارتباط الجلسة '{cookie_name}' يفتقر إلى سمة Secure، مما يسمح بإرسال الكوكي عبر بروتوكول HTTP غير المشفر وتعريضه للتنصت (Network Sniffing).",
                    evidence=cookie_str,
                    risk_indicator="medium" if is_sensitive_session else "low"
                ))

            if not has_samesite:
                findings.append(ReconFinding(
                    category="cookies",
                    title=f"غياب سمة SameSite عن كوكيز الجلسة (Missing SameSite Flag): {cookie_name}",
                    description=f"ملف تعريف ارتباط الجلسة '{cookie_name}' يفتقر إلى سمة SameSite (SameSite=Lax/Strict)، مما يعرض المستخدم لهجمات تزوير الطلبات عبر المواقع (CSRF).",
                    evidence=cookie_str,
                    risk_indicator="low" if not is_sensitive_session else "medium"
                ))

        return findings

    @classmethod
    def audit_tokens(cls, url: str, headers: Dict[str, str], body_text: str) -> List[ReconFinding]:
        findings = []

        # 1. البحث عن تسريب توكنز في روابط الـ URL (Tokens in URL Query)
        token_in_url = re.findall(r'[?&](?:token|access_token|auth|jwt|api_key)=([a-zA-Z0-9_\-\.]+)', url, re.I)
        if token_in_url:
            findings.append(ReconFinding(
                category="tokens",
                title="تسريب رمز المصادقة داخل رابط الـ URL (Token Leaked in Query Parameter)",
                description="يؤدي لتخزين التوكن في سجلات الخادم (Server Logs)، وتاريخ المتصفح، وترويسة Referer.",
                evidence=f"Extracted token in query: {token_in_url[0][:10]}... [REDACTED]",
                risk_indicator="high"
            ))

        # 2. كشف وتحليل بنية JWT Tokens (في الترويسات أو نصوص الرد)
        jwt_matches = re.findall(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', body_text)
        auth_header = headers.get("authorization", "") or headers.get("Authorization", "")
        if "Bearer " in auth_header:
            bearer_token = auth_header.split("Bearer ")[-1].strip()
            if bearer_token.startswith("eyJ"):
                jwt_matches.append(bearer_token)

        for raw_jwt in set(jwt_matches):
            try:
                parts = raw_jwt.split(".")
                if len(parts) == 3:
                    # فك تشفير هيدر الـ JWT
                    header_json = json.loads(base64.urlsafe_b64decode(parts[0] + "==").decode('utf-8', errors='ignore'))
                    # فحص إذا كانت خوارزمية التوقيع هي "none" الخطيرة
                    alg = header_json.get("alg", "").lower()
                    if alg == "none":
                        findings.append(ReconFinding(
                            category="tokens",
                            title="ثغرة توكن حرجة: خوارزمية توقيع غير مشفرة (JWT alg: none)",
                            description="التوكن لا يتم التحقق من توقيعه الرقمي مما يسمح لأي مهاجم بتعديل بيانات المستخدم وانتحال هوية المدير.",
                            evidence=f"JWT Header: {header_json}",
                            risk_indicator="high"
                        ))
            except Exception:
                pass

        return findings
