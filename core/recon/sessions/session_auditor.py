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
    # كوكيز الحماية من تزوير الطلبات (CSRF Tokens) - مصممة عمداً لتكون مقروءة بالجافاسكريبت لحماية الطلبات
    # لذلك لا يجوز نهائياً تصنيف غياب HttpOnly عنها كثغرة أمنية (Double Submit Cookie Pattern)
    CSRF_COOKIE_NAMES = {
        "csrftoken", "csrf_token", "_csrf", "xsrf-token", "x-csrf-token", 
        "antiforgery", "__requestverificationtoken", "csrftoken_v2", "csrf", "_xsrf"
    }

    # كوكيز موازنات الأحمال والشبكات السحابية والتحليلات وتفضيلات الأجهزة (ليست جلسات مصادقة مستخدمين)
    INFRASTRUCTURE_AND_ANALYTICS_COOKIES = {
        "awsalb", "awsalbcors", "__cf_bm", "__cfruid", "cf_clearance", 
        "cf_ob_info", "cf_use_ob", "arrafinity", "arrafinitysamesite", 
        "incap_ses", "visid_incap", "bigipserver", "_ga", "_gid", "_gat", 
        "gid", "gat", "__utma", "__utmb", "__utmc", "__utmz", "optanonconsent",
        "mid", "nid", "1p_jar", "aec", "datr", "sb", "wd", "dpr", "oo", "rur",
        "ig_did", "ig_nrcb", "fbp", "fr", "__secure-strp", "otz", "intercom-id"
    }

    # أسماء وأنماط كوكيز جلسات الدخول الحقيقية فقط (True Authentication Session Cookies)
    TRUE_SESSION_COOKIE_EXACT = {
        "sessionid", "session_id", "phpsessid", "jsessionid", "aspsessionid",
        "connect.sid", "laravel_session", "auth_token", "access_token", "jwt", 
        "user_session", "sid", "identity", "remember_token"
    }

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

            # 1. استبعاد كوكيز الـ CSRF من فحص HttpOnly (لأنها مصممة لتقرأ عبر كود الفرونت إند)
            is_csrf_cookie = (
                cookie_name_lower in cls.CSRF_COOKIE_NAMES 
                or cookie_name_lower.endswith("csrf") 
                or cookie_name_lower.endswith("csrftoken")
                or cookie_name_lower.endswith("xsrf-token")
            )

            # 2. استبعاد كوكيز التحليلات وتوجيه السيرفرات والأجهزة
            is_infra_or_analytics = (
                cookie_name_lower in cls.INFRASTRUCTURE_AND_ANALYTICS_COOKIES
                or any(cookie_name_lower.startswith(p) for p in ["_ga", "_cf", "awsalb", "ig_"])
            )

            if is_infra_or_analytics:
                continue

            parts_lower = [p.lower() for p in cookie_parts]
            has_httponly = "httponly" in parts_lower
            has_secure = "secure" in parts_lower
            has_samesite = any("samesite" in p for p in parts_lower)

            # التحقق الدقيق: هل الكوكي يمثل جلسة دخول مستخدم حقيقية؟
            is_true_session = (
                cookie_name_lower in cls.TRUE_SESSION_COOKIE_EXACT
                or (cookie_name_lower.startswith("session") and not is_csrf_cookie)
                or (cookie_name_lower.startswith("sess_") and not is_csrf_cookie)
                or (cookie_name_lower.startswith("auth_") and not is_csrf_cookie)
            )

            # لا يُطلب HttpOnly إلا على كوكيز الجلسات الحقيقية فقط
            if is_true_session and not is_csrf_cookie and not has_httponly:
                findings.append(ReconFinding(
                    category="cookies",
                    title=f"غياب سمة HttpOnly عن كوكيز الجلسة (Missing HttpOnly Flag): {cookie_name}",
                    description=f"ملف تعريف ارتباط الجلسة الحساس '{cookie_name}' يفتقر إلى سمة HttpOnly. يوصى بإضافتها لمنع السكريبتات الخبيثة من قراءته.",
                    evidence=cookie_str,
                    risk_indicator="high"
                ))

            # كوكيز الجلسات الحقيقية أو كوكيز الـ CSRF إذا نقلت دون Secure
            if (is_true_session or is_csrf_cookie) and not has_secure:
                findings.append(ReconFinding(
                    category="cookies",
                    title=f"غياب سمة Secure عن كوكيز الجلسة (Missing Secure Flag): {cookie_name}",
                    description=f"ملف تعريف ارتباط الجلسة '{cookie_name}' يفتقر إلى سمة Secure، مما يسمح بإرسال الكوكي عبر بروتوكول HTTP غير المشفر وتعريضه للتنصت.",
                    evidence=cookie_str,
                    risk_indicator="medium"
                ))

            # فحص SameSite لجلسات الدخول الحقيقية فقط لمنع التضخيم والإنذارات الكاذبة
            if is_true_session and not is_csrf_cookie and not has_samesite:
                findings.append(ReconFinding(
                    category="cookies",
                    title=f"غياب سمة SameSite عن كوكيز الجلسة (Missing SameSite Flag): {cookie_name}",
                    description=f"ملف تعريف ارتباط الجلسة '{cookie_name}' يفتقر إلى سمة SameSite (SameSite=Lax/Strict)، مما يعرضه للطلبات عبر المواقع.",
                    evidence=cookie_str,
                    risk_indicator="low"
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
