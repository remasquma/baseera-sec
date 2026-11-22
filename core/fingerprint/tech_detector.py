"""
Baseera Sec - Cognitive Tech & Fingerprint Detector
المرحلة 1: كشف الهوية والتقنيات والاستدلال الاستباقي لنواقل الهجوم
"""
import re
from typing import Dict
from bs4 import BeautifulSoup
from core.engine.models import TechFingerprint

class TechDetector:
    @staticmethod
    def analyze(headers: Dict[str, str], html_content: str, url: str) -> TechFingerprint:
        fp = TechFingerprint()
        headers_lower = {k.lower(): v for k, v in headers.items()}
        soup = BeautifulSoup(html_content, "html.parser")
        
        # 1. كشف خادم الويب
        server = headers_lower.get("server", "")
        if "nginx" in server.lower():
            fp.server = "Nginx"
        elif "apache" in server.lower():
            fp.server = "Apache"
        elif "cloudflare" in server.lower():
            fp.server = "Cloudflare Edge"
            fp.waf_detected = True
        else:
            fp.server = server if server else "Undisclosed Server"

        # 2. كشف أطر العمل واللغات
        powered_by = headers_lower.get("x-powered-by", "")
        if "php" in powered_by.lower() or ".php" in url:
            fp.language = "PHP"
        elif "express" in powered_by.lower() or "node" in powered_by.lower():
            fp.language = "Node.js (JavaScript)"
            fp.framework = "Express.js"
        elif "django" in powered_by.lower() or "csrftoken" in headers_lower.get("set-cookie", ""):
            fp.language = "Python"
            fp.framework = "Django"
        elif "laravel" in headers_lower.get("set-cookie", "").lower() or "xsrf-token" in headers_lower.get("set-cookie", "").lower():
            fp.language = "PHP"
            fp.framework = "Laravel"

        # 3. فحص محتوى الـ HTML (Meta tags & scripts)
        scripts = " ".join([s.get("src", "") for s in soup.find_all("script")])
        if "wp-content" in html_content or "wp-includes" in html_content:
            fp.cms = "WordPress"
            fp.framework = "WordPress Engine"
            fp.language = "PHP"
        elif "react" in scripts or "react" in html_content.lower():
            fp.framework = (fp.framework + " + React SPA") if fp.framework else "React SPA"

        # 4. استدلال نوع الموقع (Inferred Site Type)
        text_content = soup.get_text().lower()
        if any(w in text_content for w in ["cart", "checkout", "price", "سلة", "شراء", "دفع", "store"]):
            fp.inferred_site_type = "E-Commerce Platform (متجر إلكتروني)"
            fp.common_attack_vectors = [
                "Payment Logic Tampering",
                "Broken Object Level Authorization (BOLA)",
                "Session Fixation & Cart Manipulation",
                "Coupon/Pricing Race Conditions"
            ]
        elif any(w in text_content for w in ["admin", "dashboard", "لوحة تحكم", "تسجيل الدخول", "login"]):
            fp.inferred_site_type = "Admin / Corporate Portal (لوحة تحكم/بوابة إدارية)"
            fp.common_attack_vectors = [
                "Credential Stuffing & Weak MFA",
                "Session Hijacking & Missing HttpOnly",
                "Privilege Escalation",
                "Server-Side Request Forgery (SSRF)"
            ]
        elif "/api/" in url or "swagger" in html_content.lower():
            fp.inferred_site_type = "REST API Gateway (واجهة برمجة تطبيقات)"
            fp.common_attack_vectors = [
                "Broken Authentication & JWT Flaws",
                "Mass Assignment",
                "Excessive Data Exposure",
                "Unrestricted Resource Consumption"
            ]
        else:
            fp.inferred_site_type = "Corporate Web Application"
            fp.common_attack_vectors = [
                "Security Misconfigurations",
                "Missing Defensive Headers",
                "Reflected Input Injections",
                "Information Disclosure"
            ]

        return fp
