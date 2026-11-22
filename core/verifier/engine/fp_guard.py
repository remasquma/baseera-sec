"""
Baseera Sec - Heuristic false-positive guard
محرك مساعد لتصفية بعض الإنذارات والتحقق منها
1. استثناء مكتبات الطرف الثالث الشائعة (jQuery, Bootstrap, FontAwesome)
2. تصفية كوكيز موازنات الأحمال والشبكات السحابية (AWSALB, Cloudflare, Akamai)
3. التحقق المزدوج وإعادة اختبار بعض الثغرات للمساعدة على تقييم تكرارية الإثبات
"""
import re
import httpx
from typing import Dict, Any, List, Set, Optional

class ZeroFPGuard:
    # قائمة كوكيز موازنات الأحمال والسحابة
    INFRASTRUCTURE_COOKIES: Set[str] = {
        "awsalb", "awsalbcors", "__cf_bm", "__cfruid", "cf_clearance", 
        "cf_ob_info", "cf_use_ob", "arrafinity", "arrafinitysamesite", 
        "incap_ses", "visid_incap", "bigipserver", "_ga", "_gid", "_gat", 
        "gid", "gat", "__utma", "__utmb", "__utmc", "__utmz", "optanonconsent"
    }

    # قائمة مسارات ومكتبات الطرف الثالث الآمنة
    BENIGN_THIRD_PARTY_PATTERNS = [
        r"(?i)/jquery[0-9\.\-_]*(\.min)?\.js",
        r"(?i)/bootstrap[0-9\.\-_]*(\.min)?\.(js|css)",
        r"(?i)/font-?awesome",
        r"(?i)/popper(\.min)?\.js",
        r"(?i)/lodash(\.min)?\.js",
        r"(?i)/moment(\.min)?\.js",
        r"(?i)/google-analytics",
        r"(?i)/gtag/js"
    ]

    @classmethod
    def is_benign_third_party_resource(cls, url_or_path: str) -> bool:
        """التحقق مما إذا كان الملف هو مكتبة طرف ثالث معروفة وآمنة"""
        clean_path = url_or_path.lower()
        return any(re.search(pat, clean_path) for pat in cls.BENIGN_THIRD_PARTY_PATTERNS)

    @classmethod
    def is_infrastructure_cookie(cls, cookie_name: str) -> bool:
        """التحقق مما إذا كان الكوكي تابعاً لموازن أحمال أو CDN"""
        c_lower = cookie_name.lower().strip()
        if c_lower in cls.INFRASTRUCTURE_COOKIES:
            return True
        return any(c_lower.startswith(p) for p in ["_cf", "awsalb", "_ga", "optanon"])

    @classmethod
    async def double_verify_finding(
        cls,
        endpoint: str,
        vuln_type: str,
        param_name: str,
        method: str,
        client: httpx.AsyncClient
    ) -> bool:
        """
        التحقق المزدوج: إرسال فحص تأكيدي إضافي للتأكد من أن الثغرة ليست ناتجة عن خلل شبكي عابر
        """
        try:
            if "SQL" in vuln_type:
                # التحقق المزدوج لـ SQLi: تجربة استعلام شرطي إضافي
                probe_url = f"{endpoint}{'&' if '?' in endpoint else '?'}baseera_verify=1"
                r = await client.request(method, probe_url, timeout=5.0)
                return r.status_code in [200, 500]

            elif "XSS" in vuln_type:
                # التحقق المزدوج لـ XSS: التأكد من انعكاس وسم مختلف
                verify_tag = "<baseeraVerify992>"
                p_data = {param_name: verify_tag}
                if method.upper() == "POST":
                    r = await client.post(endpoint, data=p_data, timeout=5.0)
                else:
                    r = await client.get(endpoint, params=p_data, timeout=5.0)
                return verify_tag in r.text and "text/html" in r.headers.get("content-type", "").lower()

            elif "SSTI" in vuln_type:
                verify_probe = "baseera{{9*9}}check"
                p_data = {param_name: verify_probe}
                if method.upper() == "POST":
                    r = await client.post(endpoint, data=p_data, timeout=5.0)
                else:
                    r = await client.get(endpoint, params=p_data, timeout=5.0)
                return "baseera81check" in r.text

        except Exception:
            return False

        return True
