"""
Baseera Sec - Zero False Positive Verification Fortress (ZeroFPGuard)
محرك التحقق الفعلي الصارم واستبعاد كافة الإنذارات الكاذبة (100% Verified Findings)
المعايير المطبقة:
1. استبعاد تام لكافة مكتبات الطرف الثالث وحزم الـ JS والـ CDNs
2. التحقق الرياضي والمنطقي التكراري (Active PoC Verification) لكل ثغرة
3. اشتراط أدلة إثبات قطعية غير قابلة للتخمين (Non-heuristic, Fully Proven)
4. منع اعتبار أكواد 500 أو ترويسات REST القياسية كثغرات دون استغلال حقيقي
"""
import re
import uuid
import random
import time
import httpx
from bs4 import BeautifulSoup, Comment
from typing import Dict, Any, List, Set, Optional, Tuple
from urllib.parse import urlsplit, urlunsplit, urlencode, parse_qsl


class ZeroFPGuard:
    # قائمة كوكيز موازنات الأحمال والسحابة والتحليلات وتفضيلات الأجهزة
    INFRASTRUCTURE_COOKIES: Set[str] = {
        "awsalb", "awsalbcors", "__cf_bm", "__cfruid", "cf_clearance", 
        "cf_ob_info", "cf_use_ob", "arrafinity", "arrafinitysamesite", 
        "incap_ses", "visid_incap", "bigipserver", "_ga", "_gid", "_gat", 
        "gid", "gat", "__utma", "__utmb", "__utmc", "__utmz", "optanonconsent",
        "mid", "nid", "1p_jar", "aec", "datr", "sb", "wd", "dpr", "oo", "rur",
        "ig_did", "ig_nrcb", "fbp", "fr", "__secure-strp", "otz", "intercom-id"
    }

    # قائمة مسارات ومكتبات الطرف الثالث الآمنة والـ CDNs
    BENIGN_THIRD_PARTY_PATTERNS = [
        r"(?i)/jquery[0-9\.\-_]*(\.min)?\.js",
        r"(?i)/bootstrap[0-9\.\-_]*(\.min)?\.(js|css)",
        r"(?i)/font-?awesome",
        r"(?i)/popper(\.min)?\.js",
        r"(?i)/lodash(\.min)?\.js",
        r"(?i)/moment(\.min)?\.js",
        r"(?i)/google-analytics",
        r"(?i)/gtag/js",
        r"(?i)/react(\.production|\.development)?(\.min)?\.js",
        r"(?i)/react-dom(\.production|\.development)?(\.min)?\.js",
        r"(?i)/vue(\.runtime)?(\.min)?\.js",
        r"(?i)/angular(\.min)?\.js",
        r"(?i)/chunk-vendors",
        r"(?i)/webpack",
        r"(?i)/core-js",
        r"(?i)/axios(\.min)?\.js",
        r"(?i)/swiper",
        r"(?i)/slick",
        r"(?i)/highlight(\.min)?\.js",
        r"(?i)/chart(\.min)?\.js",
        r"(?i)cdnjs\.cloudflare\.com",
        r"(?i)cdn\.jsdelivr\.net",
        r"(?i)unpkg\.com",
        r"(?i)ajax\.googleapis\.com",
        r"(?i)/wp-includes/",
        r"(?i)/wp-content/plugins/"
    ]

    @classmethod
    def is_benign_third_party_resource(cls, url_or_path: str) -> bool:
        """التحقق مما إذا كان الملف هو مكتبة طرف ثالث معروفة وآمنة أو حزمة CDN"""
        clean_path = url_or_path.lower()
        return any(re.search(pat, clean_path) for pat in cls.BENIGN_THIRD_PARTY_PATTERNS)

    @classmethod
    def is_infrastructure_cookie(cls, cookie_name: str) -> bool:
        """التحقق مما إذا كان الكوكي تابعاً لموازن أحمال أو تحليلات أو CDN"""
        c_lower = cookie_name.lower().strip()
        if c_lower in cls.INFRASTRUCTURE_COOKIES:
            return True
        return any(c_lower.startswith(p) for p in ["_cf", "awsalb", "_ga", "optanon", "ig_"])

    @classmethod
    async def verify_sqli_error_suppression(
        cls,
        endpoint: str,
        param_name: str,
        method: str,
        current_val: str,
        client: httpx.AsyncClient,
        pattern: str
    ) -> bool:
        """
        التحقق الصارم من خطأ SQL:
        عند إرسال ' يحدث خطأ في بناء الجملة (Syntax Error).
        إذا قمنا بإرسال '' (اثنين من علامات الاقتباس للهروب / Escaping)، يجب أن يختفي الخطأ ويعود الخادم للعمل السليم!
        إذا ظل الخطأ موجوداً حتى مع ''، فهذا نص ثابت في الصفحة وليس حقن SQL حقيقي.
        """
        try:
            parsed = urlsplit(endpoint)
            base_endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
            orig_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            
            # تجربة إرسال علامتي اقتباس متتاليتين '' لإصلاح الجملة
            escaped_params = orig_params.copy()
            escaped_params[param_name] = f"{current_val}''"
            
            if method.upper() == "POST":
                resp_esc = await client.post(base_endpoint, data=escaped_params, timeout=5.0, follow_redirects=True)
            else:
                resp_esc = await client.get(f"{base_endpoint}?{urlencode(escaped_params)}", timeout=5.0, follow_redirects=True)
                
            # إذا اختفى خطأ الـ DBMS عند تصحيح الاقتباس، فهذا إثبات قطعي 100% أن الاستعلام قيد التنفيذ المباشر
            return not re.search(pattern, resp_esc.text)
        except Exception:
            return False

    @classmethod
    async def verify_xss_repeatable(
        cls,
        endpoint: str,
        param_name: str,
        method: str,
        client: httpx.AsyncClient
    ) -> bool:
        """
        التحقق المزدوج الصارم لـ XSS:
        إرسال وسم عشوائي فريد جديد تماماً، والتأكد من تصييره كعنصر DOM قابل للتنفيذ
        وليس كنص مشفر أو داخل تعليق أو حاوية غير قابلة للتنفيذ.
        """
        try:
            canary_id = f"bxss{uuid.uuid4().hex[:8]}"
            canary_tag = f"<{canary_id} id='poc_verify'>"
            
            parsed = urlsplit(endpoint)
            base_endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
            orig_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            test_params = orig_params.copy()
            test_params[param_name] = canary_tag

            if method.upper() == "POST":
                resp = await client.post(base_endpoint, data=test_params, timeout=5.0, follow_redirects=True)
            else:
                resp = await client.get(f"{base_endpoint}?{urlencode(test_params)}", timeout=5.0, follow_redirects=True)

            c_type = resp.headers.get("content-type", "").lower()
            if not any(t in c_type for t in ["text/html", "application/xhtml+xml"]):
                return False

            if f"&lt;{canary_id}" in resp.text:
                return False

            if canary_id in resp.text.lower():
                soup = BeautifulSoup(resp.text, "html.parser")
                matched = soup.find_all(canary_id)
                if matched:
                    for el in matched:
                        parent_name = el.parent.name.lower() if el.parent else ""
                        if parent_name in ("textarea", "title", "style", "noscript"):
                            return False
                    return True
            return False
        except Exception:
            return False

    @classmethod
    async def verify_ssti_dynamic(
        cls,
        endpoint: str,
        param_name: str,
        method: str,
        client: httpx.AsyncClient
    ) -> bool:
        """
        التحقق المزدوج لـ SSTI عبر عملية حسابية عشوائية ديناميكية:
        نولد رقمين عشوائيين (مثلاً 13 * 17 = 221)
        ونتحقق من أن محرك القوالب قام بحساب الناتج الدقيق.
        """
        try:
            n1 = random.randint(11, 29)
            n2 = random.randint(11, 29)
            expected_product = str(n1 * n2)
            canary_token = f"baseera{expected_product}sec"
            probe = f"baseera{{{{{n1}*{n2}}}}}sec"

            parsed = urlsplit(endpoint)
            base_endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
            orig_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            test_params = orig_params.copy()
            test_params[param_name] = probe

            if method.upper() == "POST":
                resp = await client.post(base_endpoint, data=test_params, timeout=5.0, follow_redirects=True)
            else:
                resp = await client.get(f"{base_endpoint}?{urlencode(test_params)}", timeout=5.0, follow_redirects=True)

            return canary_token in resp.text
        except Exception:
            return False

    @classmethod
    async def verify_cmdi_dynamic(
        cls,
        endpoint: str,
        param_name: str,
        method: str,
        client: httpx.AsyncClient
    ) -> bool:
        """
        التحقق المزدوج لحقن أوامر النظام عبر عملية جمع ديناميكية بالأمر expr:
        مثلاً: expr 31400 + 15200 = 46600
        """
        try:
            n1 = random.randint(10000, 40000)
            n2 = random.randint(10000, 40000)
            expected_sum = str(n1 + n2)
            probe = f"; expr {n1} + {n2}"

            parsed = urlsplit(endpoint)
            base_endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
            orig_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
            test_params = orig_params.copy()
            test_params[param_name] = probe

            if method.upper() == "POST":
                resp = await client.post(base_endpoint, data=test_params, timeout=5.0, follow_redirects=True)
            else:
                resp = await client.get(f"{base_endpoint}?{urlencode(test_params)}", timeout=5.0, follow_redirects=True)

            # الشرط: ظهور الناتج الحسابي الدقيق وعدم وجود الأمر كصدى نصي بحت
            if expected_sum in resp.text and probe not in resp.text:
                return True
            return False
        except Exception:
            return False

    @classmethod
    def is_true_stack_trace(cls, text: str, baseline_text: str = "") -> Tuple[bool, str]:
        """
        التحقق الصارم من تسريب الـ Stack Trace وأخطاء الخادم (CWE-209):
        يشترط وجود إطارات استدعاء فعلية بمسارات الملفات وأرقام الأسطر،
        وليس مجرد كود 500 أو كلمة 'error' عادية.
        """
        clean_text = text
        if baseline_text:
            # تجاهل أي نص موجود مسبقاً في خط الأساس
            clean_text = text.replace(baseline_text, "")

        text_lower = clean_text.lower()

        # نماذج الـ Stack Trace الحقيقية
        patterns = [
            (r"(?i)Traceback\s*\(most\s*recent\s*call\s*last\):[\s\S]*?File\s*[\"'].*?[\"'],\s*line\s*\d+", "Python Exception Stack Trace"),
            (r"(?i)\b(?:java\.lang\.|javax\.servlet\.|org\.apache\.)[a-zA-Z0-9_.]*Exception(?::[\s\S]*?\bat\s+[a-zA-Z0-9_$.]+\([a-zA-Z0-9_]+\.java:\d+\))", "Java Runtime Stack Trace"),
            (r"(?i)Fatal error:\s*Uncaught\s*.*?in\s*/[a-zA-Z0-9_\-\./]+\.php\s*on\s*line\s*\d+", "PHP Fatal Runtime Exception"),
            (r"(?i)Microsoft\.AspNetCore\..*?Exception:\s*[\s\S]*?at\s+[a-zA-Z0-9_.]+\.cs:line\s*\d+", ".NET Core Runtime Exception"),
            (r"(?i)node:internal/process/execution:\d+[\s\S]*?at\s+async\s+", "Node.js Unhandled Runtime Exception")
        ]

        for pat, desc in patterns:
            m = re.search(pat, clean_text)
            if m:
                snippet = m.group(0)[:180].strip().replace("\n", " ")
                return True, f"{desc}: {snippet}"

        return False, ""
