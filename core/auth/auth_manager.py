"""
Baseera Sec - Enterprise Authenticated Scanning & Session Lifecycle Manager
يدعم الفحص بعد تسجيل الدخول عبر:
1. تمرير كوكيز الجلسة (Session Cookies)
2. توكنز الـ JWT والـ Bearer Tokens
3. مفاتيح الـ API المخصصة والترويسات (Custom Headers & API Keys)
4. تسجيل الدخول الآلي عبر نماذج الدخول (Automated Form Login)
5. كشف انتهاء الجلسة التلقائي وإعادة المصادقة اللحظية (Session Expiry Detection & Auto-Reauth)
"""
import re
import time
import httpx
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

@dataclass
class AuthConfig:
    auth_type: str = "none" # "none", "cookie", "bearer", "api_key", "form_login"
    raw_cookie: str = ""
    bearer_token: str = ""
    api_key_header: str = "X-API-Key"
    api_key_value: str = ""
    custom_headers: Dict[str, str] = field(default_factory=dict)
    login_url: str = ""
    username_field: str = "username"
    password_field: str = "password"
    username_val: str = ""
    password_val: str = ""
    login_method: str = "POST"
    auto_reauth: bool = True

class AuthManager:
    SESSION_EXPIRED_INDICATORS = [
        r"(?i)session expired",
        r"(?i)please log in",
        r"(?i)login required",
        r"(?i)unauthorized",
        r"(?i)invalid token",
        r"(?i)token expired",
        r"(?i)jwt expired",
        r"(?i)access denied",
        r"(?i)sign in to continue"
    ]

    def __init__(self, config: Optional[AuthConfig] = None):
        self.config = config or AuthConfig()
        self.active_headers: Dict[str, str] = {}
        self.active_cookies: Dict[str, str] = {}
        self.is_authenticated: bool = False
        self.last_login_time: float = 0
        self._initialize_session()

    def _initialize_session(self):
        """تهيئة الترويسات والكوكيز بناءً على الإعدادات المدخلة"""
        t = self.config.auth_type.lower()
        if t == "bearer" and self.config.bearer_token:
            token = self.config.bearer_token.strip()
            if not token.lower().startswith("bearer "):
                token = f"Bearer {token}"
            self.active_headers["Authorization"] = token
            self.is_authenticated = True

        elif t == "cookie" and self.config.raw_cookie:
            for part in self.config.raw_cookie.split(";"):
                if "=" in part:
                    k, v = part.strip().split("=", 1)
                    self.active_cookies[k.strip()] = v.strip()
            self.active_headers["Cookie"] = self.config.raw_cookie.strip()
            self.is_authenticated = True

        elif t == "api_key" and self.config.api_key_value:
            header_name = self.config.api_key_header.strip() or "X-API-Key"
            self.active_headers[header_name] = self.config.api_key_value.strip()
            self.is_authenticated = True

        if self.config.custom_headers:
            self.active_headers.update(self.config.custom_headers)

    async def perform_initial_auth(self, client: httpx.AsyncClient) -> bool:
        """تنفيذ تسجيل الدخول الآلي إذا تم تحديد form_login"""
        if self.config.auth_type.lower() != "form_login" or not self.config.login_url:
            return self.is_authenticated

        return await self._execute_form_login(client)

    async def _execute_form_login(self, client: httpx.AsyncClient) -> bool:
        """تنفيذ طلب تسجيل الدخول وحفظ الجلسة الناتجة"""
        login_data = {
            self.config.username_field: self.config.username_val,
            self.config.password_field: self.config.password_val
        }
        try:
            if self.config.login_method.upper() == "POST":
                resp = await client.post(self.config.login_url, data=login_data, timeout=8.0, follow_redirects=True)
            else:
                resp = await client.get(self.config.login_url, params=login_data, timeout=8.0, follow_redirects=True)

            cookies = resp.headers.get_list("set-cookie")
            if cookies:
                cookie_str = "; ".join([c.split(";")[0] for c in cookies])
                self.active_headers["Cookie"] = cookie_str
                self.is_authenticated = True
                self.last_login_time = time.time()
                return True

            # التحقق مما إذا كان هناك JWT في الرد
            body = resp.text
            jwt_m = re.search(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+', body)
            if jwt_m:
                self.active_headers["Authorization"] = f"Bearer {jwt_m.group(0)}"
                self.is_authenticated = True
                self.last_login_time = time.time()
                return True

            if resp.status_code in [200, 302]:
                self.is_authenticated = True
                self.last_login_time = time.time()
                return True

        except Exception:
            pass

        return False

    async def check_and_refresh_session(self, response: httpx.Response, client: httpx.AsyncClient) -> bool:
        """
        التحقق من انتهاء الجلسة أثناء الفحص وإعادة تجديدها آلياً
        """
        if not self.config.auto_reauth or self.config.auth_type.lower() != "form_login":
            return False

        is_expired = False
        if response.status_code in [401, 403]:
            is_expired = True
        elif response.status_code == 302 and "login" in response.headers.get("location", "").lower():
            is_expired = True
        else:
            for pat in self.SESSION_EXPIRED_INDICATORS:
                if re.search(pat, response.text):
                    is_expired = True
                    break

        if is_expired:
            return await self._execute_form_login(client)

        return False

    def inject_auth_headers(self, headers_dict: Dict[str, str]) -> Dict[str, str]:
        """حقن ترويسات المصادقة في أي طلب شبكي صادر"""
        merged = headers_dict.copy()
        merged.update(self.active_headers)
        return merged
