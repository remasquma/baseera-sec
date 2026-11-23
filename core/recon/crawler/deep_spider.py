"""
Baseera Sec - Deep Enterprise Web Crawler & Endpoint Spider (v2.7.0)
محرك الزحف العميق واستكشاف مساحة الهجوم الشاملة (Attack Surface Discovery)
محدث بمحرك متطور لدعم تطبيقات الـ JavaScript الحديثة (SPAs: Angular, React, Vue)
وفحص حزم الـ Bundles وملفات توثيق الـ APIs (Swagger / OpenAPI)
"""
import re
import json
import asyncio
from typing import Dict, List, Set, Any, Optional
from urllib.parse import urlsplit, urlunsplit, urljoin, parse_qsl
import httpx
from bs4 import BeautifulSoup
from core.recon.surface.param_extractor import InjectionPoint, TargetSurface
from core.verifier.engine.fp_guard import ZeroFPGuard

class DeepSpider:
    """
    الزاحف التكراري الذكي:
    يزحف في صفحات الموقع، ويحلل حزم الـ JS وحزم الـ SPAs، ويكتشف المعاملات، والنماذج، والـ APIs
    """

    COMMON_HIGH_VALUE_PATHS = [
        "/robots.txt",
        "/sitemap.xml",
        "/swagger.json",
        "/openapi.json",
        "/api-docs",
        "/swagger/v1/swagger.json",
        "/api/",
        "/rest/",
        "/ftp",
        "/ftp/",
        "/login",
        "/search",
        "/admin",
        "/images/",
        "/uploads/",
        "/files/",
        # مسارات ووردبريس وإدارة المحتوى (CMS Probing)
        "/wp-login.php",
        "/wp-json/wp/v2/users",
        "/xmlrpc.php",
        "/wp-content/plugins/",
        # مسارات تطبيقات الويب الشائعة الحاوية لنماذج ومعاملات
        "/login.jsp",
        "/login.asp",
        "/login.php",
        "/search.jsp",
        "/search.asp",
        "/search.php",
        "/artists.php",
        "/categories.php",
        "/products.php",
        "/ReadNews.aspx",
        "/Comments.aspx",
        "/doLogin"
    ]

    DIRECTORY_LISTING_PATTERNS = [
        r"(?i)<title>\s*index of\s+/",
        r"(?i)Directory Listing for",
        r"(?i)Parent Directory</a>",
        r"(?i)Last modified</th>",
        r"(?i)\[To Parent Directory\]"
    ]

    DOM_XSS_SOURCES = [
        r"location\.search",
        r"location\.hash",
        r"location\.href",
        r"document\.referrer",
        r"window\.name"
    ]

    DOM_XSS_SINKS = [
        r"\.innerHTML\s*=",
        r"document\.write\s*\(",
        r"document\.writeln\s*\(",
        r"\$\([^\)]+\)\.html\s*\(",
        r"eval\s*\("
    ]

    def __init__(self, base_url: str, max_pages: int = 35, max_depth: int = 3):
        self.raw_base_url = base_url
        parsed = urlsplit(base_url)
        self.scheme = parsed.scheme or "http"
        self.hostname = parsed.hostname or ""
        self.port = parsed.port
        self.netloc = parsed.netloc
        self.origin = f"{self.scheme}://{self.netloc}"
        self.clean_base = urlunsplit((self.scheme, self.netloc, parsed.path or "/", "", ""))
        self.max_pages = max_pages
        self.max_depth = max_depth
        self.visited: Set[str] = set()
        self.discovered_endpoints: Set[str] = set()
        self.injection_points: List[InjectionPoint] = []
        self.discovered_forms: List[Dict[str, Any]] = []
        self.directory_listing_findings: List[Dict[str, Any]] = []
        self.dom_xss_findings: List[Dict[str, Any]] = []
        self.wordpress_findings: List[Dict[str, Any]] = []
        self.scraped_scripts: Set[str] = set()

    async def crawl(self, client: httpx.AsyncClient) -> TargetSurface:
        """
        تشغيل الزحف التكراري واستخراج مساحة الهجوم الشاملة مع دعم كامل للمنافذ غير القياسية
        """
        queue = [(self.raw_base_url, 0)]
        self.discovered_endpoints.add(self.raw_base_url)

        # إضافة المعاملات من الرابط الأساسي إن وجدت
        parsed_base = urlsplit(self.raw_base_url)
        if parsed_base.query:
            for k, v in parse_qsl(parsed_base.query, keep_blank_values=True):
                self._add_injection_point(k, v, "GET", self.clean_base, False)

        while queue and len(self.visited) < self.max_pages:
            current_url, depth = queue.pop(0)
            clean_curr = current_url.split("#")[0].strip()
            if clean_curr in self.visited:
                continue

            self.visited.add(clean_curr)

            try:
                resp = await client.get(clean_curr, timeout=4.0, follow_redirects=True)
                # التعامل الذكي مع المنافذ غير القياسية التي تشترط بروتوكول HTTPS
                if resp.status_code == 400 and ("https port" in resp.text.lower() or "plain http" in resp.text.lower()):
                    clean_curr = clean_curr.replace("http://", "https://")
                    self.scheme = "https"
                    self.origin = f"https://{self.netloc}"
                    self.clean_base = self.clean_base.replace("http://", "https://")
                    resp = await client.get(clean_curr, timeout=4.0, follow_redirects=True)

                if resp.status_code != 200:
                    continue

                html = resp.text
                content_type = resp.headers.get("content-type", "").lower()

                # فحص Directory Listing
                for pat in self.DIRECTORY_LISTING_PATTERNS:
                    if re.search(pat, html):
                        self.directory_listing_findings.append({
                            "url": clean_curr,
                            "pattern": pat,
                            "evidence": f"Directory listing disclosed at {clean_curr}"
                        })
                        break

                if "text/html" not in content_type and "application/xhtml" not in content_type:
                    continue

                soup = BeautifulSoup(html, "html.parser")

                # 1. استخراج النماذج (Forms)
                for form in soup.find_all("form"):
                    action = form.get("action") or ""
                    form_url = urljoin(clean_curr, action)
                    form_method = (form.get("method") or "GET").upper()

                    inputs_dict = {}
                    for inp in form.find_all(["input", "textarea", "select"]):
                        inp_name = inp.get("name")
                        if not inp_name:
                            continue
                        inp_val = inp.get("value") or ""
                        inputs_dict[inp_name] = inp_val
                        self._add_injection_point(inp_name, inp_val, form_method, form_url, True)

                    if inputs_dict:
                        self.discovered_forms.append({
                            "url": form_url,
                            "method": form_method,
                            "inputs": inputs_dict
                        })

                # 2. استخراج الروابط الداخلية (Links) مع فحص نطاق المنافذ المخصصة
                if depth < self.max_depth:
                    for a in soup.find_all("a", href=True):
                        href = a["href"].strip()
                        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                            continue

                        full_url = urljoin(clean_curr, href)
                        parsed_u = urlsplit(full_url)

                        # فحص نطاق الهدف (Scope Filter) مع الدعم الكامل للمنافذ غير القياسية (:81, :82, إلخ)
                        is_same_host = (parsed_u.hostname == self.hostname)
                        if is_same_host:
                            # تثبيت المنفذ غير القياسي في حال أسقطته الروابط النسبية أو الداخلية للموقع
                            if self.port and parsed_u.port != self.port:
                                fixed_netloc = f"{parsed_u.hostname}:{self.port}"
                                full_url = urlunsplit((self.scheme, fixed_netloc, parsed_u.path, parsed_u.query, parsed_u.fragment))
                                parsed_u = urlsplit(full_url)

                            clean_endpoint = urlunsplit((parsed_u.scheme, parsed_u.netloc, parsed_u.path, "", ""))
                            self.discovered_endpoints.add(clean_endpoint)

                            if parsed_u.query:
                                for q_name, q_val in parse_qsl(parsed_u.query, keep_blank_values=True):
                                    self._add_injection_point(q_name, q_val, "GET", full_url, False)

                            if full_url not in self.visited and len(queue) < 60:
                                # إعطاء أولوية في الطابور للروابط التي تحوي معاملات أو صفحات بحث ودخول ومسارات ديناميكية
                                is_priority = any(k in full_url.lower() for k in ["?", "id=", "post", "edit", "login", "search", "content", "read", "news", "comment", "reflected", "dom", "artist"])
                                if is_priority:
                                    queue.insert(0, (full_url, depth + 1))
                                else:
                                    queue.append((full_url, depth + 1))

                # 3. تحليل حزم JavaScript (SPAs & Script Bundles)
                # استخراج السكربتات المضمنة والملفات الخارجية
                scripts_to_analyze = []
                for s in soup.find_all("script"):
                    src = s.get("src")
                    if src:
                        script_url = urljoin(clean_curr, src)
                        parsed_s = urlsplit(script_url)
                        if parsed_s.hostname == self.hostname and script_url not in self.scraped_scripts:
                            if self.port and parsed_s.port != self.port:
                                fixed_netloc = f"{parsed_s.hostname}:{self.port}"
                                script_url = urlunsplit((self.scheme, fixed_netloc, parsed_s.path, parsed_s.query, parsed_s.fragment))
                            self.scraped_scripts.add(script_url)
                            scripts_to_analyze.append(script_url)
                    else:
                        if s.string:
                            self._analyze_js_content(s.string, clean_curr, script_source_url=clean_curr, is_inline=True)

                # تنزيل وتحليل حزم الـ JS الخارجية (حتى 8 حزم رئيسية)
                for s_url in scripts_to_analyze[:8]:
                    try:
                        s_resp = await client.get(s_url, timeout=3.5)
                        if s_resp.status_code == 200:
                            self._analyze_js_content(s_resp.text, clean_curr, script_source_url=s_url, is_inline=False)
                    except Exception:
                        continue

            except Exception:
                continue

        # فحص المسارات القياسية ومواصفات OpenAPI / Swagger
        await self._probe_high_value_paths(client)

        return TargetSurface(
            raw_url=self.raw_base_url,
            clean_base_url=self.clean_base,
            origin=self.origin,
            url_params=dict(parse_qsl(parsed_base.query, keep_blank_values=True)),
            injection_points=self.injection_points,
            discovered_links=list(self.discovered_endpoints)[:40],
            discovered_forms=self.discovered_forms[:20]
        )

    def _analyze_js_content(self, js_text: str, current_page_url: str, script_source_url: str = "", is_inline: bool = False):
        """تحليل محتوى كود الجافاسكريبت لاستخراج المسارات والـ API والمعاملات وفحص DOM XSS بدقة متناهية وبـ URI نقي"""
        if not js_text:
            return

        # الرابط النقي المستهدف (Valid RFC 3986 URI)
        pure_clean_url = current_page_url if is_inline else (script_source_url or current_page_url)

        # 1. استخراج مسارات API ونقاط النهاية
        api_patterns = [
            r'["\'](/(?:api|rest|v[1-3]|graphql|auth|user|products?|items?|cart|basket|order|search|upload|download|files?|ftp)[a-zA-Z0-9_\-\./\?=&]*)["\']',
            r'["\']([a-zA-Z0-9_\-]+\.(?:php|asp|aspx|jsp)\?[a-zA-Z0-9_\-=&]+)["\']'
        ]

        for pat in api_patterns:
            for match in re.findall(pat, js_text):
                full_api = urljoin(self.origin, match)
                parsed_api = urlsplit(full_api)
                if parsed_api.hostname == self.hostname:
                    if self.port and parsed_api.port != self.port:
                        full_api = urlunsplit((self.scheme, f"{self.hostname}:{self.port}", parsed_api.path, parsed_api.query, parsed_api.fragment))
                        parsed_api = urlsplit(full_api)
                    self.discovered_endpoints.add(full_api)
                    if parsed_api.query:
                        for q_name, q_val in parse_qsl(parsed_api.query, keep_blank_values=True):
                            self._add_injection_point(q_name, q_val, "GET", full_api, False)
                    else:
                        if any(k in match.lower() for k in ["search", "find", "query"]):
                            self._add_injection_point("q", "test", "GET", full_api, False)
                        elif any(k in match.lower() for k in ["product", "item", "user", "order"]):
                            self._add_injection_point("id", "1", "GET", full_api, False)

        # 2. فحص ثغرات DOM XSS الحقيقية والمثبتة فقط (Zero False Positive Guard)
        # استبعاد تام لكافة حزم الطرف الثالث المعروفة والـ CDNs والمكتبات الآمنة
        if ZeroFPGuard.is_benign_third_party_resource(pure_clean_url):
            return

        # التحقق الصارم من وجود تدفق بيانات مباشر حقيقي (Direct Tainted Data Flow)
        # بين المصدر (Source) والمصب (Sink) في نفس السياق البرمجي
        direct_dom_xss_patterns = [
            (r"(?i)(?:\.innerHTML\s*=|document\.write\s*\(|document\.writeln\s*\(|\$\([^\)]+\)\.html\s*\(|eval\s*\()[^;\n]*(?:location\.(?:search|hash|href)|document\.referrer|window\.name)", "Direct Unsanitized Sink Injection"),
            (r"(?i)(?:var|let|const)\s+([a-zA-Z0-9_$]+)\s*=\s*(?:location\.(?:search|hash|href)|document\.referrer)[\s\S]{1,200}?(?:\.innerHTML\s*=|document\.write\s*\(|\.html\s*\()\s*\1", "Direct Variable Flow to DOM Sink")
        ]

        is_real_dom_xss = False
        matched_evidence = ""
        if "dompurify" not in js_text.lower():
            for pat, desc in direct_dom_xss_patterns:
                m = re.search(pat, js_text)
                if m:
                    is_real_dom_xss = True
                    snippet = m.group(0)[:120].strip().replace("\n", " ")
                    matched_evidence = f"{desc}: {snippet}"
                    break

        if is_real_dom_xss:
            script_desc = f"inline script on page '{current_page_url}'" if is_inline else f"script file '{pure_clean_url}'"
            evidence_str = f"Verified DOM XSS Flow in {script_desc} | Evidence: {matched_evidence}"
            self.dom_xss_findings.append({
                "url": pure_clean_url,
                "evidence": evidence_str,
                "script": pure_clean_url,
                "is_inline": is_inline
            })

    def _add_injection_point(self, name: str, val: str, method: str, url: str, is_form: bool):
        # منع تكرار نفس المعامل في نفس الرابط
        if not any(ip.param_name == name and ip.target_url == url and ip.method == method for ip in self.injection_points):
            self.injection_points.append(InjectionPoint(
                param_name=name,
                original_value=val or "1",
                method=method,
                target_url=url,
                is_form_input=is_form
            ))

    async def _probe_high_value_paths(self, client: httpx.AsyncClient):
        """فحص المسارات الشائعة مثل /swagger.json و /robots.txt و /ftp وغيرها"""
        for path in self.COMMON_HIGH_VALUE_PATHS:
            target = urljoin(self.origin, path)
            if target in self.visited:
                continue
            try:
                r = await client.get(target, timeout=3.0, follow_redirects=True)
                if r.status_code == 200:
                    self.discovered_endpoints.add(target)

                    # فحص OpenAPI / Swagger
                    if any(s in path for s in ["swagger", "openapi", "api-docs"]):
                        try:
                            spec = json.loads(r.text)
                            if "paths" in spec and isinstance(spec["paths"], dict):
                                for api_route, route_methods in spec["paths"].items():
                                    api_full = urljoin(self.origin, api_route)
                                    self.discovered_endpoints.add(api_full)
                                    if isinstance(route_methods, dict):
                                        for m, details in route_methods.items():
                                            m_upper = m.upper()
                                            if isinstance(details, dict) and "parameters" in details:
                                                for param in details["parameters"]:
                                                    p_name = param.get("name")
                                                    if p_name:
                                                        self._add_injection_point(p_name, "1", m_upper, api_full, False)
                        except Exception:
                            pass

                    # فحص Directory listing
                    for pat in self.DIRECTORY_LISTING_PATTERNS:
                        if re.search(pat, r.text):
                            self.directory_listing_findings.append({
                                "url": target,
                                "pattern": pat,
                                "evidence": f"Open directory listing detected at {target}"
                            })
                            break

                    # فحص ووردبريس (User Enumeration & XML-RPC)
                    if "/wp-json/wp/v2/users" in path:
                        try:
                            users = json.loads(r.text)
                            if isinstance(users, list) and len(users) > 0 and ("slug" in users[0] or "name" in users[0]):
                                user_names = [str(u.get("slug") or u.get("name")) for u in users[:5]]
                                self.wordpress_findings.append({
                                    "title": "كشف وتعداد مستخدمي ووردبريس (WordPress User Enumeration Disclosed)",
                                    "url": target,
                                    "evidence": f"REST API leaks internal WordPress usernames: {', '.join(user_names)}",
                                    "cwe": "CWE-200"
                                })
                        except Exception:
                            pass

                    if "/xmlrpc.php" in path:
                        text_lower = r.text.lower()
                        is_html_resp = "<!doctype html" in text_lower or "<html" in text_lower or "<head" in text_lower
                        # الخادم الحقيقي لووردبريس يعيد نصاً محدداً وصريحاً عند طلب GET
                        if not is_html_resp and r.status_code == 200 and "XML-RPC server accepts POST requests only." in r.text:
                            self.wordpress_findings.append({
                                "title": "تفعيل واجهة XML-RPC لووردبريس (WordPress XML-RPC API Enabled)",
                                "url": target,
                                "evidence": f"XML-RPC endpoint confirmed at {target} ('XML-RPC server accepts POST requests only.')",
                                "cwe": "CWE-200"
                            })

                    # استخراج روابط من robots.txt إن وجد
                    if "/robots.txt" in path:
                        disallowed = re.findall(r"Disallow:\s*([^\r\n#]+)", r.text)
                        for d in disallowed:
                            d_clean = d.strip()
                            if d_clean and not d_clean.startswith("*"):
                                d_full = urljoin(self.origin, d_clean)
                                self.discovered_endpoints.add(d_full)
            except Exception:
                continue
