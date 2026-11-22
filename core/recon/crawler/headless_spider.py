"""
Baseera Sec - Advanced Headless Browser Dynamic Crawler
محرك الزحف الديناميكي لتطبيقات الويب الحديثة (SPAs: React, Angular, Vue):
1. تشغيل متصفح حقيقي في الخلفية (Native Headless Chrome)
2. تنفيذ كود الـ JavaScript كاملاً وتصيير شجرة الـ DOM الديناميكية
3. استخراج الروابط والنماذج والأزرار التفاعلية (button / onclick) التي لا تظهر في الـ HTML الثابت
"""
import os
import subprocess
import shutil
import asyncio
from typing import Dict, List, Set, Any, Optional
from urllib.parse import urlsplit, urlunsplit, urljoin, parse_qsl
from bs4 import BeautifulSoup
from core.recon.surface.param_extractor import InjectionPoint

class HeadlessBrowserCrawler:

    @classmethod
    def is_headless_available(cls) -> bool:
        """التحقق من توفر متصفح كروم / كروميوم على النظام"""
        return bool(shutil.which("google-chrome") or shutil.which("chromium-browser") or shutil.which("chromium"))

    @classmethod
    async def render_dynamic_dom(cls, url: str, wait_seconds: float = 2.0) -> str:
        """
        تشغيل متصفح كروم برمجياً في الخلفية وسحب شجرة الـ DOM الكاملة بعد تنفيذ السكريبتات
        ضمن بيئة معزولة (Disposable Isolated Profile) ودون تعطيل الحماية
        """
        import tempfile
        chrome_bin = shutil.which("google-chrome") or shutil.which("chromium-browser") or shutil.which("chromium")
        if not chrome_bin:
            return ""

        temp_profile = tempfile.mkdtemp(prefix="baseera_browser_")
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
            "--disk-cache-size=1",
            "--media-cache-size=1",
            f"--virtual-time-budget={int(wait_seconds * 1000)}",
            "--dump-dom",
            url
        ]

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10.0)
            return stdout.decode('utf-8', errors='ignore')
        except Exception:
            return ""
        finally:
            if os.path.exists(temp_profile):
                shutil.rmtree(temp_profile, ignore_errors=True)

    @classmethod
    async def crawl_spa_page(cls, url: str) -> Dict[str, Any]:
        """
        استخراج الروابط والنماذج التفاعلية من الصفحة بعد تصيير الجافاسكريبت
        """
        result = {
            "links": [],
            "injection_points": [],
            "dynamic_buttons": []
        }

        rendered_html = await cls.render_dynamic_dom(url)
        if not rendered_html:
            return result

        parsed_origin = urlsplit(url)
        origin = f"{parsed_origin.scheme}://{parsed_origin.netloc}"

        soup = BeautifulSoup(rendered_html, "html.parser")

        # 1. استخراج الروابط المصيرة بالجافاسكريبت
        for a in soup.find_all("a", href=True):
            href = a["href"].strip()
            if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                continue
            full_link = urljoin(url, href)
            if parsed_origin.hostname in full_link:
                result["links"].append(full_link)
                # استخراج المعاملات
                parsed_link = urlsplit(full_link)
                if parsed_link.query:
                    for q_k, q_v in parse_qsl(parsed_link.query, keep_blank_values=True):
                        result["injection_points"].append(InjectionPoint(
                            param_name=q_k,
                            original_value=q_v or "1",
                            method="GET",
                            target_url=full_link,
                            is_form_input=False
                        ))

        # 2. استخراج النماذج الديناميكية
        for form in soup.find_all("form"):
            action = form.get("action") or ""
            form_url = urljoin(url, action)
            method = (form.get("method") or "GET").upper()
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    result["injection_points"].append(InjectionPoint(
                        param_name=name,
                        original_value=inp.get("value") or "1",
                        method=method,
                        target_url=form_url,
                        is_form_input=True
                    ))

        # 3. استخراج الأزرار التفاعلية (Interactive Elements)
        for btn in soup.find_all(["button", "div", "span"], onclick=True):
            onclick = btn.get("onclick") or ""
            result["dynamic_buttons"].append(onclick)

        return result
