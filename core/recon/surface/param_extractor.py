"""
Baseera Sec - Enterprise Parameter & Attack Surface Extractor
يقوم بتفكيك وتحليل الرابط، استخراج المعاملات (Query Parameters)، 
واستكشاف النماذج (HTML Forms) والمسارات المرتبطة لاكتشاف كافة نقاط الإدخال القابلة للاختبار
"""
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urljoin
from typing import Dict, List, Any
from dataclasses import dataclass, field
from bs4 import BeautifulSoup

@dataclass
class InjectionPoint:
    param_name: str
    original_value: str
    method: str = "GET" # "GET" أو "POST"
    target_url: str = ""
    is_form_input: bool = False

@dataclass
class TargetSurface:
    raw_url: str
    clean_base_url: str
    origin: str
    url_params: Dict[str, str] = field(default_factory=dict)
    injection_points: List[InjectionPoint] = field(default_factory=list)
    discovered_links: List[str] = field(default_factory=list)
    discovered_forms: List[Dict[str, Any]] = field(default_factory=list)

class SurfaceExtractor:
    @classmethod
    def analyze_surface(cls, target_url: str, html_body: str = "") -> TargetSurface:
        parsed = urlsplit(target_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        clean_base = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))

        url_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        injection_points: List[InjectionPoint] = []

        # 1. استخراج معاملات الرابط نفسه (GET Query Parameters)
        for name, val in url_params.items():
            injection_points.append(InjectionPoint(
                param_name=name,
                original_value=val,
                method="GET",
                target_url=clean_base,
                is_form_input=False
            ))

        discovered_links = []
        discovered_forms = []

        # 2. فحص محتوى صفحة HTML لاستخراج النماذج (HTML Forms) والروابط الداخلية
        if html_body:
            try:
                soup = BeautifulSoup(html_body, "html.parser")

                # استخراج النماذج
                for form in soup.find_all("form"):
                    action = form.get("action") or ""
                    form_url = urljoin(clean_base, action)
                    form_method = (form.get("method") or "GET").upper()

                    inputs_dict = {}
                    for inp in form.find_all(["input", "textarea", "select"]):
                        inp_name = inp.get("name")
                        if not inp_name:
                            continue
                        inp_val = inp.get("value") or ""
                        inputs_dict[inp_name] = inp_val

                        # إضافة حقل الإدخال كنقطة حقن محتملة
                        if not any(ip.param_name == inp_name and ip.target_url == form_url for ip in injection_points):
                            injection_points.append(InjectionPoint(
                                param_name=inp_name,
                                original_value=inp_val,
                                method=form_method,
                                target_url=form_url,
                                is_form_input=True
                            ))

                    if inputs_dict:
                        discovered_forms.append({
                            "url": form_url,
                            "method": form_method,
                            "inputs": inputs_dict
                        })

                # استخراج روابط تحتوي على معاملات GET إضافية
                for a in soup.find_all("a", href=True):
                    href = a["href"].strip()
                    if href.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue
                    full_link = urljoin(clean_base, href)
                    if origin in full_link and "?" in full_link:
                        if full_link not in discovered_links and full_link != target_url:
                            discovered_links.append(full_link)

            except Exception:
                pass

        return TargetSurface(
            raw_url=target_url,
            clean_base_url=clean_base,
            origin=origin,
            url_params=url_params,
            injection_points=injection_points,
            discovered_links=discovered_links[:15],
            discovered_forms=discovered_forms[:10]
        )
