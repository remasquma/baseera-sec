"""
Baseera Sec - Server-Side Template Injection (SSTI) Active Verifier
محرك فحص حقن قوالب الخادم (SSTI - CWE-1336 / CWE-94)
يدعم أطر عمل: Jinja2, Twig, Freemarker, Velocity, Smarty, Ruby ERB, Mako
"""
import re
import time
import httpx
from typing import Dict, Any, Optional
from urllib.parse import urlencode, parse_qsl, urlsplit, urlunsplit

class SSTIDetector:
    # حمولات رياضية آمنة وفريدة لكشف التنفيذ داخل محركات القوالب
    SSTI_PROBES = [
        ("baseera{{7*7}}sec", "49", "Jinja2 / Twig / Python / PHP expression probe"),
        ("baseera${7*7}sec", "49", "Java / JSP / Freemarker expression probe"),
        ("baseera<%= 7*7 %>sec", "49", "Ruby ERB / ASP expression probe"),
        ("baseera#{7*7}sec", "49", "Ruby / Node.js expression probe"),
        ("baseera{{7*'7'}}sec", "7777777", "Jinja2 string multiplication probe")
    ]

    @classmethod
    async def audit_parameter(
        cls,
        target_url: str,
        param_name: str,
        current_val: str,
        method: str,
        client: httpx.AsyncClient
    ) -> Optional[Dict[str, Any]]:
        parsed = urlsplit(target_url)
        base_endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        orig_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not orig_params and param_name:
            orig_params[param_name] = current_val or "test"

        # خط الأساس
        try:
            r_base = await client.request(method, target_url, timeout=5.0, follow_redirects=True)
            base_text = r_base.text
        except Exception:
            base_text = ""

        for probe_payload, expected_eval, probe_desc in cls.SSTI_PROBES:
            # إذا كانت النتيجة المتوقعة موجودة أصلاً في خط الأساس، نتخطى
            if f"baseera{expected_eval}sec" in base_text:
                continue

            test_params = orig_params.copy()
            test_params[param_name] = probe_payload

            try:
                t0 = time.perf_counter()
                if method.upper() == "POST":
                    resp = await client.post(base_endpoint, data=test_params, timeout=6.0, follow_redirects=True)
                else:
                    resp = await client.get(f"{base_endpoint}?{urlencode(test_params)}", timeout=6.0, follow_redirects=True)
                lat_ms = round((time.perf_counter() - t0) * 1000, 2)

                # الشرط القطعي: ظهور الناتج الحسابي المنفذ محاطاً بالعلامة المميزة
                target_token = f"baseera{expected_eval}sec"
                if target_token in resp.text and target_token not in base_text:
                    return {
                        "is_vulnerable": True,
                        "type": "Server-Side Template Injection (SSTI)",
                        "param_name": param_name,
                        "payload": probe_payload,
                        "evaluated_result": expected_eval,
                        "http_code": resp.status_code,
                        "latency_ms": lat_ms,
                        "evidence": f"HTTP {resp.status_code} | Parameter '{param_name}' evaluated template payload '{probe_payload}' to '{expected_eval}'.",
                        "raw_request": f"{method} {base_endpoint} ({param_name}={probe_payload})",
                        "raw_response": f"Template evaluated to: {target_token}",
                        "remediation": "تجنب تمرير مدخلات المستخدم مباشرة إلى دوال تصيير القوالب (Template Engines)، واستخدم التمرير الآمن للمتغيرات (Context Variables)."
                    }
            except Exception:
                continue

        return None
