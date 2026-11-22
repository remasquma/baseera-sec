"""
Baseera Sec - Cross-Site Scripting (Reflected XSS) Active Verifier
Context-aware validation verifying:
1. True DOM element injection (unescaped executable tag nodes)
2. Safe entity encoding (&lt; &gt; &quot;)
3. Non-executable contexts (HTML comments, <textarea>, <title>, <style>)
Prevents mistaking harmless reflection for executable XSS.
"""
import time
import re
import httpx
from bs4 import BeautifulSoup, Comment
from typing import Dict, Any, Optional
from urllib.parse import urlencode, parse_qsl, urlsplit, urlunsplit


class XSSDetector:
    # Unique probe with distinct tag name and canary attribute
    XSS_TAG_NAME = "baseeraxss731"
    XSS_PROBE = f"<{XSS_TAG_NAME} id='poc'>"

    @classmethod
    async def audit_parameter(
        cls,
        target_url: str,
        param_name: str,
        method: str,
        client: httpx.AsyncClient
    ) -> Optional[Dict[str, Any]]:
        parsed = urlsplit(target_url)
        base_endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        orig_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not orig_params and param_name:
            orig_params[param_name] = "test"

        probes_to_test = [
            cls.XSS_PROBE,
            f"\'><{cls.XSS_TAG_NAME} id=\'poc\'>",
            f"</script><{cls.XSS_TAG_NAME} id=\'poc\'>"
        ]

        defended_result = None

        try:
            for current_probe in probes_to_test:
                test_params = orig_params.copy()
                test_params[param_name] = current_probe

                t0 = time.perf_counter()
                if method.upper() == "POST":
                    resp = await client.post(base_endpoint, data=test_params, timeout=6.0, follow_redirects=True)
                else:
                    resp = await client.get(f"{base_endpoint}?{urlencode(test_params)}", timeout=6.0, follow_redirects=True)

                elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
                c_type = resp.headers.get("content-type", "").lower()
                resp_text = resp.text

                # If content-type is JSON or plain text, browsers do not execute HTML tags
                if not any(t in c_type for t in ["text/html", "application/xhtml+xml"]):
                    return None

                # 1. Check if probe is encoded (Defended / Sanitized)
                if f"&lt;{cls.XSS_TAG_NAME}" in resp_text or f"&#60;{cls.XSS_TAG_NAME}" in resp_text:
                    if not defended_result:
                        defended_result = {
                            "is_vulnerable": False,
                            "type": "Defended / Sanitized Input (HTML Entity Encoded)",
                            "param_name": param_name,
                            "payload": current_probe,
                            "http_code": resp.status_code,
                            "latency_ms": elapsed_ms,
                            "evidence": "Probe tags were properly encoded (&lt; / &#60;); browser DOM execution prevented.",
                            "remediation": "Continue using context-aware output encoding."
                        }
                    continue

                # 2. Context-aware DOM parsing with BeautifulSoup
                if cls.XSS_TAG_NAME in resp_text.lower():
                    soup = BeautifulSoup(resp_text, "html.parser")

                    # Check if probe was parsed as an actual HTML tag element
                    matched_elements = soup.find_all(cls.XSS_TAG_NAME)
                    if matched_elements:
                        # Verify parent context: is it inside <script>, <style>, <textarea>, or <title>?
                        is_in_container = False
                        for el in matched_elements:
                            parent_tag = el.parent.name.lower() if el.parent else ""
                            if parent_tag in ("textarea", "title", "style", "noscript"):
                                is_in_container = True
                                break

                        if not is_in_container:
                            # True unescaped DOM element injection confirmed!
                            return {
                                "is_vulnerable": True,
                                "type": "Reflected Cross-Site Scripting (XSS)",
                                "severity": "HIGH",
                                "param_name": param_name,
                                "payload": current_probe,
                                "http_code": resp.status_code,
                                "latency_ms": elapsed_ms,
                                "evidence": f"HTTP {resp.status_code} | Parameter '{param_name}' directly injected unescaped <{cls.XSS_TAG_NAME}> tag element into live DOM tree.",
                                "raw_request": f"{method} {base_endpoint}?{urlencode(test_params)}",
                                "raw_response": f"<{cls.XSS_TAG_NAME}> element rendered as executable DOM node.",
                                "remediation": f"Apply context-aware HTML output encoding (e.g. htmlspecialchars / encodeURIComponent) to parameter '{param_name}'."
                            }

                    # Check if it was trapped inside an HTML comment
                    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
                    if any(cls.XSS_TAG_NAME in c.lower() for c in comments):
                        if not defended_result:
                            defended_result = {
                                "is_vulnerable": False,
                                "type": "Reflected Input in HTML Comment",
                                "param_name": param_name,
                                "payload": current_probe,
                                "http_code": resp.status_code,
                                "latency_ms": elapsed_ms,
                                "evidence": "Probe reflected inside HTML comment <!-- ... --> without breaking out.",
                                "remediation": "Sanitize comment reflections to prevent '-->' comment injection."
                            }
                        continue

            return defended_result

        except Exception:
            pass

        return None
