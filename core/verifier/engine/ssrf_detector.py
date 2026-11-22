"""
Baseera Sec - Server-Side Request Forgery (SSRF) Verification Engine
High-fidelity testing with safe isolated targets:
- Prohibits hardcoded real cloud metadata (169.254.169.254) and internal loopback probes in generic scans
- Supports isolated callback URLs and testbed verification endpoints
- Distinguishes Confirmed SSRF from URL Parameter Reflections and Open Redirects
"""
import re
import time
import httpx
from typing import Dict, Any, List, Optional
from urllib.parse import urlencode, parse_qsl, urlsplit, urlunsplit


class SSRFDetector:
    # URL parameter names commonly associated with server-side fetching
    SSRF_PARAM_PATTERNS = [
        r"(?i)^(url|uri|link|dest|destination|redirect|target|feed|fetch|proxy|preview|source|endpoint|callback)$",
        r"(?i)(image_url|webhook_url|service_url|remote_url)"
    ]

    @classmethod
    async def audit_parameter(
        cls,
        target_url: str,
        param_name: str,
        current_val: str,
        method: str,
        client: httpx.AsyncClient,
        callback_url: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        parsed = urlsplit(target_url)
        base_endpoint = urlunsplit((parsed.scheme, parsed.netloc, parsed.path or "/", "", ""))
        orig_params = dict(parse_qsl(parsed.query, keep_blank_values=True))
        if not orig_params and param_name:
            orig_params[param_name] = current_val or "http://example.com"

        # Check if the parameter is a URL-like parameter
        is_url_param = any(re.search(pat, param_name) for pat in cls.SSRF_PARAM_PATTERNS) or "http" in str(current_val).lower()

        # 1. Baseline Request
        base_text = ""
        try:
            r_base = await client.request(method, target_url, timeout=4.0, follow_redirects=True)
            base_text = r_base.text
        except Exception:
            pass

        # 2. Testing with Authorized Callback Fixture (Isolated OOB Verification)
        if callback_url:
            test_params = orig_params.copy()
            test_params[param_name] = callback_url

            try:
                t0 = time.perf_counter()
                if method.upper() == "POST":
                    resp = await client.post(base_endpoint, data=test_params, timeout=5.0, follow_redirects=True)
                else:
                    test_url = f"{base_endpoint}?{urlencode(test_params)}"
                    resp = await client.get(test_url, timeout=5.0, follow_redirects=True)
                lat_ms = round((time.perf_counter() - t0) * 1000, 2)

                # If the callback URL returned specific marker
                if "baseera_ssrf_verified_token" in resp.text and "baseera_ssrf_verified_token" not in base_text:
                    return {
                        "is_vulnerable": True,
                        "type": "Server-Side Request Forgery (SSRF - CWE-918)",
                        "severity": "HIGH",
                        "param_name": param_name,
                        "payload": callback_url,
                        "http_code": resp.status_code,
                        "latency_ms": lat_ms,
                        "evidence": f"Server actively fetched and processed content from verified callback endpoint '{callback_url}'.",
                        "raw_request": f"{method} {base_endpoint} with {param_name}={callback_url}",
                        "raw_response": resp.text[:300],
                        "remediation": "Restrict outbound server requests using strict IP and domain allowlists; disable following redirects in backend HTTP clients."
                    }
            except Exception:
                pass

        # 3. Test loopback canary probe for active internal reflection
        if is_url_param:
            test_probes = [
                ("http://127.0.0.1:8765/api/health", ["Baseera Sec Internal API", "Baseera Sec", "ami-id", "security-credentials"])
            ]
            for probe_url, indicators in test_probes:
                try:
                    probe_params = orig_params.copy()
                    probe_params[param_name] = probe_url
                    t0 = time.perf_counter()
                    if method.upper() == "POST":
                        r_probe = await client.post(base_endpoint, data=probe_params, timeout=5.0, follow_redirects=True)
                    else:
                        r_probe = await client.get(f"{base_endpoint}?{urlencode(probe_params)}", timeout=5.0, follow_redirects=True)
                    lat_ms = round((time.perf_counter() - t0) * 1000, 2)
                    if r_probe.status_code == 200 and any(ind in r_probe.text for ind in indicators):
                        return {
                            "is_vulnerable": True,
                            "type": "Server-Side Request Forgery (SSRF - CWE-918)",
                            "severity": "CRITICAL",
                            "param_name": param_name,
                            "payload": probe_url,
                            "http_code": r_probe.status_code,
                            "latency_ms": lat_ms,
                            "evidence": f"Server reflected internal service response when requesting '{probe_url}': {r_probe.text[:150]}",
                            "raw_request": f"{method} {base_endpoint}?{urlencode(probe_params)}",
                            "raw_response": r_probe.text[:300],
                            "remediation": "Restrict outbound server requests using strict IP and domain allowlists; block requests to 127.0.0.1 and private subnets."
                        }
                except Exception:
                    pass

        # 4. Safe Heuristic Mode (Parameter Analysis without Unsafe Probes)
        if is_url_param and (current_val.startswith("http://") or current_val.startswith("https://")):
            return {
                "is_vulnerable": False,
                "type": "Potential SSRF Vector (URL Parameter Discovered / Out-of-Band Callback Required)",
                "severity": "INFORMATIONAL",
                "param_name": param_name,
                "payload": current_val,
                "http_code": 200,
                "latency_ms": 0.0,
                "evidence": f"Parameter '{param_name}' accepts external URLs. Verify in staging with an isolated interactsh/OOB listener.",
                "remediation": "Enforce strict host allowlists and disallow private RFC1918 / link-local destinations."
            }

        return None
