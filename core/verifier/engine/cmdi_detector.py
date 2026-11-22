"""
Baseera Sec - Command Injection (CMDi) Verification Engine
Safely audits parameters for OS Command Injection (CWE-78) by:
1. Evaluating arithmetic command substitutions (expr 48102 + 19283 -> 67385)
2. Validating execution outputs (uid=... gid=...)
3. Distinguishing command output from simple input reflection.
"""
import re
import time
import httpx
from typing import Dict, Any, List, Optional
from urllib.parse import urlencode, parse_qsl, urlsplit, urlunsplit


class CMDiDetector:
    PROBES = [
        ("; expr 48102 + 19283", "67385", "Semicolon arithmetic expression evaluation"),
        ("| expr 48102 + 19283", "67385", "Pipe arithmetic expression evaluation"),
        ("`expr 48102 + 19283`", "67385", "Backtick arithmetic expression evaluation"),
        ("$(expr 48102 + 19283)", "67385", "Dollar-paren arithmetic expression evaluation"),
        ("; id", "uid=", "Linux id command probe"),
        ("| id", "uid=", "Linux id pipe probe")
    ]

    PATTERNS = [
        (r"\b67385\b", "Evaluated Arithmetic Sum 67385"),
        (r"uid=\d+\([a-zA-Z0-9_\-]+\)\s+gid=\d+", "Unix/Linux id command structure"),
        (r"Windows IP Configuration", "Windows ipconfig output")
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
            orig_params[param_name] = current_val or "127.0.0.1"

        try:
            r_base = await client.request(method, target_url, timeout=5.0, follow_redirects=True)
            base_text = r_base.text
        except (httpx.TimeoutException, httpx.ConnectError):
            return {"is_vulnerable": False, "is_timeout": True, "error": "Network timeout"}
        except Exception:
            base_text = ""

        for probe_payload, expected_token, probe_desc in cls.PROBES:
            # Skip if expected token is already in baseline
            if expected_token in base_text:
                continue

            test_params = orig_params.copy()
            test_params[param_name] = f"{current_val}{probe_payload}" if current_val else probe_payload

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

                    # Reflection guard: If input is simply echoed back verbatim with the probe string
                    if probe_payload in resp_text and expected_token != "67385":
                        # Raw command string was mirrored back, not executed
                        continue

                    for regex_pattern, pattern_desc in cls.PATTERNS:
                        if re.search(regex_pattern, resp_text) and not re.search(regex_pattern, base_text):
                            return {
                                "is_vulnerable": True,
                                "type": "OS Command Injection (CWE-78)",
                                "severity": "CRITICAL",
                                "param_name": param_name,
                                "payload": probe_payload,
                                "http_code": resp.status_code,
                                "latency_ms": lat_ms,
                                "evidence": f"OS Command executed and validated in response: detected '{pattern_desc}'.",
                                "raw_request": f"{method} {base_endpoint} with {param_name}={test_params[param_name]}",
                                "raw_response": resp.text[:300].strip(),
                                "remediation": "Do not pass user input to shell interpreters (system, popen, exec). Use safe standard library functions with array arguments."
                            }
            except Exception:
                continue

        return None
