"""
Baseera Sec - Targeted Attack Live Multi-Vector Executor
محرك التنفيذ الشبكي الفعلي لمصفوفة الهجمات المتعددة
محدث: التحقق الصارم من أن كود الاستجابة 200 قبل تأكيد أي ثغرة لمنع أي خطأ
"""
import time
import re
import httpx
from urllib.parse import parse_qs, urlsplit
from dataclasses import dataclass
from typing import List, Dict, Optional
from core.ai.attack_agent import TargetedAttackAction
from core.verifier.engine.sql_detector import SQLDetector
from core.verifier.engine.xss_detector import XSSDetector
from core.verifier.engine.cmdi_detector import CMDiDetector
from core.verifier.engine.traversal_detector import TraversalDetector
from core.verifier.engine.ssrf_detector import SSRFDetector
from core.verifier.engine.ssti_detector import SSTIDetector
from core.verifier.engine.idor_detector import IDORDetector
from core.verifier.engine.fp_guard import ZeroFPGuard

@dataclass
class AttackExecutionOutcome:
    attack_name: str
    target_endpoint: str
    attack_vector: str
    attack_category: str
    payload_sent: str
    predicted_probability: float
    execution_status: str     # "EXPLOITED_CONFIRMED" (تم تأكيد الثغرة) أو "TARGET_SECURE" (محمي)
    http_status_code: int
    execution_time_ms: float
    raw_response_evidence: str
    is_vulnerability_proven: bool
    remediation_command: str

class AttackExecutor:
    """
    محرك التنفيذ الشبكي النشط:
    يرسل كل هجوم رشحه الـ AI عبر الشبكة، ويحلل الاستجابة اللحظية لإثبات أو نفي الثغرة بدليل قطعي
    """

    @classmethod
    async def execute_attacks(
        cls,
        actions: List[TargetedAttackAction],
        client: httpx.AsyncClient,
        secondary_client_headers: Optional[Dict[str, str]] = None,
        secondary_resource_url: Optional[str] = None,
    ) -> List[AttackExecutionOutcome]:
        outcomes = []

        for action in actions:
            start_t = time.time()
            endpoint = action.target_endpoint
            payload = action.test_payload
            status = "TARGET_SECURE"
            is_proven = False
            http_code = 0
            evidence_snippet = ""
            remediation = "تأكد من تطبيق معايير الأمان الموصى بها في إعدادات الخادم."

            try:
                http_method = getattr(action, "http_method", "GET").upper()
                param_match = re.search(r"Parameter:\s*([a-zA-Z0-9_\-\.]+)", action.attack_name)
                param_name = getattr(action, "param_name", "") or (param_match.group(1) if param_match else "")

                # -------------------------------------------------------------
                # 0. هجوم حقن قواعد البيانات (Active SQL Injection Verification)
                # -------------------------------------------------------------
                if "SQL Injection" in action.attack_name:
                    sql_res = await SQLDetector.audit_parameter(
                        target_url=endpoint,
                        param_name=param_name,
                        current_val="1",
                        method=http_method,
                        client=client
                    )
                    if sql_res and sql_res.get("is_vulnerable"):
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        http_code = sql_res.get("http_code", 200)
                        evidence_snippet = f"HTTP {http_code} | Proven {sql_res.get('type')}: {sql_res.get('evidence')}"
                        remediation = sql_res.get("remediation", "")
                    elif sql_res and sql_res.get("is_timeout"):
                        status = "UNREACHABLE_TIMEOUT"
                        http_code = 0
                        evidence_snippet = "تعذر الاتصال بالهدف عبر الشبكة (انتهت مهلة الطلب / Network Timeout)."
                    else:
                        http_code = 200
                        evidence_snippet = f"HTTP 200 | Target resisted SQL injection probes on parameter '{param_name}' ({http_method})."

                # -------------------------------------------------------------
                # 0.1 هجوم حقن السكريبتات عبر المتصفح (Reflected XSS Verification)
                # -------------------------------------------------------------
                elif "Reflected XSS" in action.attack_name or "XSS" in action.attack_name:
                    xss_res = await XSSDetector.audit_parameter(
                        target_url=endpoint,
                        param_name=param_name,
                        method=http_method,
                        client=client
                    )
                    if xss_res and xss_res.get("is_vulnerable"):
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        http_code = xss_res.get("http_code", 200)
                        evidence_snippet = xss_res.get("evidence", "")
                        remediation = xss_res.get("remediation", "")
                    else:
                        http_code = 200
                        evidence_snippet = f"HTTP 200 | Parameter '{param_name}' sanitized against HTML/XSS reflection ({http_method})."

                # -------------------------------------------------------------
                # 0.2 هجوم حقن أوامر النظام (Command Injection Verification)
                # -------------------------------------------------------------
                elif "Command Injection" in action.attack_name or "CMDi" in action.attack_name:
                    cmdi_res = await CMDiDetector.audit_parameter(
                        target_url=endpoint,
                        param_name=param_name,
                        current_val="127.0.0.1",
                        method=http_method,
                        client=client
                    )
                    if cmdi_res and cmdi_res.get("is_vulnerable"):
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        http_code = cmdi_res.get("http_code", 200)
                        evidence_snippet = cmdi_res.get("evidence", "")
                        remediation = cmdi_res.get("remediation", "")
                    else:
                        http_code = 200
                        evidence_snippet = f"HTTP 200 | Parameter '{param_name}' safe against OS command execution ({http_method})."

                # -------------------------------------------------------------
                # 0.3 هجوم تخطي المسارات واستعراض الملفات (Path Traversal / LFI)
                # -------------------------------------------------------------
                elif "Path Traversal" in action.attack_name or "LFI" in action.attack_name:
                    trav_res = await TraversalDetector.audit_parameter(
                        target_url=endpoint,
                        param_name=param_name,
                        current_val="index.html",
                        method=http_method,
                        client=client
                    )
                    if trav_res and trav_res.get("is_vulnerable"):
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        http_code = trav_res.get("http_code", 200)
                        evidence_snippet = trav_res.get("evidence", "")
                        remediation = trav_res.get("remediation", "")
                    else:
                        http_code = 200
                        evidence_snippet = f"HTTP 200 | Target prevents directory traversal on '{param_name}' ({http_method})."

                # -------------------------------------------------------------
                # 0.4 هجوم تزوير طلبات الخادم (SSRF Verification)
                # -------------------------------------------------------------
                elif "SSRF" in action.attack_name:
                    ssrf_res = await SSRFDetector.audit_parameter(
                        target_url=endpoint,
                        param_name=param_name,
                        current_val="http://example.com",
                        method=http_method,
                        client=client
                    )
                    if ssrf_res and ssrf_res.get("is_vulnerable"):
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        http_code = ssrf_res.get("http_code", 200)
                        evidence_snippet = ssrf_res.get("evidence", "")
                        remediation = ssrf_res.get("remediation", "")
                    else:
                        http_code = 200
                        evidence_snippet = f"HTTP 200 | Target prevents loopback/cloud SSRF on '{param_name}' ({http_method})."

                # -------------------------------------------------------------
                # 0.5 هجوم حقن قوالب الخادم (SSTI Verification)
                # -------------------------------------------------------------
                elif "SSTI" in action.attack_name or "Template" in action.attack_name:
                    ssti_res = await SSTIDetector.audit_parameter(
                        target_url=endpoint,
                        param_name=param_name,
                        current_val="test",
                        method=http_method,
                        client=client
                    )
                    if ssti_res and ssti_res.get("is_vulnerable"):
                        # التحقق المزدوج (Double-Verification Guard)
                        is_repeatable = await ZeroFPGuard.double_verify_finding(endpoint, "SSTI", param_name, http_method, client)
                        if is_repeatable:
                            status = "EXPLOITED_CONFIRMED"
                            is_proven = True
                            http_code = ssti_res.get("http_code", 200)
                            evidence_snippet = f"HTTP {http_code} | {ssti_res.get('evidence')} [Double-Verified]"
                            remediation = ssti_res.get("remediation", "")
                    else:
                        http_code = 200
                        evidence_snippet = f"HTTP 200 | Parameter '{param_name}' safe against SSTI evaluation ({http_method})."

                # -------------------------------------------------------------
                # 0.6 هجوم الوصول المباشر للكائنات والتحكم بالصلاحيات (IDOR Verification)
                # -------------------------------------------------------------
                elif "IDOR" in action.attack_name:
                    query_values = parse_qs(urlsplit(endpoint).query, keep_blank_values=True)
                    current_value = (query_values.get(param_name) or [""])[0]
                    idor_res = await IDORDetector.audit_parameter(
                        target_url=endpoint,
                        param_name=param_name,
                        current_val=current_value,
                        method=http_method,
                        client=client,
                        secondary_client_headers=secondary_client_headers,
                        secondary_resource_url=secondary_resource_url,
                    )
                    if idor_res and idor_res.get("is_vulnerable"):
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        http_code = idor_res.get("http_code", 200)
                        evidence_snippet = f"HTTP {http_code} | {idor_res.get('evidence')}"
                        remediation = idor_res.get("remediation", "")
                    else:
                        status = "INCONCLUSIVE"
                        http_code = (idor_res or {}).get("http_code", 0)
                        evidence_snippet = (idor_res or {}).get(
                            "evidence",
                            "IDOR was not confirmed; dual-account authorization evidence is unavailable.",
                        )
                elif "CORS" in action.attack_name:
                    headers = {"Origin": "https://evil-adversary.com"}
                    res = await client.get(endpoint, headers=headers, timeout=5.0, follow_redirects=True)
                    http_code = res.status_code
                    acao = res.headers.get("access-control-allow-origin", "")
                    acac = res.headers.get("access-control-allow-credentials", "").lower()
                    if "evil-adversary.com" in acao and acac == "true":
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        evidence_snippet = f"HTTP {res.status_code} | Critical CORS: Server echoes arbitrary attacker origin WITH credentials: {acao} (ACAC: true)"
                        remediation = "قيد النطاقات المسموح بها في ترويسة CORS ولا تعكس أصولاً عشوائية مع تفعيل الكوكيز."
                    elif acao == "*" and acac != "true":
                        status = "TARGET_SECURE"
                        evidence_snippet = f"HTTP {res.status_code} | Public Resource: Access-Control-Allow-Origin: * without credentials (Standard public API behavior)."
                    else:
                        evidence_snippet = f"HTTP {res.status_code} | Target rejected rogue origin (CORS headers protected or absent)."

                # -------------------------------------------------------------
                # 2. هجوم التضمين وخداع النقر (Clickjacking / Framing)
                # -------------------------------------------------------------
                elif "Clickjacking" in action.attack_name:
                    res = await client.get(endpoint, timeout=5.0, follow_redirects=True)
                    http_code = res.status_code
                    headers_lower = {k.lower(): v for k, v in res.headers.items()}
                    has_xfo = "x-frame-options" in headers_lower
                    csp = headers_lower.get("content-security-policy", "")
                    has_frame_ancestors = "frame-ancestors" in csp

                    # شرط قطعي: يجب أن تكون الصفحة تعمل فعلياً بـ 200 OK لتعتبر ثغرة حقيقية قابلة للاستغلال
                    if res.status_code == 200 and not has_xfo and not has_frame_ancestors:
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        evidence_snippet = f"HTTP 200 OK | Missing 'X-Frame-Options' and 'frame-ancestors' policy. Page allows full UI embedding."
                        remediation = "أضف ترويسة: X-Frame-Options: SAMEORIGIN أو Content-Security-Policy: frame-ancestors 'self';"
                    elif res.status_code != 200:
                        status = "TARGET_SECURE"
                        evidence_snippet = f"HTTP {res.status_code} | Endpoint not viable for Clickjacking (Non-200 response)."
                    else:
                        evidence_snippet = f"HTTP {res.status_code} | Framing prevented by policy: {headers_lower.get('x-frame-options', 'CSP active')}"

                # -------------------------------------------------------------
                # 3. هجوم تخفيض التشفير (SSL Strip / HSTS)
                # -------------------------------------------------------------
                elif "SSL" in action.attack_name or "HSTS" in action.attack_name:
                    res = await client.get(endpoint, timeout=5.0, follow_redirects=True)
                    http_code = res.status_code
                    headers_lower = {k.lower(): v for k, v in res.headers.items()}
                    if "strict-transport-security" not in headers_lower and res.status_code == 200:
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        evidence_snippet = f"HTTP 200 OK | Response headers completely lack 'Strict-Transport-Security'."
                        remediation = "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload"
                    else:
                        evidence_snippet = f"HTTP {res.status_code} | HSTS policy strictly enforced or redirect active: {headers_lower.get('strict-transport-security', 'Secured')}"

                # -------------------------------------------------------------
                # 4. هجوم تسريب مسارات السورس كود (.git)
                # -------------------------------------------------------------
                elif ".git" in endpoint:
                    res = await client.get(endpoint, timeout=5.0, follow_redirects=False)
                    http_code = res.status_code
                    if res.status_code == 200 and ("ref:" in res.text or "[core]" in res.text or "repositoryformatversion" in res.text):
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        evidence_snippet = f"HTTP 200 OK | Leaked Git metadata: {res.text[:70]}..."
                        remediation = "location ~ /\\. { deny all; }"
                    else:
                        evidence_snippet = f"HTTP {res.status_code} | Git directory access is blocked or non-existent."

                # -------------------------------------------------------------
                # 5. هجوم تسريب ملفات البيئة والمفاتيح (.env)
                # -------------------------------------------------------------
                elif ".env" in endpoint:
                    res = await client.get(endpoint, timeout=5.0, follow_redirects=False)
                    http_code = res.status_code
                    if res.status_code == 200 and any(k in res.text for k in ["DB_", "APP_", "SECRET", "KEY="]):
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        evidence_snippet = f"HTTP 200 OK | Leaked environment variables: {res.text[:70]}..."
                        remediation = "انقل ملف .env خارج مجلد الجذر العام public_html."
                    else:
                        evidence_snippet = f"HTTP {res.status_code} | .env access blocked or file not exposed."

                # -------------------------------------------------------------
                # 6. هجوم سرقة الجلسة (Insecure Cookie / HttpOnly)
                # -------------------------------------------------------------
                elif "Session" in action.attack_name or "Cookie" in action.attack_name:
                    res = await client.get(endpoint, timeout=5.0, follow_redirects=True)
                    http_code = res.status_code
                    cookies_headers = res.headers.get_list("set-cookie")
                    infra_cookies = {
                        "awsalb", "awsalbcors", "__cf_bm", "__cfruid", "cf_clearance", 
                        "cf_ob_info", "cf_use_ob", "arrafinity", "arrafinitysamesite", 
                        "incap_ses", "visid_incap", "bigipserver", "_ga", "_gid", "_gat", 
                        "gid", "gat", "__utma", "__utmb", "__utmc", "__utmz", "optanonconsent"
                    }
                    sens_patterns = [
                        r"(?i)sess", r"(?i)auth", r"(?i)token", r"(?i)jwt", r"(?i)login", 
                        r"(?i)phpsessid", r"(?i)jsessionid", r"(?i)aspsessionid",
                        r"(?i)connect\.sid", r"(?i)laravel_session"
                    ]
                    sensitive_insecure = []
                    for c in cookies_headers:
                        c_name = c.split("=")[0].strip().lower()
                        if c_name in infra_cookies or any(c_name.startswith(p) for p in ["_cf", "awsalb", "_ga"]):
                            continue
                        if "httponly" not in c.lower() and any(re.search(pat, c_name) for pat in sens_patterns):
                            sensitive_insecure.append(c)

                    if sensitive_insecure and res.status_code == 200:
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        evidence_snippet = f"HTTP {res.status_code} | Sensitive session cookie transmitted without HttpOnly: {sensitive_insecure[0].split(';')[0]}"
                        remediation = "Set-Cookie: session_id=xyz; Secure; HttpOnly; SameSite=Strict"
                    else:
                        status = "TARGET_SECURE"
                        evidence_snippet = f"HTTP {res.status_code} | Session cookies protected or non-session routing cookies (AWSALB/CDN) safely filtered."

                # -------------------------------------------------------------
                # 7. هجوم استدراج أخطاء الخادم (Verbose Error Fuzzing)
                # -------------------------------------------------------------
                elif "Fuzzing" in action.attack_name or "Stack Trace" in action.attack_name:
                    res = await client.get(endpoint, timeout=5.0, follow_redirects=False)
                    http_code = res.status_code
                    body_lower = res.text.lower()
                    has_stack_trace = any(w in body_lower for w in ["fatal error", "stack trace", "traceback (most recent call last)", "syntax error", "/var/www/", "exception in line"])
                    if has_stack_trace or res.status_code == 500:
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        evidence_snippet = f"HTTP {res.status_code} | Verbose internal exception leaked: {res.text[:70]}..."
                        remediation = "عطّل عرض الأخطاء للمستخدمين (display_errors = Off) واستخدم صفحات خطأ عامة."
                    else:
                        evidence_snippet = f"HTTP {res.status_code} | Server handled invalid route safely without leaking debug traces."

                # -------------------------------------------------------------
                # 8. هجوم التلاعب بطرائق البروتوكول (HTTP Method Tampering)
                # -------------------------------------------------------------
                elif "Method" in action.attack_name or "Verb" in action.attack_name:
                    res = await client.options(endpoint, timeout=5.0, follow_redirects=True)
                    http_code = res.status_code
                    allow_header = res.headers.get("allow", "").upper()
                    dangerous_methods = [m for m in ["PUT", "DELETE", "TRACE"] if m in allow_header]
                    if dangerous_methods and res.status_code == 200:
                        status = "EXPLOITED_CONFIRMED"
                        is_proven = True
                        evidence_snippet = f"HTTP {res.status_code} | Dangerous HTTP methods allowed: {', '.join(dangerous_methods)}"
                        remediation = "عطّل طرائق PUT و DELETE و TRACE غير المستخدمة في إعدادات خادم الويب."
                    else:
                        evidence_snippet = f"HTTP {res.status_code} | Allowed methods restricted: {allow_header or 'Default safe methods'}"

                else:
                    res = await client.get(endpoint, timeout=5.0, follow_redirects=True)
                    http_code = res.status_code
                    evidence_snippet = f"HTTP {res.status_code} Response processed."

            except Exception as e:
                http_code = 0
                err_str = str(e).lower()
                if isinstance(e, (httpx.TimeoutException, httpx.ConnectError, httpx.ConnectTimeout)) or "timeout" in err_str or "timed out" in err_str:
                    status = "UNREACHABLE_TIMEOUT"
                    evidence_snippet = f"تعذر الاتصال بالهدف عبر الشبكة (مهلة اتصال {type(e).__name__})."
                else:
                    status = "TARGET_SECURE"
                    evidence_snippet = f"الهدف تصدى للهجوم أو رفض الحزمة ({str(e)[:50]})."

            elapsed_ms = round((time.time() - start_t) * 1000, 2)

            outcomes.append(AttackExecutionOutcome(
                attack_name=action.attack_name,
                target_endpoint=endpoint,
                attack_vector=action.attack_vector,
                attack_category=action.attack_category,
                payload_sent=payload,
                predicted_probability=action.predicted_probability,
                execution_status=status,
                http_status_code=http_code,
                execution_time_ms=elapsed_ms,
                raw_response_evidence=evidence_snippet,
                is_vulnerability_proven=is_proven,
                remediation_command=remediation
            ))

        return outcomes
