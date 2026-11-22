"""
Baseera Sec - AI Attack Strategist & Comprehensive Multi-Vector Synthesizer
المرحلة 4: العقل المخطط - يرشح وينتج مصفوفة متكاملة من الهجمات المستهدفة والعدائية الحديثة
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any
from core.engine.models import TechFingerprint, ReconFinding

@dataclass
class TargetedAttackAction:
    attack_name: str
    target_endpoint: str
    attack_vector: str
    attack_category: str          # "Adversarial", "Session/Auth", "Protocol", "Data Leak"
    predicted_probability: float  # نسبة النجاح المتوقعة
    test_payload: str             # الحمولة الذكية المصممة للاختبار
    success_criteria: str         # شرط التأكد من نجاح الهجوم
    description: str
    http_method: str = "GET"
    param_name: str = ""
    is_form_input: bool = False

@dataclass
class AttackStrategyResult:
    model_used: str
    strategy_summary: str
    actions: List[TargetedAttackAction] = field(default_factory=list)

class LocalAttackAgent:
    async def synthesize_targeted_attacks(
        self,
        target_url: str,
        fingerprint: TechFingerprint,
        recon_findings: List[ReconFinding],
        surface: Any = None
    ) -> AttackStrategyResult:
        """
        يولد مصفوفة هجمات ذكية وشاملة مخصصة لسياق الهدف ونقاط الإدخال المكتشفة
        تشمل هجمات حقن قواعد البيانات (SQLi)، حقن السكريبتات (XSS)، والهجمات العدائية الحديثة
        """
        base = target_url.rstrip('/')
        actions: List[TargetedAttackAction] = []

        # -------------------------------------------------------------
        # المسار 0: هجمات حقن المعاملات المكتشفة حياً (SQL Injection & XSS)
        # -------------------------------------------------------------
        if surface and hasattr(surface, "injection_points") and surface.injection_points:
            # تجاهل معاملات الأطر الداخلية مثل ASP.NET ViewState لمنع تشتيت الفحص
            ignored_params = {
                "__viewstate", "__viewstategenerator", "__eventvalidation", 
                "__eventtarget", "__eventargument", "__lastfocus", "csrf_token", 
                "authenticity_token", "_csrf", "xsrf_token"
            }
            
            # ترتيب المعاملات بالأولوية (المعاملات عالية الخطورة أولاً: id, user, pass, query, file...)
            high_value_keywords = [
                "id", "user", "uid", "uname", "login", "pass", "password", "pwd",
                "artist", "cat", "category", "query", "q", "search", "content",
                "page", "file", "url", "email", "comment", "msg", "text", "newsad"
            ]

            def param_priority(ip):
                name = ip.param_name.lower()
                if name in ignored_params or name.startswith("__"):
                    return 999
                for idx, kw in enumerate(high_value_keywords):
                    if kw in name:
                        return idx
                return 100

            valid_points = [
                p for p in surface.injection_points 
                if p.param_name.lower() not in ignored_params and not p.param_name.startswith("__")
            ]
            valid_points.sort(key=param_priority)

            for p in valid_points[:25]: # فحص أهم نقاط الإدخال الحقيقية بالزاحف الذكي
                p_lower = p.param_name.lower()
                p_method = getattr(p, "method", "GET").upper()
                method_tag = f" [{p_method}]" if p_method == "POST" else ""

                # 1. SQL Injection (Error, Boolean differential, and Auth Bypass)
                is_auth_field = any(k in p_lower for k in ["uid", "user", "uname", "login", "pass", "pwd", "auth"])
                attack_title = (
                    f"هجوم تجاوز المصادقة وقواعد البيانات (SQL Injection Auth Bypass - Parameter: {p.param_name}){method_tag}"
                    if is_auth_field and p.is_form_input
                    else f"هجوم حقن قواعد البيانات (SQL Injection - Parameter: {p.param_name}){method_tag}"
                )

                actions.append(TargetedAttackAction(
                    attack_name=attack_title,
                    target_endpoint=p.target_url or target_url,
                    attack_vector=f"Input Parameter SQL Injection ({p.param_name} via {p_method})",
                    attack_category="Database Injection",
                    predicted_probability=0.96,
                    test_payload=f"{p.param_name}={p.original_value}' (Error & Boolean & Auth bypass)",
                    success_criteria="Server leaks DBMS syntax error, exhibits boolean differential, or bypasses login",
                    description=f"اختبار إمكانية حقن أوامر SQL داخل المعامل `{p.param_name}` باستعمال {p_method}.",
                    http_method=p_method,
                    param_name=p.param_name,
                    is_form_input=p.is_form_input
                ))
                # 2. Reflected XSS
                actions.append(TargetedAttackAction(
                    attack_name=f"هجوم حقن السكريبتات عبر المتصفح (Reflected XSS - Parameter: {p.param_name}){method_tag}",
                    target_endpoint=p.target_url or target_url,
                    attack_vector=f"Reflected DOM Injection ({p.param_name} via {p_method})",
                    attack_category="Client-Side Injection",
                    predicted_probability=0.88,
                    test_payload=f"{p.param_name}=<baseeraXSS731>",
                    success_criteria="Server reflects unescaped HTML tags in response body",
                    description=f"التحقق من إمكانية تنفيذ سكريبتات ضارة في متصفح الزائر عبر المعامل `{p.param_name}`.",
                    http_method=p_method,
                    param_name=p.param_name,
                    is_form_input=p.is_form_input
                ))
                # 3. Command Injection
                if any(k in p_lower for k in ["cmd", "ip", "host", "ping", "exec", "command", "process", "test"]):
                    actions.append(TargetedAttackAction(
                        attack_name=f"هجوم حقن أوامر النظام (Command Injection - Parameter: {p.param_name}){method_tag}",
                        target_endpoint=p.target_url or target_url,
                        attack_vector=f"OS Command Injection ({p.param_name} via {p_method})",
                        attack_category="System Injection",
                        predicted_probability=0.92,
                        test_payload=f"{p.param_name}=; id",
                        success_criteria="Server executes OS command and leaks output",
                        description=f"التحقق من تنفيذ أوامر النظام عبر المعامل `{p.param_name}`.",
                        http_method=p_method,
                        param_name=p.param_name,
                        is_form_input=p.is_form_input
                    ))
                # 4. Path Traversal / LFI
                if any(k in p_lower for k in ["file", "path", "page", "doc", "view", "template", "include", "read", "newsad"]):
                    actions.append(TargetedAttackAction(
                        attack_name=f"هجوم تخطي المسارات واستعراض الملفات (Path Traversal - Parameter: {p.param_name}){method_tag}",
                        target_endpoint=p.target_url or target_url,
                        attack_vector=f"Directory Traversal ({p.param_name} via {p_method})",
                        attack_category="Access Control Bypass",
                        predicted_probability=0.90,
                        test_payload=f"{p.param_name}=../../../../etc/passwd",
                        success_criteria="Server leaks /etc/passwd or win.ini system files",
                        description=f"التحقق من إمكانية قراءة ملفات النظام عبر المعامل `{p.param_name}`.",
                        http_method=p_method,
                        param_name=p.param_name,
                        is_form_input=p.is_form_input
                    ))
                # 5. SSRF
                if any(k in p_lower for k in ["url", "link", "dest", "redirect", "feed", "fetch", "site", "domain"]):
                    actions.append(TargetedAttackAction(
                        attack_name=f"هجوم تزوير طلبات الخادم (SSRF - Parameter: {p.param_name}){method_tag}",
                        target_endpoint=p.target_url or target_url,
                        attack_vector=f"Server-Side Request Forgery ({p.param_name} via {p_method})",
                        attack_category="Server Injection",
                        predicted_probability=0.89,
                        test_payload=f"{p.param_name}=http://169.254.169.254/latest/meta-data/",
                        success_criteria="Server fetches internal cloud metadata or local loopback service",
                        description=f"التحقق من استدراج الخادم لطلب عناوين داخلية عبر المعامل `{p.param_name}`.",
                        http_method=p_method,
                        param_name=p.param_name,
                        is_form_input=p.is_form_input
                    ))
                # 6. SSTI (Server-Side Template Injection)
                if any(k in p_lower for k in ["name", "template", "view", "render", "msg", "text", "comment", "q", "query", "search", "title", "preview", "email"]):
                    actions.append(TargetedAttackAction(
                        attack_name=f"هجوم حقن قوالب الخادم (SSTI - Parameter: {p.param_name}){method_tag}",
                        target_endpoint=p.target_url or target_url,
                        attack_vector=f"Server-Side Template Injection ({p.param_name} via {p_method})",
                        attack_category="Template Injection",
                        predicted_probability=0.87,
                        test_payload=f"{p.param_name}=baseera{{{{7*7}}}}sec",
                        success_criteria="Server evaluates math expression inside template engine returning '49'",
                        description=f"التحقق من إمكانية تنفيذ أكواد برمجية في محرك القوالب عبر المعامل `{p.param_name}`.",
                        http_method=p_method,
                        param_name=p.param_name,
                        is_form_input=p.is_form_input
                    ))
                # 7. IDOR / Broken Access Control
                if any(k in p_lower for k in ["id", "user", "account", "order", "profile", "doc", "file", "invoice"]):
                    actions.append(TargetedAttackAction(
                        attack_name=f"هجوم الوصول المباشر للكائنات (IDOR - Parameter: {p.param_name}){method_tag}",
                        target_endpoint=p.target_url or target_url,
                        attack_vector=f"Insecure Direct Object Reference ({p.param_name} via {p_method})",
                        attack_category="Access Control Bypass",
                        predicted_probability=0.89,
                        test_payload=f"{p.param_name}=2 (Alternative Object ID Testing)",
                        success_criteria="Server leaks unauthorized object data without permission checks",
                        description=f"التحقق من الوصول لسجلات مستخدمين آخرين عبر تعديل المعامل `{p.param_name}`.",
                        http_method=p_method,
                        param_name=p.param_name,
                        is_form_input=p.is_form_input
                    ))

        # -------------------------------------------------------------
        # المسار 1: الهجمات العدائية الحديثة وإعدادات النطاق المتقاطع (CORS & Framing)
        # -------------------------------------------------------------
        actions.append(TargetedAttackAction(
            attack_name="هجوم استغلال CORS المضلل (Adversarial CORS Origin Spoofing)",
            target_endpoint=base,
            attack_vector="CORS Arbitrary Origin Reflection",
            attack_category="Adversarial Attack",
            predicted_probability=0.88,
            test_payload="Origin: https://evil-adversary.com | Access-Control-Request-Method: GET",
            success_criteria="Access-Control-Allow-Origin echoes evil-adversary or allows credentials",
            description="محاكاة هجوم عدائي حديث لاختراق سياق النطاق وسرقة بيانات الجلسة عبر مواقع وسيطة."
        ))

        actions.append(TargetedAttackAction(
            attack_name="هجوم التضمين وخداع النقر (Clickjacking / UI Redressing)",
            target_endpoint=base,
            attack_vector="Missing X-Frame-Options & CSP Frame Ancestors",
            attack_category="Adversarial Attack",
            predicted_probability=0.92,
            test_payload="[Framing Test] Proof-of-concept embedding check on target URL",
            success_criteria="Page responds with HTTP 200 without X-Frame-Options or frame-ancestors restrictions",
            description="اختبار إمكانية استنساخ وتضمين واجهة الموقع داخل إطار خفي لخداع المستخدمين وسرقة نقراتهم."
        ))

        # -------------------------------------------------------------
        # المسار 2: هجمات البروتوكول وتخفيض التشفير (Protocol Downgrade)
        # -------------------------------------------------------------
        http_target = base.replace("https://", "http://") if "https://" in base else base
        actions.append(TargetedAttackAction(
            attack_name="محاكاة تخفيض التشفير والتنصت (SSL Strip / Cleartext Downgrade)",
            target_endpoint=http_target,
            attack_vector="Missing HSTS & Insecure Transport",
            attack_category="Protocol Attack",
            predicted_probability=0.85,
            test_payload="HEAD / HTTP/1.1 (Without HTTPS upgrade enforcement)",
            success_criteria="Server allows HTTP unencrypted access or lacks Strict-Transport-Security",
            description="محاكاة اعتراض اتصالات المستخدمين في الشبكات العامة وتنصت المهاجم على البيانات غير المشفرة."
        ))

        # -------------------------------------------------------------
        # المسار 3: هجمات تسريب الأسرار وسحب السورس كود (Secrets Exfiltration)
        # -------------------------------------------------------------
        actions.append(TargetedAttackAction(
            attack_name="استغلال تسريب مستودع الأكواد المصدري (.git Source Code Probe)",
            target_endpoint=f"{base}/.git/HEAD",
            attack_vector="Direct Source Code Repository Disclosure",
            attack_category="Data Leak",
            predicted_probability=0.78,
            test_payload="GET /.git/HEAD HTTP/1.1",
            success_criteria="HTTP 200 containing 'ref: refs/heads/' git signature",
            description="فحص عدائي لمسار التحكم بالنسخ لمحاولة تنزيل السورس كود الداخلي وسجلات المطورين."
        ))

        actions.append(TargetedAttackAction(
            attack_name="محاكاة استخراج أسرار البيئة ومفاتيح الربط (.env Secrets Leak)",
            target_endpoint=f"{base}/.env",
            attack_vector="Environment Configuration Disclosure",
            attack_category="Data Leak",
            predicted_probability=0.75,
            test_payload="GET /.env HTTP/1.1",
            success_criteria="HTTP 200 containing DB_, APP_KEY, or SECRET configuration tokens",
            description="محاولة سحب ملفات المتغيرات الحساسة التي قد تكشف كلمات مرور قواعد البيانات وواجهات API."
        ))

        # -------------------------------------------------------------
        # المسار 4: هجمات الجلسات وسرقة الكوكيز (Session Hijacking)
        # -------------------------------------------------------------
        actions.append(TargetedAttackAction(
            attack_name="محاكاة سرقة الجلسة عبر السكريبتات (Insecure Cookie / DOM Session Hijacking)",
            target_endpoint=base,
            attack_vector="Missing HttpOnly & Lax SameSite Protection",
            attack_category="Session/Auth",
            predicted_probability=0.90,
            test_payload="[Cookie Audit] Checking HttpOnly & Secure flags in Set-Cookie headers",
            success_criteria="Session cookie transmitted without HttpOnly or Secure flags",
            description="التحقق مما إذا كانت ملفات تعريف الارتباط عرضة للسرقة من خلال استغلال متصفح الضحية."
        ))

        # -------------------------------------------------------------
        # المسار 5: هجمات استدراج أخطاء الخادم (Adversarial Error & Stack Trace Fuzzing)
        # -------------------------------------------------------------
        actions.append(TargetedAttackAction(
            attack_name="هجوم استدراج أخطاء الخادم وكشف الـ Stack Trace (Verbose Error Fuzzing)",
            target_endpoint=f"{base}/%%invalid_path_probe_baseera%%",
            attack_vector="Information Disclosure via Unhandled Exceptions",
            attack_category="Adversarial Attack",
            predicted_probability=0.82,
            test_payload="GET /%00%27%22-- HTTP/1.1",
            success_criteria="Server leaks internal file paths, framework traces, or debug information",
            description="إرسال طلبات معدلة وشاذة عمداً لمعرفة هل يفصح الخادم عن بنيته التحتية وأخطائه البرمجية."
        ))

        # -------------------------------------------------------------
        # المسار 6: فحص الأفعال والطرائق غير الآمنة (Dangerous HTTP Verb Tampering)
        # -------------------------------------------------------------
        actions.append(TargetedAttackAction(
            attack_name="هجوم التلاعب بطرائق البروتوكول (HTTP Method / Verb Tampering)",
            target_endpoint=base,
            attack_vector="Insecure HTTP Methods (PUT / DELETE / TRACK)",
            attack_category="Protocol Attack",
            predicted_probability=0.70,
            test_payload="OPTIONS / HTTP/1.1",
            success_criteria="Allow header contains dangerous methods like PUT, DELETE, or TRACE",
            description="التحقق من إمكانية تنفيذ عمليات غير مصرح بها أو رفع ملفات في حال بقاء أوامر HTTP الخطيرة مفعلة."
        ))

        summary = (
            f"بناءً على فهم نوع وسياق الهدف ({fingerprint.inferred_site_type})، "
            f"قام العقل الذكي (AI Attack Strategist) بتوليد مصفوفة هجومية متكاملة تضم {len(actions)} هجمات نوعية."
        )

        return AttackStrategyResult(
            model_used="Baseera AI Attack Strategist (Adaptive Multi-Vector Cognitive Engine)",
            strategy_summary=summary,
            actions=actions
        )
