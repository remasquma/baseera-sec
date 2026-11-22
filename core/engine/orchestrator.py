"""Coordinate Baseera Sec's local scanning and verification stages."""
import time
import asyncio
from typing import Dict, Any, Callable, List, Optional
from config.settings import AuditConfig
from core.engine.models import AuditReport, VerifiedVulnerability, SeverityLevel, ReconFinding
from core.recon.headers.header_auditor import HeaderAuditor
from core.recon.sessions.session_auditor import SessionAuditor
from core.recon.crawler.path_crawler import PathCrawler
from core.verifier.engine.proof_validator import ProofValidator
from core.verifier.engine.attack_executor import AttackExecutor
from core.ai.attack_agent import LocalAttackAgent
from core.ai.local_forensic_advisor import LocalForensicAdvisor
from core.ai.local_tech_analyzer import LocalTechAnalyzer
from core.ai.local_model_analyzer import local_ai_classifier
from core.reporting.cvss.calculator import CVSSCalculator
from core.recon.crawler.deep_spider import DeepSpider
from core.auth.auth_manager import AuthManager
from core.recon.api.api_parser import APISchemaParser
from core.recon.crawler.headless_spider import HeadlessBrowserCrawler
from core.network.request_gateway import GatewayAsyncClient, RequestGateway


def _local_ai_findings(ai_score: Dict[str, Any]) -> List[ReconFinding]:
    findings = []
    rule_signals = ai_score.get("rule_based_signals") or []
    if rule_signals:
        findings.append(ReconFinding(
            category="anomaly",
            title="إشارات نمطية مكتشفة بواسطة التحليل القائم على القواعد",
            description="رصد التحليل القائم على القواعد أنماطًا مطابقة لمؤشرات كشف محددة؛ لا تمثل هذه الإشارات نتيجة نموذج عصبي.",
            evidence=f"Rule-based signals: {rule_signals}",
            risk_indicator="high"
        ))
    return findings


class AuditOrchestrator:
    def __init__(self, config: AuditConfig = None):
        self.config = config or AuditConfig()
        self.attack_agent = LocalAttackAgent()
        self.local_advisor = LocalForensicAdvisor()
        self.local_tech_analyzer = LocalTechAnalyzer()

    async def run_full_audit(
        self,
        target_url: str,
        progress_callback: Callable[[str, int], None] = None,
        auth_config: Optional[Any] = None,
        api_spec_content: Optional[str] = None,
        secondary_auth_headers: Optional[Dict[str, str]] = None,
        secondary_resource_url: Optional[str] = None,
    ) -> AuditReport:
        """
        تشغيل الفحص مع التحليل المحلي والمصادقة الاختيارية.
        """
        start_time = time.time()
        scan_id = f"SCAN-{int(start_time)}"
        
        def notify(stage: str, percent: int):
            if progress_callback:
                progress_callback(stage, percent)

        # تهيئة مدير المصادقة وحقن الترويسات
        auth_mgr = AuthManager(auth_config)
        client_headers = {"User-Agent": self.config.user_agent}
        client_headers = auth_mgr.inject_auth_headers(client_headers)

        # 1. الاتصال الأولي وسحب المحتوى
        notify("الاتصال بالهدف والتحقق من التوافر...", 10)
        headers = {}
        html = ""
        cookies = []
        response_url = target_url
        
        # TLS verification enabled by default (Finding F-05 resolved)
        verify_ssl = not getattr(self.config, "allow_insecure_tls", False)
        gateway = RequestGateway(
            target_url,
            allowed_domains=self.config.allowed_domains,
            allow_internal_targets=self.config.allow_internal_targets,
            allow_insecure_tls=not verify_ssl,
            default_timeout=self.config.request_timeout,
            max_concurrency=self.config.max_concurrent_requests,
            user_agent=self.config.user_agent,
        )
        async with GatewayAsyncClient(gateway, headers=client_headers) as client:
            # تنفيذ المصادقة الآلية للنماذج إن وجدت
            if auth_mgr.config.auth_type.lower() == "form_login":
                notify("تنفيذ تسجيل الدخول الآلي وحفظ الجلسة المصادقة...", 14)
                await auth_mgr.perform_initial_auth(client)
                client_headers = auth_mgr.inject_auth_headers(client_headers)
                client.headers.update(client_headers)

            try:
                res = await client.get(target_url, timeout=self.config.request_timeout, follow_redirects=True)
                # ترقية تلقائية إلى HTTPS إذا كان المنفذ غير القياسي (مثل :81 أو :8443) يعمل ببروتوكول مشفر
                if res.status_code == 400 and ("https port" in res.text.lower() or "plain http" in res.text.lower()):
                    target_url = target_url.replace("http://", "https://")
                    res = await client.get(target_url, timeout=self.config.request_timeout, follow_redirects=True)
                headers = dict(res.headers)
                html = res.text
                cookies = res.headers.get_list("set-cookie")
                response_url = str(res.url)
            except Exception:
                if target_url.startswith("http://"):
                    try:
                        https_candidate = target_url.replace("http://", "https://")
                        res = await client.get(https_candidate, timeout=self.config.request_timeout, follow_redirects=True)
                        target_url = https_candidate
                        headers = dict(res.headers)
                        html = res.text
                        cookies = res.headers.get_list("set-cookie")
                        response_url = str(res.url)
                    except Exception:
                        pass

            # المرحلة 1: كشف الهوية والتقنيات من الاستجابة
            notify("المرحلة 1: كشف الهوية والتقنيات المخفية بالذكاء الاصطناعي...", 20)
            
            fingerprint = await self.local_tech_analyzer.classify_deep_tech(
                target_url, headers, html
            )

            # المرحلة 2: بناء خطة الفحص التكيفية
            notify(f"المرحلة 2: توليد خطة الفحص المخصصة لـ ({fingerprint.inferred_site_type})...", 35)
            await asyncio.sleep(0.2)

            # المرحلة 3: الفحص والتدقيق العميق + كشف الشذوذ السلوكي
            notify("المرحلة 3: فحص الجلسات والمسارات وكشف الشذوذ السلوكي المنطقي...", 50)
            recon_findings = []
            
            if self.config.check_headers:
                recon_findings.extend(HeaderAuditor.audit(headers, response_url))

            if self.config.check_sessions_and_tokens:
                recon_findings.extend(SessionAuditor.audit_cookies(cookies))
                recon_findings.extend(SessionAuditor.audit_tokens(target_url, headers, html))

            # فحص المسارات
            probe_logs = []
            if self.config.check_hidden_paths:
                path_findings = await PathCrawler.probe_paths(target_url, client)
                recon_findings.extend(path_findings)
                # تسجيل بيانات الردود لتحليل الشذوذ
                for pf in path_findings:
                    probe_logs.append({
                        "path": pf.title,
                        "evidence": pf.evidence,
                        "risk": pf.risk_indicator
                    })

            # المهمة 2: كشف الشذوذ بواسطة مجموعة نماذج Nazzoor المحلية
            ai_score = local_ai_classifier.score_text(html[:3000] if html else target_url)
            recon_findings.extend(_local_ai_findings(ai_score))

            anomalies = await self.local_tech_analyzer.analyze_behavioral_anomalies(
                target_url, probe_logs
            )
            recon_findings.extend(anomalies)

            # المرحلة 4: استكشاف نقاط الإدخال والزحف العميق عبر الصفحات والنماذج
            notify("المرحلة 4: تشغيل الزاحف الذكي لاستكشاف كافة الصفحات والنماذج ومعاملات الموقع...", 60)
            spider = DeepSpider(target_url, max_pages=30, max_depth=3)
            surface = await spider.crawl(client)

            # تسجيل أي ثغرة تصفح مجلدات Directory Listing تم اكتشافها أثناء الزحف
            for dl in spider.directory_listing_findings:
                recon_findings.append(ReconFinding(
                    category="directory_listing",
                    title="تصفح مفتوح لمجلدات الخادم (Directory Listing Disclosed)",
                    description=f"الخادم يسمح بتصفح واستعراض محتويات المجلدات ({dl['url']}) مما يعرض الملفات الداخلية للتحميل.",
                    evidence=dl["evidence"],
                    risk_indicator="medium"
                ))

            # تسجيل نقاط نهاية ووردبريس المكشوفة (CMS Probing)
            for wf in getattr(spider, "wordpress_findings", []):
                recon_findings.append(ReconFinding(
                    category="cms",
                    title=wf["title"],
                    description="تم رصد نقطة نهاية ووردبريس مكشوفة تسمح بتسريب أسماء المستخدمين أو هجمات التخمين.",
                    evidence=wf["evidence"],
                    risk_indicator="medium"
                ))

            # استيراد وتحليل مواصفات الـ APIs (OpenAPI / Swagger / Postman / GraphQL)
            if api_spec_content:
                notify("استيراد وتحليل مواصفات الـ API وتوليد نقاط الحقن...", 63)
                api_points = APISchemaParser.parse_schema_content(api_spec_content, target_url)
                for ap in api_points:
                    surface.injection_points.append(ap)
                    if ap.target_url not in surface.discovered_links:
                        surface.discovered_links.append(ap.target_url)

            # الزحف الديناميكي لتطبيقات الـ SPAs عبر المتصفح الخفي (Headless Browser)
            if HeadlessBrowserCrawler.is_headless_available():
                notify("تشغيل المتصفح الخفي (Headless Chrome) لتصيير تطبيقات SPAs واستخراج العناصر التفاعلية...", 66)
                spa_data = await HeadlessBrowserCrawler.crawl_spa_page(target_url)
                for sp_p in spa_data.get("injection_points", []):
                    if not any(ip.param_name == sp_p.param_name and ip.target_url == sp_p.target_url for ip in surface.injection_points):
                        surface.injection_points.append(sp_p)
                for sp_link in spa_data.get("links", []):
                    if sp_link not in surface.discovered_links:
                        surface.discovered_links.append(sp_link)

            if surface.injection_points:
                notify(f"المرحلة 4: تم اكتشاف {len(surface.injection_points)} نقطة إدخال عبر صفحات الموقع؛ ترشيح حمولات الفحص...", 68)
            else:
                notify("المرحلة 4: ترشيح مصفوفة الهجمات العدائية المتوافقة مع سياق الهدف...", 68)

            attack_strategy = await self.attack_agent.synthesize_targeted_attacks(
                target_url, fingerprint, recon_findings, surface=surface
            )

            # المرحلة 5: [التنفيذ الفعلي] إطلاق مصفوفة الهجمات عبر الشبكة وتأكيد الـ PoC
            notify(f"المرحلة 5: [تنفيذ فعلي] إطلاق {len(attack_strategy.actions)} هجمات نوعية وحقن حقيقي للحمولات...", 80)
            attack_outcomes = await AttackExecutor.execute_attacks(
                attack_strategy.actions,
                client,
                secondary_client_headers=secondary_auth_headers,
                secondary_resource_url=secondary_resource_url,
            )

            # جمع الثغرات المؤكدة قطيعاً
            verified_vulns = ProofValidator.verify_findings(recon_findings, target_url)

            # إضافة ثغرات DOM-Based XSS المكتشفة في أكواد الـ JavaScript
            for dx in spider.dom_xss_findings:
                if not any("DOM-Based XSS" in v.title for v in verified_vulns):
                    script_loc = str(dx.get('script') or dx['url'])
                    import re
                    url_m = re.search(r'https?://[^\s\'"<>]+', script_loc)
                    clean_script_url = url_m.group(0) if url_m else target_url

                    verified_vulns.append(VerifiedVulnerability(
                        vuln_id=f"BASEERA-DOMXSS-{len(verified_vulns)+1:03d}",
                        title="ثغرة حقن السكريبتات عبر واجهة المتصفح (DOM-Based XSS)",
                        cwe_id="CWE-79",
                        owasp_category="A03:2021-Injection",
                        severity=SeverityLevel.HIGH,
                        cvss_score=7.3,
                        confidence_score=0.98,
                        description="تم رصد تدفق لبيانات غير مفلترة من مدخلات DOM (location.search/hash) مباشرة إلى دوال التنفيذ في المتصفح.",
                        poc_evidence=f"DOM Flow: {dx['evidence']}",
                        attack_vector="Client-Side DOM Injection",
                        remediation_guide="استخدم مكتبات تنقية موثوقة مثل DOMPurify وتجنب استخدام innerHTML أو document.write.",
                        affected_url=clean_script_url
                    ))

            # إضافة أي هجوم إضافي أثبته محرك التنفيذ المباشر (مثل SQLi أو XSS) مع منع التكرار التام
            for outcome in attack_outcomes:
                if outcome.is_vulnerability_proven:
                    # فحص منع التكرار: عدم تكرار HSTS أو Clickjacking أو CORS
                    if "SSL" in outcome.attack_name or "HSTS" in outcome.attack_name:
                        if any("HSTS" in v.title or v.cwe_id == "CWE-319" for v in verified_vulns):
                            continue
                    if "Clickjacking" in outcome.attack_name:
                        if any("Clickjacking" in v.title or v.cwe_id == "CWE-1021" for v in verified_vulns):
                            continue
                    if "CORS" in outcome.attack_name:
                        if any("CORS" in v.title or v.cwe_id == "CWE-942" for v in verified_vulns):
                            continue

                    if not any(v.title == outcome.attack_name for v in verified_vulns):
                        # تحديد المعايير القياسية بدقة لكل نوع ثغرة
                        if "SQL Injection" in outcome.attack_name:
                            cwe = "CWE-89"
                            owasp = "A03:2021-Injection"
                            sev = SeverityLevel.CRITICAL
                            cvss = 9.8
                        elif "Reflected XSS" in outcome.attack_name or "XSS" in outcome.attack_name:
                            cwe = "CWE-79"
                            owasp = "A03:2021-Injection"
                            sev = SeverityLevel.HIGH
                            cvss = 7.5
                        elif "Command Injection" in outcome.attack_name or "CMDi" in outcome.attack_name:
                            cwe = "CWE-78"
                            owasp = "A03:2021-Injection"
                            sev = SeverityLevel.CRITICAL
                            cvss = 9.8
                        elif "Path Traversal" in outcome.attack_name or "LFI" in outcome.attack_name:
                            cwe = "CWE-22"
                            owasp = "A01:2021-Broken Access Control"
                            sev = SeverityLevel.HIGH
                            cvss = 8.5
                        elif "SSRF" in outcome.attack_name:
                            cwe = "CWE-918"
                            owasp = "A10:2021-Server-Side Request Forgery"
                            sev = SeverityLevel.HIGH
                            cvss = 8.6
                        elif "CORS" in outcome.attack_name:
                            cwe = "CWE-942"
                            owasp = "A05:2021-Security Misconfiguration"
                            sev = SeverityLevel.HIGH
                            cvss = 7.8
                        elif "Clickjacking" in outcome.attack_name:
                            cwe = "CWE-1021"
                            owasp = "A05:2021-Security Misconfiguration"
                            sev = SeverityLevel.MEDIUM
                            cvss = 6.1
                        elif ".git" in outcome.attack_name or ".env" in outcome.attack_name:
                            cwe = "CWE-552"
                            owasp = "A05:2021-Security Misconfiguration"
                            sev = SeverityLevel.HIGH
                            cvss = 8.6
                        elif "SSTI" in outcome.attack_name or "Template" in outcome.attack_name:
                            cwe = "CWE-1336"
                            owasp = "A03:2021-Injection"
                            sev = SeverityLevel.CRITICAL
                            cvss = 9.8
                        elif "IDOR" in outcome.attack_name:
                            cwe = "CWE-639"
                            owasp = "A01:2021-Broken Access Control"
                            sev = SeverityLevel.HIGH
                            cvss = 8.5
                        else:
                            cwe = "CWE-749" if "Method" in outcome.attack_name else "CWE-693"
                            owasp = "A05:2021-Security Misconfiguration"
                            sev = SeverityLevel.LOW
                            cvss = 4.0

                        verified_vulns.append(VerifiedVulnerability(
                            vuln_id=f"BASEERA-LIVE-{len(verified_vulns)+1:03d}",
                            title=outcome.attack_name,
                            cwe_id=cwe,
                            owasp_category=owasp,
                            severity=sev,
                            cvss_score=cvss,
                            confidence_score=1.0,
                            description=f"تم إثبات نجاح الهجوم عملياً واستخراج دليل استجابة قطعي: {outcome.raw_response_evidence}",
                            poc_evidence=f"Payload Sent: {outcome.payload_sent} -> Response Proof: {outcome.raw_response_evidence}",
                            attack_vector=outcome.attack_vector,
                            remediation_guide=outcome.remediation_command,
                            affected_url=outcome.target_endpoint
                        ))

            # حساب مؤشر الخطورة CVSS المحدث
            overall_risk = CVSSCalculator.calculate_overall_risk(verified_vulns)

            # المرحلة 6: صياغة التقرير الجنائي بالذكاء الاصطناعي
            notify("المرحلة 6: استدعاء الذكاء الاصطناعي لصياغة التقرير الجنائي النهائي...", 90)
            ai_result = await self.local_advisor.generate_forensic_consultation(
                target_url, fingerprint, verified_vulns
            )

        end_time = time.time()
        notify("اكتمل الفحص وتنفيذ الهجمات بنجاح!", 100)

        targeted_actions_dicts = [
            {
                "attack_name": a.attack_name,
                "target_endpoint": a.target_endpoint,
                "vector": a.attack_vector,
                "category": a.attack_category,
                "probability": a.predicted_probability,
                "payload": a.test_payload,
                "criteria": a.success_criteria,
                "desc": a.description
            }
            for a in attack_strategy.actions
        ]

        executed_outcomes_dicts = [
            {
                "attack_name": o.attack_name,
                "target_endpoint": o.target_endpoint,
                "vector": o.attack_vector,
                "category": o.attack_category,
                "payload": o.payload_sent,
                "status": o.execution_status,
                "http_code": o.http_status_code,
                "time_ms": o.execution_time_ms,
                "evidence": o.raw_response_evidence,
                "proven": o.is_vulnerability_proven,
                "remediation": o.remediation_command
            }
            for o in attack_outcomes
        ]

        # تحديد اسم المحرك المستخدم في الواجهة
        engine_label = (
            "Hanadi Nazzoor AI Ensemble (CodeBERT + DistilRoBERTa + TF-IDF/LightGBM)"
            if local_ai_classifier.is_loaded
            else "Hanadi Nazzoor AI Ensemble (Partial / Heuristic Fallback)"
        )
        report = AuditReport(
            target_url=target_url,
            scan_id=scan_id,
            start_time=start_time,
            end_time=end_time,
            total_duration_seconds=round(end_time - start_time, 2),
            fingerprint=fingerprint,
            recon_findings=recon_findings,
            targeted_attack_plan=targeted_actions_dicts,
            attack_execution_results=executed_outcomes_dicts,
            verified_vulnerabilities=verified_vulns,
            overall_risk_score=overall_risk,
            executive_summary=ai_result.get("executive_summary", ""),
            forensic_attack_chain=fingerprint.common_attack_vectors,
            attack_model_used=engine_label,
            generated_by=f"Baseera Sec Engine ({ai_result.get('engine_used', 'Hybrid')})"
        )
        return report
