"""
Baseera Sec local forensic advisor.
Generates executive summaries and remediation roadmaps from local scan results.
"""
from typing import Dict, Any, List
from core.engine.models import TechFingerprint, VerifiedVulnerability


class LocalForensicAdvisor:
    async def generate_forensic_consultation(
        self,
        target_url: str,
        fingerprint: TechFingerprint,
        vulnerabilities: List[VerifiedVulnerability]
    ) -> Dict[str, Any]:
        """
        توليد ملخص جنائي محلي اعتمادًا على نتائج الفحص المتاحة.
        """
        return self._generate_offline_forensic_report(target_url, fingerprint, vulnerabilities)

    def _generate_offline_forensic_report(
        self,
        target_url: str,
        fp: TechFingerprint,
        vulns: List[VerifiedVulnerability]
    ) -> Dict[str, Any]:
        vuln_count = len(vulns)
        crit_count = sum(1 for v in vulns if v.severity.value == "CRITICAL")
        high_count = sum(1 for v in vulns if v.severity.value == "HIGH")

        top_vuln_titles = [v.title for v in vulns[:3]]

        summary = (
            f"تم إخضاع الهدف ({target_url}) للتقييم الأمني الشامل وفق معايير PTES و NIST SP 800-115. "
            f"أظهرت النتائج رصد {vuln_count} ثغرة أمنية مؤكدة بالدليل الملموس (PoC)، "
            f"منها {crit_count} ثغرة حرجة و {high_count} ثغرة عالية الخطورة. "
        )

        if crit_count > 0 or high_count > 0:
            summary += (
                f"أبرز الثغرات المكتشفة: ({', '.join(top_vuln_titles)}). "
                f"يوصى بالبدء الفوري في تطبيق خطط الترقيع المحددة في التقرير لحماية البيانات وسرية المستخدمين."
            )
        else:
            summary += "الهدف أظهر صموداً أمام مصفوفة الهجمات الأساسية، مع ضرورة الالتزام بالمراجعة الدورية."

        return {
            "executive_summary": summary,
            "engine_used": "Baseera Local Forensic Engine",
            "status": "success"
        }
