"""
Baseera Sec local technology and behavioral analyzer.
"""
from typing import Dict, Any, List, Optional
from core.engine.models import TechFingerprint, ReconFinding
from core.fingerprint.tech_detector import TechDetector


class LocalTechAnalyzer:
    async def classify_deep_tech(
        self,
        target_url: str,
        headers: Dict[str, str],
        html_sample: str
    ) -> Optional[TechFingerprint]:
        """
        تحليل تقنيات الموقع محلياً عبر محرك TechDetector
        """
        return TechDetector.analyze(headers, html_sample, target_url)

    async def analyze_behavioral_anomalies(
        self,
        target_url: str,
        probe_logs: List[Dict[str, Any]]
    ) -> List[ReconFinding]:
        """
        تحليل الشذوذ السلوكي واستجابات الخادم محلياً
        """
        anomalies = []
        for log in probe_logs:
            if log.get("risk") == "high":
                anomalies.append(ReconFinding(
                    category="anomaly",
                    title=f"شذوذ سلوكي في المسار: {log.get('path', '')}",
                    description="الخادم استجاب بأنماط تشير إلى كشف مسار حساس أو تصرف غير معتاد.",
                    evidence=str(log.get("evidence", "")),
                    risk_indicator="medium"
                ))
        return anomalies
