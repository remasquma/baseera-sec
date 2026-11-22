"""
Baseera Sec - CVSS v3.1 Standards Calculator & Risk Aggregator
Provides:
1. Standard CVSS Base Score calculation per vulnerability
2. Baseera Aggregate Risk Index calculation with full formula transparency
Formula: Baseera Aggregate Risk = min(10.0, (Max CVSS * 0.65) + (Average CVSS * 0.35))
"""
from typing import List, Dict, Any
from core.engine.models import VerifiedVulnerability


class CVSSCalculator:

    @staticmethod
    def calculate_overall_risk(vulnerabilities: List[VerifiedVulnerability]) -> float:
        """
        حساب مؤشر الخطر التراكمي المعتمد (Baseera Aggregate Risk Index):
        الصيغة الحسابية: (Max CVSS * 0.65) + (Average CVSS * 0.35)
        ملاحظة: هذا المؤشر هو قياس تركيبي خاص بمنصة بصيرة ولا يستبدل درجة CVSS Base الفردية لكل ثغرة.
        """
        if not vulnerabilities:
            return 0.0

        scores = [float(v.cvss_score) for v in vulnerabilities if v.cvss_score is not None]
        if not scores:
            return 0.0

        max_score = max(scores)
        avg_score = sum(scores) / len(scores)

        # Baseera Composite Risk Formula
        aggregated_risk = (max_score * 0.65) + (avg_score * 0.35)
        return round(min(10.0, aggregated_risk), 1)

    @staticmethod
    def get_risk_label(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL (خطر حرج يهدد أمان النظام)"
        elif score >= 7.0:
            return "HIGH (خطر مرتفع يتطلب معالجة عاجلة)"
        elif score >= 4.0:
            return "MEDIUM (خطر متوسط)"
        elif score > 0.0:
            return "LOW (ملاحظات أمان روتينية)"
        return "SECURE (سليم)"

    @staticmethod
    def get_formula_disclosure() -> Dict[str, str]:
        return {
            "name": "Baseera Aggregate Risk Index",
            "formula": "min(10.0, (Max_CVSS * 0.65) + (Avg_CVSS * 0.35))",
            "description": "Composite severity weight balancing peak exposure (65%) and overall attack surface density (35%)."
        }
