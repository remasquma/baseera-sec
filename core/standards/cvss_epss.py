"""
Baseera Sec - Standards Engine: CVSS v3.1/v4.0 & EPSS Prioritizer
منظومة تقييم الخطورة وحساب احتمالية الاستغلال الواقعية وترتيب أولويات المعالجة
"""
import math
from typing import Dict, Any, List, Optional


def _optional_float(value: Any) -> Optional[float]:
    if isinstance(value, bool) or value is None:
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) else None


class StandardsCalculator:
    @staticmethod
    def calculate_priority(cvss: float, epss: float) -> str:
        """
        Risk-Based Vulnerability Prioritization:
        دمج الخطورة النظرية (CVSS) مع احتمالية الاستغلال الواقعية (EPSS)
        """
        if cvss >= 7.0 and epss >= 0.50:
            return "P1 - Critical Urgent (ثغرة خطيرة يسهل استغلالها بنشاط في العالم الواقعي)"
        elif cvss >= 7.0:
            return "P2 - High Priority (ثغرة شديدة الأثر لكن استغلالها الميداني أقل احتمالاً)"
        elif cvss >= 4.0 and epss >= 0.40:
            return "P3 - Medium Active (ثغرة متوسطة لكنها شائعة الاستهداف)"
        else:
            return "P4 - Low / Maintenance (توصيات أمان وتحصين روتيني)"

    @staticmethod
    def get_risk_matrix_data(vulnerabilities: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """
        بيانات مصفوفة المخاطر لرسم منحنى (CVSS vs EPSS)
        """
        points = []
        for v in vulnerabilities:
            cvss = _optional_float(v.get("cvss_score"))
            epss = _optional_float(v.get("epss_score"))
            points.append({
                "id": v.get("vuln_code") or "N/A",
                "title": v.get("title") or "N/A",
                "x_cvss": cvss,
                "y_epss": round(epss * 100, 1) if epss is not None else None,
                "severity": v.get("severity") or "N/A",
                "priority": (
                    StandardsCalculator.calculate_priority(cvss, epss)
                    if cvss is not None and epss is not None
                    else "N/A"
                )
            })
        return points
