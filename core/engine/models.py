"""
Baseera Sec - Core Data Models (The Unified Data Contract)
معيار البيانات الموحد بين محرك ريماس ونماذج هنادي والواجهة
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum
import time

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class TechFingerprint:
    server: Optional[str] = None
    framework: Optional[str] = None
    language: Optional[str] = None
    cms: Optional[str] = None
    waf_detected: bool = False
    inferred_site_type: str = "Generic Web Application"
    common_attack_vectors: List[str] = field(default_factory=list)

@dataclass
class ReconFinding:
    category: str  # "headers", "cookies", "tokens", "paths"
    title: str
    description: str
    evidence: str
    risk_indicator: str  # "high", "medium", "low"
    timestamp: float = field(default_factory=time.time)

@dataclass
class VerifiedVulnerability:
    vuln_id: str
    title: str
    cwe_id: str
    owasp_category: str
    severity: SeverityLevel
    cvss_score: float
    confidence_score: float  # 0.0 to 1.0 (Strict PoC ensures 0.95 - 1.0)
    description: str
    poc_evidence: str        # دليل الإثبات العملي (HTTP request/response proof)
    attack_vector: str
    remediation_guide: str   # خطوات الترقيع والكود التصحيحي
    affected_url: str = ""   # المسار والرابط الدقيق المصاب
    timestamp: float = field(default_factory=time.time)

@dataclass
class AuditReport:
    target_url: str
    scan_id: str
    start_time: float
    end_time: float
    total_duration_seconds: float
    fingerprint: TechFingerprint
    recon_findings: List[ReconFinding] = field(default_factory=list)
    targeted_attack_plan: List[Dict[str, Any]] = field(default_factory=list)  # خطة الهجوم المرشحة من الـ AI
    attack_execution_results: List[Dict[str, Any]] = field(default_factory=list)  # نتائج تنفيذ الهجوم الفعلي
    verified_vulnerabilities: List[VerifiedVulnerability] = field(default_factory=list)
    overall_risk_score: float = 0.0
    executive_summary: str = ""
    forensic_attack_chain: List[str] = field(default_factory=list)
    attack_model_used: str = "AI Targeted Attack Strategist"
    generated_by: str = "Baseera Sec AI-Engine v2.0"
