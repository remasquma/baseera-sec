"""
Baseera Sec - Configuration & Ethical Guardrails
"""
from dataclasses import dataclass, field
from typing import List

@dataclass
class AuditConfig:
    # النطاق المسموح به لضمان الالتزام الأخلاقي
    target_url: str = ""
    allowed_domains: List[str] = field(default_factory=list)
    
    # خيارات التخصيص والتحكم
    scan_depth: str = "deep"  # "quick", "standard", "deep"
    enable_ai_reasoning: bool = True
    strict_poc_verification: bool = True  # Require proof checks; false positives are still possible.
    
    # فلاتر الهجمات المستهدفة (يمكن للمستخدم تفعيل/تعطيل ما يشاء)
    check_headers: bool = True
    check_sessions_and_tokens: bool = True
    check_hidden_paths: bool = True
    check_injections: bool = True
    check_misconfigs: bool = True
    
    # حدود الأداء والسرعة
    request_timeout: float = 6.0
    max_concurrent_requests: int = 15
    user_agent: str = "BaseeraSec-EthicalAuditor/2.0 (+https://baseerasec.local)"
    allow_insecure_tls: bool = False
    allow_internal_targets: bool = False
