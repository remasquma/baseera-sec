"""
Baseera Sec - Database Schema (Enterprise VAPT Data Models)
مخطط قاعدة البيانات الشامل لمشاريع الفحص، الثغرات، ومعايير (PTES, NIST, CVSS, EPSS, MITRE, OWASP ASVS, CIS)
"""
import time
from sqlalchemy import Column, Integer, String, Float, Boolean, Text, ForeignKey, create_engine
from sqlalchemy.orm import declarative_base, relationship, sessionmaker

Base = declarative_base()

class Project(Base):
    __tablename__ = "projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(200), nullable=False)
    target_type = Column(String(50), default="Web")  # "Web Application" أو "Mobile/Desktop Application"
    target_url = Column(String(500), nullable=False)
    methodology = Column(String(100), default="PTES + NIST SP 800-115")
    status = Column(String(50), default="Active")
    created_at = Column(Float, default=time.time)

    # علاقات
    vulnerabilities = relationship("Vulnerability", back_populates="project", cascade="all, delete-orphan")
    attacks = relationship("AttackExecutionLog", back_populates="project", cascade="all, delete-orphan")

class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, autoincrement=True)
    vuln_code = Column(String(50), nullable=False) # e.g. BASEERA-VULN-001
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    
    title = Column(String(300), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(50), default="MEDIUM") # CRITICAL, HIGH, MEDIUM, LOW, INFO
    target_endpoint = Column(String(500), default="")
    
    # المعايير القياسية العالمية (لا تسند افتراضات غير مثبتة)
    cve_id = Column(String(50), default="N/A")
    cwe_id = Column(String(50), default="N/A")
    
    # درجات التقييم والأولويات (قيم Nullable بدلاً من أرقام افتراضية مصطنعة)
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(150), nullable=True)
    epss_score = Column(Float, nullable=True)       # احتمالية الاستغلال تسند فقط لثغرات CVE الموثقة
    epss_percentile = Column(Float, nullable=True)
    
    # مصفوفة MITRE ATT&CK
    mitre_tactic = Column(String(150), nullable=True)
    mitre_technique_id = Column(String(100), nullable=True)
    
    # الامتثال والمعايير المرجعية
    owasp_category = Column(String(200), default="Uncategorized")
    asvs_level = Column(String(50), nullable=True)
    asvs_requirement_id = Column(String(50), nullable=True)
    cis_control_id = Column(String(100), nullable=True)
    nist_control = Column(String(100), nullable=True)
    
    # أدلة الإثبات العملي (PoC) والترقيع
    poc_evidence = Column(Text, nullable=False)
    http_request = Column(Text, default="")
    http_response = Column(Text, default="")
    steps_to_reproduce = Column(Text, default="")
    remediation_roadmap = Column(Text, nullable=False)
    
    created_at = Column(Float, default=time.time)

    project = relationship("Project", back_populates="vulnerabilities")

class AttackExecutionLog(Base):
    __tablename__ = "attack_executions"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("projects.id"), nullable=False)
    attack_name = Column(String(250), nullable=False)
    category = Column(String(100), default="Adversarial")
    target_endpoint = Column(String(500), nullable=False)
    payload_sent = Column(Text, nullable=False)
    execution_status = Column(String(50), default="EXPLOITED_CONFIRMED") # EXPLOITED_CONFIRMED, TARGET_SECURE
    http_code = Column(Integer, default=200)
    latency_ms = Column(Float, default=0.0)
    evidence = Column(Text, default="")
    is_proven = Column(Boolean, default=True)
    created_at = Column(Float, default=time.time)

    project = relationship("Project", back_populates="attacks")
