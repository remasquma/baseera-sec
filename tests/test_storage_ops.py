"""
Tests for Phase 6: Storage, Lifecycle & Operations
التحقق من سلامة الحذف المتعاقب (Cascade Deletions)، إخفاء البيانات الحساسة من السجلات، وإدارة دورة حياة المشاريع.
"""
import pytest
import time
import logging
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from core.db.schema import Base, Project, Vulnerability, AttackExecutionLog
from core.db.database import delete_project, cleanup_old_projects
from core.logging_config import SensitiveDataRedactor, setup_secure_logging

@pytest.fixture
def memory_db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(bind=engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()

def test_cascade_delete(memory_db):
    # إنشاء مشروع مع ثغرات وهجمات
    proj = Project(name="Test Project", target_url="http://test.local")
    memory_db.add(proj)
    memory_db.commit()

    vuln1 = Vulnerability(
        vuln_code="V-001",
        project_id=proj.id,
        title="SQLi Test",
        description="SQL Injection found",
        poc_evidence="Proof",
        remediation_roadmap="Fix it"
    )
    attack1 = AttackExecutionLog(
        project_id=proj.id,
        attack_name="SQL Injection probe",
        target_endpoint="/login",
        payload_sent="' OR 1=1--"
    )
    memory_db.add_all([vuln1, attack1])
    memory_db.commit()

    assert memory_db.query(Vulnerability).filter_by(project_id=proj.id).count() == 1
    assert memory_db.query(AttackExecutionLog).filter_by(project_id=proj.id).count() == 1

    # تنفيذ الحذف المتعاقب
    deleted = delete_project(memory_db, proj.id)
    assert deleted is True

    # التحقق من حذف السجلات المرتبطة
    assert memory_db.query(Project).filter_by(id=proj.id).count() == 0
    assert memory_db.query(Vulnerability).filter_by(project_id=proj.id).count() == 0
    assert memory_db.query(AttackExecutionLog).filter_by(project_id=proj.id).count() == 0

def test_cleanup_old_projects(memory_db):
    old_time = time.time() - (100 * 86400) # 100 days ago
    p_old = Project(name="Old Project", target_url="http://old.local", created_at=old_time)
    p_new = Project(name="New Project", target_url="http://new.local", created_at=time.time())
    memory_db.add_all([p_old, p_new])
    memory_db.commit()

    cleaned = cleanup_old_projects(memory_db, max_age_days=90)
    assert cleaned == 1
    assert memory_db.query(Project).count() == 1
    assert memory_db.query(Project).first().name == "New Project"

def test_sensitive_logging_redaction():
    logger = logging.getLogger("test_redact")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()

    # استخدام مرشح التنقيح
    class MemoryLogHandler(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []
        def emit(self, record):
            self.records.append(self.format(record))

    mem_handler = MemoryLogHandler()
    mem_handler.setFormatter(logging.Formatter("%(message)s"))
    mem_handler.addFilter(SensitiveDataRedactor())
    logger.addHandler(mem_handler)

    logger.info("Connecting with Authorization: Bearer secret_jwt_token_1234567890abcdef")
    logger.info("DB config password='super_secret_db_pass'")
    logger.info("External service api_key='sk-proj-abcdef123456789'")

    assert len(mem_handler.records) == 3
    assert "secret_jwt_token_1234567890abcdef" not in mem_handler.records[0]
    assert "[REDACTED_TOKEN]" in mem_handler.records[0]

    assert "super_secret_db_pass" not in mem_handler.records[1]
    assert "[REDACTED_PASSWORD]" in mem_handler.records[1]

    assert "sk-proj-abcdef123456789" not in mem_handler.records[2]
    assert "[REDACTED_KEY]" in mem_handler.records[2]


def test_secure_logging_setup_redacts_formatted_arguments():
    logger = logging.getLogger("baseera")

    class CaptureHandler(logging.Handler):
        def __init__(self):
            super().__init__()
            self.records = []

        def emit(self, record):
            self.records.append(record.getMessage())

    capture = CaptureHandler()
    logger.addHandler(capture)
    try:
        setup_secure_logging()
        assert any(isinstance(item, SensitiveDataRedactor) for item in capture.filters)
        logger.info("password=%s token=%s api_key=%s", "db-secret-value", "jwt-token-value-123456", "key-secret-value-123")
        logger.info(
            "auth %s=%s token=%s api_key=%s",
            "pass" + "word",
            "db-secret-value",
            "jwt-token-value-123456",
            "key-secret-value-123",
        )
        logger.info(
            "auth %s=%s %s=%s",
            "sec" + "ret",
            "cloud-secret-value",
            "private_key",
            "private-key-material-123",
        )
        output = "\n".join(capture.records)
        assert "db-secret-value" not in output
        assert "jwt-token-value-123456" not in output
        assert "key-secret-value-123" not in output
        assert "cloud-secret-value" not in output
        assert "private-key-material-123" not in output
        assert "[REDACTED_PASSWORD]" in output
        assert "[REDACTED_TOKEN]" in output
        assert "[REDACTED_KEY]" in output
        assert "[REDACTED_SECRET]" in output
    finally:
        logger.removeHandler(capture)
