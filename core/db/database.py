"""
Baseera Sec - Database Session Manager & Data Lifecycle Management
"""
import os
import time
from sqlalchemy import create_engine, event
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker, Session
from core.db.schema import Base, Project, Vulnerability, AttackExecutionLog

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "baseera_vapt.db")
DATABASE_URL = f"sqlite:///{DB_PATH}"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})

# تفعيل التحقق من المفاتيح الأجنبية في SQLite تلقائياً لضمان سلامة علاقات الحذف المتعاقب (Cascade Deletions)
@event.listens_for(Engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

def init_db():
    Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def delete_project(db: Session, project_id: int) -> bool:
    """حذف مشروع وجميع الثغرات وسجلات الهجمات المرتبطة به بالتتابع (Cascade Delete)."""
    project = db.query(Project).filter(Project.id == project_id).first()
    if not project:
        return False
    db.delete(project)
    db.commit()
    return True

def cleanup_old_projects(db: Session, max_age_days: int = 90) -> int:
    """تنظيف المشاريع القديمة التي تجاوزت مدة الاحتفاظ المحددة."""
    cutoff = time.time() - (max_age_days * 86400)
    old_projects = db.query(Project).filter(Project.created_at < cutoff).all()
    count = len(old_projects)
    for p in old_projects:
        db.delete(p)
    db.commit()
    return count
