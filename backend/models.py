import os
from datetime import datetime, timezone
from sqlalchemy import Column, Integer, String, Float, DateTime, Text, create_engine
from sqlalchemy.orm import declarative_base, sessionmaker

# Use PostgreSQL when configured, or zero-config SQLite fallback for instant local demo
DATABASE_URL = os.getenv("DATABASE_URL", "sqlite:///./asop_local.db")

connect_args = {"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
engine = create_engine(DATABASE_URL, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


class SecurityLog(Base):
    __tablename__ = "security_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    source_ip = Column(String(64), index=True)
    service = Column(String(64), index=True)
    endpoint = Column(String(256))
    method = Column(String(16))
    payload = Column(Text)
    threat_type = Column(String(64), index=True)  # SQLi, XSS, Brute Force, Normal
    severity = Column(String(32))  # CRITICAL, HIGH, MEDIUM, LOW
    risk_score = Column(Float)  # 0 - 100
    mitre_tactic = Column(String(64))
    ai_reasoning = Column(Text)
    automated_action = Column(String(128))


class SecurityControl(Base):
    __tablename__ = "security_controls"

    id = Column(Integer, primary_key=True, index=True)
    control_id = Column(String(32), unique=True, index=True)  # e.g. ISO-A.8.26
    framework = Column(String(64))  # ISO 27001 / NIST 800-53 / OWASP ASVS
    name = Column(String(128))
    description = Column(Text)
    status = Column(String(32))  # PASS, WARNING, FAIL
    pass_rate = Column(Float)  # 0 - 100%
    last_validated = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    evidence_count = Column(Integer, default=0)


class AuditEvidence(Base):
    __tablename__ = "audit_evidence"

    id = Column(Integer, primary_key=True, index=True)
    log_id = Column(Integer, index=True)
    control_id = Column(String(32), index=True)
    evidence_hash = Column(String(64), unique=True)  # SHA-256 tamper-evident hash
    threat_type = Column(String(64))
    source_ip = Column(String(64))
    captured_payload = Column(Text)
    response_taken = Column(String(128))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class ComplianceReport(Base):
    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(256))
    overall_risk_score = Column(Float)
    compliance_score = Column(Float)
    total_logs_analyzed = Column(Integer)
    critical_incidents = Column(Integer)
    generated_by = Column(String(64))  # Gemini LLM / Hybrid Engine
    markdown_content = Column(Text)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
