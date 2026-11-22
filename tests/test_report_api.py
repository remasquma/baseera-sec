import json
import shutil

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from api import main as api_main
from core.db.database import get_db
from core.db.schema import Base, Project, Vulnerability


@pytest.fixture
def report_client(tmp_path, monkeypatch):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(bind=engine)()
    project = Project(name="Incomplete test project", target_url="http://example.test")
    session.add(project)
    session.flush()
    session.add(Vulnerability(
        vuln_code="VULN-INCOMPLETE",
        project_id=project.id,
        title="Incomplete finding",
        description="",
        severity=None,
        target_endpoint=None,
        cve_id=None,
        cwe_id=None,
        cvss_score=None,
        epss_score=None,
        epss_percentile=None,
        mitre_technique_id=None,
        owasp_category=None,
        asvs_level=None,
        asvs_requirement_id=None,
        cis_control_id=None,
        poc_evidence="",
        remediation_roadmap="",
    ))
    session.commit()

    def override_get_db():
        yield session

    api_main.app.dependency_overrides[get_db] = override_get_db
    monkeypatch.setattr(api_main, "REPORTS_DIR", str(tmp_path))
    with TestClient(api_main.app) as client:
        yield client, project.id

    api_main.app.dependency_overrides.pop(get_db, None)
    session.close()
    engine.dispose()


def test_report_api_supports_html_json_sarif_and_txt_with_incomplete_rows(report_client):
    client, project_id = report_client

    html_response = client.get(f"/api/reports/export/{project_id}/html")
    json_response = client.get(f"/api/reports/export/{project_id}/json")
    sarif_response = client.get(f"/api/reports/export/{project_id}/sarif")
    txt_response = client.get(f"/api/reports/export/{project_id}/txt")

    assert html_response.status_code == 200
    assert "N/A / 10" in html_response.text
    assert "CWE-200" not in html_response.text
    assert json_response.status_code == 200
    assert json.loads(json_response.text)["vulnerabilities"][0]["cvss_score"] is None
    assert sarif_response.status_code == 200
    assert json.loads(sarif_response.text)["version"] == "2.1.0"
    assert txt_response.status_code == 200
    assert "Peak CVSS Score                : N/A / 10.0" in txt_response.text


def test_pdf_export_failure_does_not_break_other_report_formats(report_client, monkeypatch):
    client, project_id = report_client

    def fail_pdf(_html, _path):
        raise RuntimeError("PDF renderer unavailable")

    monkeypatch.setattr(api_main.EnterpriseReporter, "export_pdf", fail_pdf)
    pdf_response = client.get(f"/api/reports/export/{project_id}/pdf")
    txt_response = client.get(f"/api/reports/export/{project_id}/txt")

    assert pdf_response.status_code == 503
    assert "PDF report generation failed" in pdf_response.json()["detail"]
    assert txt_response.status_code == 200


def test_pdf_report_api_returns_generated_pdf(report_client):
    client, project_id = report_client
    if not any(shutil.which(binary) for binary in ("google-chrome", "chromium", "chromium-browser")):
        pytest.skip("Chrome or Chromium is not installed")
    response = client.get(f"/api/reports/export/{project_id}/pdf")

    assert response.status_code == 200
    assert response.headers["content-type"] == "application/pdf"
    assert response.content.startswith(b"%PDF-1.4")
