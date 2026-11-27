import pytest
from fastapi.testclient import TestClient
from api.main import app

client = TestClient(app)

def test_missing_protocol_rejected():
    response = client.post(
        "/api/audit/start",
        json={"target_url": "testphp.vulnweb.com", "target_type": "Web"}
    )
    assert response.status_code == 400
    assert "بروتوكول" in response.json()["detail"]

def test_fake_nonexistent_domain_rejected():
    response = client.post(
        "/api/audit/start",
        json={"target_url": "https://definitely-fake-nonexistent-domain-123456789.xyz", "target_type": "Web"}
    )
    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "غير موجود" in detail or "تعذر" in detail

def test_empty_url_rejected():
    response = client.post(
        "/api/audit/start",
        json={"target_url": "   ", "target_type": "Web"}
    )
    assert response.status_code == 400
