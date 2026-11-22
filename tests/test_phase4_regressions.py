import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest
from fastapi import FastAPI, Header
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient

from api import main as api_main
from core.ai.attack_agent import TargetedAttackAction
from core.engine.local_scanner import LocalPackageAuditor
from core.network.request_gateway import RequestGateway, ScopeViolationError
from core.verifier.engine.attack_executor import AttackExecutor
from core.verifier.engine.idor_detector import IDORDetector


def _scan_source(tmp_path, monkeypatch, source):
    (tmp_path / "sample.py").write_text(source, encoding="utf-8")
    monkeypatch.setattr(
        "core.engine.local_scanner.local_ai_classifier.score_text",
        lambda _text: {},
    )
    return LocalPackageAuditor.audit_package_or_directory(str(tmp_path))


def test_secret_scanner_uses_entropy_and_redacts_values(tmp_path, monkeypatch):
    secret = "aB3dE5fG7hJ9kL2mN4pQ"
    _, findings, vulnerabilities = _scan_source(
        tmp_path, monkeypatch, f'api_key = "{secret}"\n'
    )

    assert LocalPackageAuditor.shannon_entropy(secret) > 3.5
    assert len(vulnerabilities) == 1
    assert 0.0 < vulnerabilities[0].confidence_score < 0.95
    assert secret not in findings[0].evidence
    assert secret not in vulnerabilities[0].poc_evidence
    assert "entropy" in findings[0].evidence.lower()


@pytest.mark.parametrize(
    "source",
    [
        'API_KEY = "EXAMPLE"\n',
        'token = "REPLACE_ME"\n',
        'api_key = "YOUR_API_KEY"\n',
        'secret = "aaaaaaaaaaaaaaaaaaaaaaaa"\n',
        'password = "change_me"\n',
    ],
)
def test_secret_scanner_suppresses_placeholders_and_low_entropy_keys(
    tmp_path, monkeypatch, source
):
    _, _, vulnerabilities = _scan_source(tmp_path, monkeypatch, source)
    assert vulnerabilities == []


def test_secret_scanner_still_reports_non_placeholder_passwords(tmp_path, monkeypatch):
    _, findings, vulnerabilities = _scan_source(
        tmp_path, monkeypatch, 'password = "admin123"\n'
    )

    assert len(vulnerabilities) == 1
    assert vulnerabilities[0].cwe_id == "CWE-798"
    assert "redacted" in findings[0].evidence.lower()


def _account_test_app(vulnerable):
    app = FastAPI()
    records = {
        "alice": {"id": 41, "email": "alice@example.test", "balance": 500},
        "bob": {"id": 82, "email": "bob@example.test", "balance": 100},
    }
    token_owner = {"alice-token": "alice", "bob-token": "bob"}

    @app.get("/profiles/{profile_id}")
    async def get_profile(profile_id: str, authorization: str = Header(default="")):
        token = authorization.removeprefix("Bearer ").strip()
        owner = token_owner.get(token)
        if owner is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)

        record_owner = {"41": "alice", "82": "bob"}.get(profile_id)
        if record_owner is None:
            return JSONResponse({"error": "not found"}, status_code=404)
        if not vulnerable and record_owner != owner:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return records[record_owner]

    return app


async def _run_idor_check(app):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        headers={"Authorization": "Bearer alice-token"},
        base_url="http://testserver",
    ) as client:
        return await IDORDetector.audit_parameter(
            target_url="http://testserver/profiles/41?user_id=41",
            param_name="user_id",
            current_val="41",
            method="GET",
            client=client,
            secondary_client_headers={"Authorization": "Bearer bob-token"},
            secondary_resource_url="http://testserver/profiles/82?user_id=82",
        )


def test_idor_confirms_owner_record_exposed_to_second_account():
    result = asyncio.run(_run_idor_check(_account_test_app(vulnerable=True)))
    assert result["is_vulnerable"] is True
    assert result["status"] == "CROSS_ACCOUNT_ACCESS_CONFIRMED"


def test_idor_does_not_confirm_access_denied_for_second_account():
    result = asyncio.run(_run_idor_check(_account_test_app(vulnerable=False)))
    assert result["is_vulnerable"] is False
    assert result["status"] == "CROSS_ACCOUNT_BYPASS_NOT_CONFIRMED"


async def _run_difference_only_check():
    app = FastAPI()

    @app.get("/profiles/{profile_id}")
    async def profile(profile_id: str, authorization: str = Header(default="")):
        if authorization == "Bearer alice-token":
            return {"message": "Alice profile"}
        if authorization == "Bearer bob-token" and profile_id == "82":
            return {"message": "Bob profile"}
        return JSONResponse({"message": "not accessible"}, status_code=403)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app),
        headers={"Authorization": "Bearer alice-token"},
        base_url="http://testserver",
    ) as client:
        return await IDORDetector.audit_parameter(
            target_url="http://testserver/profiles/41?user_id=41",
            param_name="user_id",
            current_val="41",
            method="GET",
            client=client,
            secondary_client_headers={"Authorization": "Bearer bob-token"},
            secondary_resource_url="http://testserver/profiles/82?user_id=82",
        )


def test_idor_does_not_infer_vulnerability_from_response_difference():
    result = asyncio.run(_run_difference_only_check())
    assert result["is_vulnerable"] is False


async def _run_executor_forwarding_check(action, secondary_headers, secondary_resource):
    with patch(
        "core.verifier.engine.attack_executor.IDORDetector.audit_parameter",
        new=AsyncMock(return_value={
            "is_vulnerable": False,
            "status": "CROSS_ACCOUNT_BYPASS_NOT_CONFIRMED",
            "evidence": "Cross-account access denied.",
        }),
    ) as audit:
        async with httpx.AsyncClient() as client:
            outcomes = await AttackExecutor.execute_attacks(
                [action],
                client,
                secondary_client_headers=secondary_headers,
                secondary_resource_url=secondary_resource,
            )
    return outcomes, audit


def test_attack_executor_passes_secondary_idor_credentials():
    action = TargetedAttackAction(
        attack_name="IDOR check (Parameter: user_id)",
        target_endpoint="http://testserver/profiles/41?user_id=41",
        attack_vector="IDOR",
        attack_category="Access Control",
        predicted_probability=0.5,
        test_payload="",
        success_criteria="",
        description="",
        param_name="user_id",
    )
    secondary_headers = {"Authorization": "Bearer bob-token"}
    secondary_resource = "http://testserver/profiles/82?user_id=82"
    outcomes, audit = asyncio.run(
        _run_executor_forwarding_check(action, secondary_headers, secondary_resource)
    )

    assert len(outcomes) == 1
    assert outcomes[0].execution_status == "INCONCLUSIVE"
    audit.assert_awaited_once()
    assert audit.await_args.kwargs["secondary_client_headers"] == secondary_headers
    assert audit.await_args.kwargs["secondary_resource_url"] == secondary_resource


def test_idor_without_two_account_inputs_is_inconclusive():
    async def run():
        async with httpx.AsyncClient() as client:
            return await IDORDetector.audit_parameter(
                target_url="http://testserver/profiles/41?user_id=41",
                param_name="user_id",
                current_val="41",
                method="GET",
                client=client,
            )

    result = asyncio.run(run())
    assert result["is_vulnerable"] is False
    assert result["status"] == "DUAL_ACCOUNT_REQUIRED"


def test_internal_target_opt_in_does_not_expand_domain_scope():
    gateway = RequestGateway("http://127.0.0.1:8888", allow_internal_targets=True)
    with pytest.raises(ScopeViolationError):
        gateway.validate_destination("http://169.254.169.254/latest/meta-data/")


def test_api_blocks_cross_site_state_changing_requests():
    with TestClient(api_main.app) as client:
        rejected = client.post(
            "/api/audit/start",
            headers={"Origin": "https://attacker.example"},
            json={},
        )
        accepted_for_validation = client.post(
            "/api/audit/start",
            headers={"Origin": "http://127.0.0.1:8765"},
            json={},
        )

    assert rejected.status_code == 403
    assert accepted_for_validation.status_code == 422
