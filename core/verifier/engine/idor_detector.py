"""Cross-account object authorization checks for IDOR/BOLA."""
import json
import logging
import re
import httpx
from typing import Any, Dict, Optional
from urllib.parse import urlsplit


logger = logging.getLogger("baseera.verifier.idor")


class IDORDetector:
    IDOR_PARAM_PATTERNS = [
        r"(?i)^id$", r"(?i)user_?id", r"(?i)account_?id", r"(?i)order_?id",
        r"(?i)profile_?id", r"(?i)doc_?id", r"(?i)file_?id", r"(?i)invoice_?id"
    ]
    IDENTITY_KEYS = {
        "id", "user_id", "account_id", "profile_id", "owner_id",
        "email", "phone", "ssn",
    }
    SENSITIVE_KEYS = IDENTITY_KEYS | {"balance", "password_hash"}

    @classmethod
    def _identity_headers(cls, headers: Dict[str, str]) -> Dict[str, str]:
        return {
            key.lower(): value.strip()
            for key, value in headers.items()
            if key.lower() == "authorization"
            or key.lower() == "cookie"
            or key.lower().endswith("-api-key")
        }

    @classmethod
    def _record_fields(cls, body: str) -> Dict[str, str]:
        try:
            data = json.loads(body)
        except (json.JSONDecodeError, TypeError):
            return {}

        fields: Dict[str, str] = {}

        def visit(value: Any):
            if isinstance(value, dict):
                for key, item in value.items():
                    normalized_key = str(key).lower()
                    if normalized_key in cls.SENSITIVE_KEYS and item is not None:
                        fields[normalized_key] = str(item).strip()
                    visit(item)
            elif isinstance(value, list):
                for item in value:
                    visit(item)

        visit(data)
        return fields

    @staticmethod
    def _same_origin(first: str, second: str) -> bool:
        a = urlsplit(first)
        b = urlsplit(second)
        return (
            a.scheme.lower() == b.scheme.lower()
            and a.hostname == b.hostname
            and a.port == b.port
            and a.scheme.lower() in {"http", "https"}
        )

    @classmethod
    async def audit_parameter(
        cls,
        target_url: str,
        param_name: str,
        current_val: str,
        method: str,
        client: httpx.AsyncClient,
        secondary_client_headers: Optional[Dict[str, str]] = None,
        secondary_resource_url: Optional[str] = None,
    ) -> Optional[Dict[str, Any]]:
        if not any(re.search(pattern, param_name) for pattern in cls.IDOR_PARAM_PATTERNS):
            return None

        if not secondary_client_headers or not secondary_resource_url:
            return {
                "is_vulnerable": False,
                "status": "DUAL_ACCOUNT_REQUIRED",
                "type": "IDOR not verified: two-account evidence is required",
                "evidence": (
                    "No cross-account authorization conclusion was made. Supply a distinct "
                    "second account and its own resource URL."
                ),
            }

        if (
            not cls._same_origin(target_url, secondary_resource_url)
            or target_url == secondary_resource_url
        ):
            return {
                "is_vulnerable": False,
                "status": "INVALID_SECONDARY_RESOURCE",
                "type": "IDOR verification configuration is invalid",
                "evidence": "The second account control resource must be a different URL on the same origin.",
            }

        primary_identity = cls._identity_headers(dict(client.headers))
        secondary_identity = cls._identity_headers(secondary_client_headers)
        if (
            not primary_identity
            or not secondary_identity
            or primary_identity == secondary_identity
        ):
            return {
                "is_vulnerable": False,
                "status": "DISTINCT_ACCOUNTS_REQUIRED",
                "type": "IDOR not verified: account credentials are not distinct",
                "evidence": "Primary and secondary identity headers must be present and different.",
            }

        try:
            primary_response = await client.request(
                method, target_url, timeout=5.0, follow_redirects=True
            )
            secondary_own_response = await client.request(
                method,
                secondary_resource_url,
                headers=secondary_client_headers,
                timeout=5.0,
                follow_redirects=True,
            )
            secondary_cross_response = await client.request(
                method,
                target_url,
                headers=secondary_client_headers,
                timeout=5.0,
                follow_redirects=True,
            )
        except httpx.HTTPError as exc:
            logger.warning("IDOR dual-account request failed: %s", type(exc).__name__)
            return {
                "is_vulnerable": False,
                "status": "REQUEST_FAILED",
                "type": "IDOR verification inconclusive",
                "evidence": f"Dual-account request failed ({type(exc).__name__}).",
            }

        primary_fields = cls._record_fields(primary_response.text)
        secondary_own_fields = cls._record_fields(secondary_own_response.text)
        secondary_cross_fields = cls._record_fields(secondary_cross_response.text)
        if not (
            200 <= primary_response.status_code < 300
            and 200 <= secondary_own_response.status_code < 300
            and primary_fields
            and secondary_own_fields
        ):
            return {
                "is_vulnerable": False,
                "status": "SECONDARY_ACCOUNT_UNVERIFIED",
                "type": "IDOR verification inconclusive",
                "evidence": (
                    "Both accounts must successfully read their own distinct records before "
                    "cross-account access can be assessed."
                ),
            }

        distinct_owner_fields = {
            key for key in cls.IDENTITY_KEYS
            if primary_fields.get(key)
            and secondary_own_fields.get(key)
            and primary_fields[key] != secondary_own_fields[key]
        }
        if not distinct_owner_fields:
            return {
                "is_vulnerable": False,
                "status": "ACCOUNTS_NOT_DISTINGUISHABLE",
                "type": "IDOR verification inconclusive",
                "evidence": "The two own-resource responses did not establish distinct object owners.",
            }

        cross_matches_owner = {
            key for key in distinct_owner_fields
            if secondary_cross_fields.get(key) == primary_fields.get(key)
        }
        sensitive_matches_owner = {
            key for key in cls.SENSITIVE_KEYS
            if key in primary_fields
            and secondary_cross_fields.get(key) == primary_fields[key]
        }

        if (
            200 <= secondary_cross_response.status_code < 300
            and cross_matches_owner
            and sensitive_matches_owner
        ):
            return {
                "is_vulnerable": True,
                "status": "CROSS_ACCOUNT_ACCESS_CONFIRMED",
                "type": "Insecure Direct Object Reference (IDOR / BOLA)",
                "severity": "HIGH",
                "param_name": param_name,
                "payload": f"Identity B requested Identity A resource '{current_val}'",
                "http_code": secondary_cross_response.status_code,
                "evidence": (
                    "Identity B read its own distinct record, then received Identity A's "
                    "matching sensitive identity fields from Identity A's resource."
                ),
                "raw_response": secondary_cross_response.text[:200].strip(),
                "remediation": (
                    "Enforce object-level authorization for every request and verify that "
                    "the authenticated principal owns or may access the requested object."
                ),
            }

        return {
            "is_vulnerable": False,
            "status": "CROSS_ACCOUNT_BYPASS_NOT_CONFIRMED",
            "type": "Cross-account access was not confirmed",
            "http_code": secondary_cross_response.status_code,
            "evidence": (
                "The second account could not retrieve a response matching the first account's "
                "sensitive record. A status or response difference alone was not treated as IDOR."
            ),
        }
