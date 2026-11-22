"""
Baseera Sec - Intelligent Sensitive Path & Backup Explorer
Phase 3: Explores sensitive paths and exposed files (.git, .env, admin, backup).
Features SPA catch-all detection, 404-as-200 filtering, and content-specific signature checks.
"""
import re
import uuid
import json
import httpx
from typing import List, Dict, Tuple
from urllib.parse import urljoin
from core.engine.models import ReconFinding


class PathCrawler:
    # High-value paths and validation patterns
    HIGH_VALUE_TARGETS: List[Tuple[str, str, str]] = [
        ("/.git/HEAD", "مستودع Git مكشوف (.git Repository Leak)", "high"),
        ("/.env", "ملف إعدادات وبيئة مكشوف (.env File Leak)", "high"),
        ("/admin", "مسار لوحة الإدارة مكشوف (Admin Panel Route)", "medium"),
        ("/api/v1", "واجهة برمجية مكشوفة (Exposed API v1 Route)", "low"),
        ("/config.json", "ملف إعدادات برمجية مكشوف (Exposed config.json)", "high"),
        ("/backup.sql", "نسخة احتياطية لقاعدة البيانات مكشوفة (Backup SQL Dump)", "high"),
        ("/phpinfo.php", "صفحة معلومات بيئة الخادم مكشوفة (PHP Info Disclosure)", "medium"),
        ("/robots.txt", "ملف توجيه الزواحف متاح (Robots.txt Discovered)", "low"),
    ]

    @classmethod
    async def probe_paths(cls, base_url: str, client: httpx.AsyncClient) -> List[ReconFinding]:
        findings = []

        # 1. Probe a random canary path to detect SPA catch-all 200 responses
        canary_path = f"/baseera_canary_{uuid.uuid4().hex[:8]}"
        canary_url = urljoin(base_url, canary_path)
        is_spa_catchall = False
        canary_len = 0
        canary_text_sample = ""

        try:
            r_canary = await client.get(canary_url, timeout=4.0, follow_redirects=False)
            if r_canary.status_code == 200:
                is_spa_catchall = True
                canary_len = len(r_canary.content)
                canary_text_sample = r_canary.text[:300].strip()
        except Exception:
            pass

        for path, title, risk in cls.HIGH_VALUE_TARGETS:
            target_url = urljoin(base_url, path)
            try:
                res = await client.get(target_url, timeout=4.0, follow_redirects=False)
                if res.status_code == 200:
                    content_len = len(res.content)
                    content_text = res.text
                    content_sample = content_text[:300].strip()

                    # SPA Catch-All Filter: If response matches canary 404 response, skip false positive
                    if is_spa_catchall:
                        if abs(content_len - canary_len) < 30 and content_sample == canary_text_sample:
                            continue

                    is_real_match = False

                    if path == "/.git/HEAD":
                        if "ref: refs/" in content_sample or re.match(r"^[0-9a-f]{40}\b", content_sample):
                            is_real_match = True
                    elif path == "/.env":
                        if any(k in content_sample for k in ["DB_", "APP_", "SECRET", "PASSWORD", "KEY="]):
                            is_real_match = True
                    elif path == "/backup.sql":
                        # Must contain SQL dump signatures
                        if any(k in content_sample.upper() for k in ["CREATE TABLE", "INSERT INTO", "DROP TABLE", "MYSQL DUMP", "POSTGRESQL"]):
                            is_real_match = True
                    elif path == "/config.json":
                        try:
                            parsed_cfg = json.loads(content_text)
                            if isinstance(parsed_cfg, dict) and len(parsed_cfg) > 0:
                                is_real_match = True
                        except Exception:
                            is_real_match = False
                    elif path == "/phpinfo.php":
                        if "phpinfo()" in content_sample or "PHP Version" in content_sample:
                            is_real_match = True
                    elif path == "/robots.txt":
                        if "user-agent:" in content_sample.lower() or "disallow:" in content_sample.lower():
                            is_real_match = True
                    elif path in ["/admin", "/api/v1"]:
                        # Exclude default HTML pages that mirror the homepage or canary
                        if not is_spa_catchall:
                            is_real_match = True

                    if is_real_match:
                        findings.append(ReconFinding(
                            category="paths",
                            title=title,
                            description=f"تم تأكيد وجود المسار الحساس '{path}' بمحتوى محدد ومطابق بحجم {content_len} بايت.",
                            evidence=f"GET {target_url} -> HTTP 200 | Sample: {content_sample[:80]}...",
                            risk_indicator=risk
                        ))
            except Exception:
                continue

        return findings
