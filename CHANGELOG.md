# Changelog - Baseera Sec Platform

All notable changes to the Baseera Sec platform are documented in this file.
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
The `prod` suffix previously used in this file was not a readiness certification
and has been removed; this project is not production-ready.

---

## [2.8.0] - 2026-11-20

### 🛡️ Critical Security Hardening (P0)
- **HTTP Request Scope Gateway (`core/network/request_gateway.py`):**
  - Added checks for disallowed private destinations and redirect targets to scanner HTTP requests. This is not comprehensive SSRF protection: DNS socket pinning is absent and optional browser traffic bypasses the gateway.
  - Added redirect-hop checks; DNS pre-resolution does not fully prevent DNS rebinding.
  - Introduced configurable per-scan request budgets, timeouts, cancellation tokens, and dry-run execution modes.
- **API Hardening & Local Exposure Limits (`api/main.py`):**
  - Removed insecure wildcard CORS origins with credentials (`allow_origins=["*"]` + `allow_credentials=True`). Explicitly bound default API server to localhost (`127.0.0.1`).
  - Added rigorous target URL and domain pre-validation on all audit trigger endpoints (`/api/audit/start`, `/api/audit/upload`).
  - Removed deprecated external key verification (`/api/verify-key`) and replaced it with local engine health status check without Gemini cloud dependencies.
- **Secure File Ingestion & Extraction (`core/engine/local_scanner.py`, `api/main.py`):**
  - Restricted maximum upload size to 25MB.
  - Implemented secure server-side UUID filenames and strict `.zip` extension validation.
  - Hardened archive extraction using `tempfile.mkdtemp`, Zip-Slip protection (`os.path.commonpath`), extraction bounds (50MB uncompressed limit, 2,000 files limit), symlink rejection, and deterministic temp folder teardown.
- **Browser Automation Isolation (`core/recon/crawler/headless_spider.py`, `core/reporting/enterprise_reporter.py`):**
  - Eliminated dangerous `--no-sandbox` flags from standard headless browser execution.
  - Isolated browser sessions inside disposable temporary user data directories (`--user-data-dir`) with strict execution timeouts and automated lifecycle cleanup.

---

### 🔍 Vulnerability Detector Engineering
- **SQL Injection Verification (`core/verifier/engine/sql_detector.py`):**
  - Separated raw database syntax errors (CWE-209) from confirmed exploitable SQL injection (CWE-89).
  - Built repeatable Boolean-based blind differential analysis (`1 AND 1=1` vs `1 AND 1=2`) requiring length divergence > 80 bytes and repeatable baseline confirmation.
  - Purged fabricated 120ms latency and hardcoded 92% confidence percentages.
- **Context-Aware Cross-Site Scripting (`core/verifier/engine/xss_detector.py`):**
  - Integrated BeautifulSoup DOM parsing to analyze reflection context (HTML body, attributes, comments, or non-executable tags such as `<title>`, `<textarea>`).
  - Proved execution viability only when script tags or event handlers remain unescaped, differentiating active XSS from harmless HTML entity reflections (`&lt;`).
- **IDOR Multi-Account Matrix (`core/verifier/engine/idor_detector.py`):**
  - Architected dual-token permission matrix to verify true cross-tenant access control violations (CWE-639) without speculative single-token guessings.
- **SSRF Controlled Probe Engine (`core/verifier/engine/ssrf_detector.py`):**
  - Replaced hardcoded AWS metadata (`169.254.169.254`) and internal port probes (`127.0.0.1:8765`) with safe parameter reflection and loopback isolation architecture.
- **Command Injection (`core/verifier/engine/cmdi_detector.py`):**
  - Replaced echo reflection checks with arithmetic evaluation (`expr 48102 + 19283 -> 67385`) and strict regex verification (`uid=.*gid=`), filtering out verbatim input mirrors.
- **Path Traversal (`core/verifier/engine/traversal_detector.py`):**
  - Added baseline comparison ensuring `/etc/passwd` root account patterns (`root:.*:0:0:`) exist only in malicious response payloads and not in baseline reflections.
- **Recon & Web Security Auditing (`core/recon/headers/header_auditor.py`, `core/recon/crawler/path_crawler.py`):**
  - Tailored HSTS findings to HTTPS contexts and adjusted HTTP severity to Informational.
  - Added canary 404 probing in path discovery to eliminate false positives caused by Single Page Application (SPA) catch-all routing.

---

### 🧠 AI & Machine Learning Integrity
- **CodeBERT Nazzoor Neural Architecture (`core/ai/local_model_analyzer.py`):**
  - Historical implementation clamped weights and inferred class-1 semantics. Phase 3 supersedes that behavior: current checkpoint inspection found no NaN/Inf or values above `1e10`; load-time mutation and unverified class interpretation have been removed.
  - Neural outputs (logits, softmax, numeric class index) are diagnostic only. Missing class mappings block malicious/benign decisions, and heuristic signals remain separate.
  - LightGBM inference is blocked when the saved scikit-learn version is incompatible with the runtime.
- **Elimination of Gemini Cloud Dependencies:**
  - Completely purged `google-genai` and `gemini-2.5-flash` dependencies from `requirements.txt` and codebase.
  - Converted `core/ai/cloud_bridge/gemini_advisor.py` and `gemini_analyzer.py` into local, offline-resilient analysis modules.

---

### 📊 Benchmark & Accuracy Engineering
- **Synthetic Verification Benchmark Testbed (`benchmark/`):**
  - Renamed harness from misleading "Official OWASP Benchmark" to "Baseera Sec Synthetic Verification Benchmark Testbed".
  - Curated 34 explicit synthetic test cases (18 True Positives, 16 True Negatives).
  - Implemented exact case path matching (`case_path in v.affected_url`) to prevent cross-endpoint contamination during whole-domain crawling.
  - Generated live confusion matrix calculations (TP, FP, TN, FN, Recall, Precision, Accuracy, F1-Score) exported directly to `reports/benchmark_testbed_results.json`.

---

### 📑 Enterprise Reporting Engine
- **XSS & Injection Hardening (`core/reporting/enterprise_reporter.py`):**
  - Added HTML context escaping on all user-supplied data, targets, and forensic evidence in generated HTML reports.
  - Embedded Content Security Policy (`default-src 'self' 'unsafe-inline'`) preventing script execution within generated reports.
  - Added atomic temporary file creation with restricted file permissions (`0o600`) and isolated profile cleanup during headless PDF generation.
  - Introduced clean Plain Text (`.txt`) report generation.
- **Realistic Compliance & Risk Modeling (`core/standards/compliance.py`, `core/reporting/cvss/calculator.py`):**
  - Replaced empty-scan 100% compliance claims with realistic assessed/untested state matrices.
  - Formally codified and documented Baseera Aggregate Risk formula:
    $$\text{Risk} = \min\left(10.0, (\text{Max CVSS} \times 0.65) + (\text{Avg CVSS} \times 0.35)\right)$$

---

### 💾 Storage, Lifecycle & Operations
- **Database Schema & Cascade Safety (`core/db/schema.py`, `core/db/database.py`):**
  - Removed artificial default values (`0.15` EPSS, `V14.4.1` ASVS, `CWE-200`); all metrics are now nullable (`None`) or `"N/A"`.
  - Configured SQLite foreign keys via engine listener (`PRAGMA foreign_keys=ON;`) ensuring atomic cascade deletions of vulnerabilities and attack logs when projects are deleted.
  - Added project lifecycle endpoints (`GET /api/projects`, `GET /api/projects/{id}`, `DELETE /api/projects/{id}`).
- **Secure Logging (`core/logging_config.py`):**
  - Created centralized log filter `SensitiveDataRedactor` scrubbing Bearer tokens, passwords, API keys, and RSA/EC private keys.
