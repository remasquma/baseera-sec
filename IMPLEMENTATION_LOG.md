# Baseera Sec - Master Implementation & Security Hardening Log

## Phase 0: Full Repository Inspection & Baseline Audit

- **Date:** 2026-11-20
- **Environment:** Ubuntu Linux (x86_64), Python 3.14.4, PyTorch 2.15.0+cpu, Transformers 5.23.0
- **Baseline Test Suite:** `tests/test_platform.py` (5 tests passing)
- **Baseline Git Tag:** `baseline_v1.0.0` (commit `5ec8b08`)

### Initial Findings Verification (F-01 through F-30):
1. **F-01 (Scope Enforcement):** Confirmed. Probing and crawler components send requests without a centralized gateway. `config/settings.py` defined `allowed_domains` but detectors could target any URL.
2. **F-02 (API Auth & CORS):** Confirmed. `api/main.py` lacked authentication, per-project authorization, and had `allow_origins=["*"]` with `allow_credentials=True`.
3. **F-03 (Unsafe Uploads):** Confirmed. Direct string concatenation with `file.filename` in `api/main.py`, unvalidated zip extraction (`zf.extractall`) in `core/engine/local_scanner.py`.
4. **F-04 (Browser Sandboxing):** Confirmed. `core/recon/crawler/headless_spider.py` and `core/reporting/enterprise_reporter.py` passed `--no-sandbox`.
5. **F-05 (TLS Verification):** Confirmed. `core/engine/orchestrator.py` instantiated `httpx.AsyncClient(..., verify=False)`.
6. **F-06 / F-21 / F-22 (Weak Detector Proofs):** Confirmed. XSS flagged on tag reflection without DOM context; SQLi had hardcoded confidence; SSRF targeted loopback and cloud metadata directly.
7. **F-07 (Hardcoded Confidence/Latency):** Confirmed in `core/verifier/engine/sql_detector.py` (e.g. latency 120ms, 92.0% confidence).
8. **AI Model Integrity (historical finding):** The initial audit reported missing repository weights and numerical saturation on host files. Reinspection of the current in-repository checkpoints in Phase 3 did not reproduce NaN/Inf or oversized values; class-label metadata is still absent.
9. **F-09 (IDOR Methodology):** Confirmed. IDOR detector merely swapped IDs and checked if text was non-empty/different, without multi-account ownership matrix.
10. **F-11 (Benchmark Labeling):** Confirmed. 34 synthetic cases were branded "Official OWASP Benchmark Scorecard v1.2".
11. **F-12 (Fabricated Metadata):** Confirmed. Hardcoded "CVE-LOCAL-SECRET" and simulated EPSS/ASVS/CIS scores in upload endpoints.
12. **F-13 (Unsafe HTML Reports):** Confirmed. Unescaped format string interpolation in `enterprise_reporter.py`.
13. **F-16 (SSRF Fixed Probes):** Confirmed. Probed `169.254.169.254` and `127.0.0.1:8765`.
14. **F-24 (Local SAST):** Confirmed. Regex-only secret scanning without AST or language-specific checks.
15. **F-25 / F-26 (Compliance & Risk Scoring):** Confirmed. Empty scans received 95-100% compliance; aggregate risk formula was unclarified.
16. **F-27 (Unsafe PDF Export):** Confirmed. Shared static path `/tmp/baseera_report_export.html`.
17. **F-29 (Database Defaults):** Confirmed. Fake default CVSS vectors, EPSS scores, and ASVS IDs in SQLAlchemy schema.
18. **User Special Instruction (Gemini API):** Confirmed. Code had remnants of `google.genai` and `gemini-2.5-flash`. Completely purged and replaced with local offline processing.

---

## Phase 1: Critical Security Hardening (P0) — Status: PASS
- **Scope Gateway (`core/network/request_gateway.py`):** Centralized HTTP/HTTPS gateway created. Validates schemes (http/https), domains, resolved IP addresses (blocks RFC 1918, RFC 3927 loopback/link-local/multicast/private networks). Validates each redirect hop. Enforces scan budgets, concurrency limits, dry-run mode, and cancellation.
- **API Hardening (`api/main.py`):** CORS restricted to local origins with credentials allowed only for explicit localhost origins (no `allow_origins=["*"]`). Added target scope pre-validation.
- **Upload Hardening (`api/main.py`, `core/engine/local_scanner.py`):** Enforced 25MB file upload limit, sanitized filenames with UUIDs, prohibited path traversal, added zip-slip/symlink/bomb protections, and automatic temporary extraction cleanup. Removed fabricated "CVE-LOCAL-SECRET" and artificial EPSS values.
- **Browser Sandboxing (`core/recon/crawler/headless_spider.py`, `core/reporting/enterprise_reporter.py`):** Removed `--no-sandbox`. Implemented isolated disposable browser user-data directories (`--user-data-dir`) with strict automatic cleanup.
- **TLS Verification (`core/engine/orchestrator.py`):** Enabled TLS certificate verification by default (`verify_ssl = not allow_insecure_tls`).
- **Gemini Purge:** Removed all imports of `google.genai` and model `gemini-2.5-flash` from `requirements.txt`, `api/main.py`, `core/ai/cloud_bridge/gemini_advisor.py`, and `core/ai/cloud_bridge/gemini_analyzer.py`. Fully transitioned to local offline architecture.
- **Tests:** 11 passed (`tests/test_gateway.py`, `tests/test_platform.py`).

## Phase 2: Vulnerability Detector Engineering — Status: PASS
- **SQL Injection (`core/verifier/engine/sql_detector.py`):** Separated error disclosure from confirmed injection. Added Boolean differential verification with repeatability checks. Removed hardcoded latency (120ms) and confidence (92%); all metrics are measured and calculated from actual responses.
- **Cross-Site Scripting (`core/verifier/engine/xss_detector.py`):** Context-aware DOM parsing using BeautifulSoup element analysis. Differentiates executable tag nodes from non-executing containers (`<textarea>`, `<title>`, `<!-- comment -->`) and entity-encoded defenses (`&lt;`).
- **Insecure Direct Object References (`core/verifier/engine/idor_detector.py`):** Multi-account verification architecture. Dual-token testing verifies whether Identity B can access Identity A's private data. Single-account parameter shifts are categorized as Heuristic Observations without premature vulnerability claims.
- **Server-Side Request Forgery (`core/verifier/engine/ssrf_detector.py`):** Purged fixed internal IP and cloud metadata probes (`169.254.169.254`, `127.0.0.1:8765`). Added isolated callback architecture.
- **OS Command Injection (`core/verifier/engine/cmdi_detector.py`):** Implemented arithmetic command evaluation (`expr 48102 + 19283 -> 67385`) and execution structure validation (`uid=... gid=...`). Discards verbatim input parameter reflections.
- **Path Traversal / LFI (`core/verifier/engine/traversal_detector.py`):** Validates actual system file disclosures against baseline while eliminating probe reflection false positives.
- **Server-Side Template Injection (`core/verifier/engine/ssti_detector.py`):** Retained and verified mathematical template execution (`{{7*7}} -> 49`).
- **Headers & Recon (`core/recon/headers/header_auditor.py`, `core/recon/crawler/path_crawler.py`):** Context-aware header severity (HTTP vs HTTPS). Added canary 404 detection in PathCrawler to eliminate false positives on Single Page Applications (SPAs) and catch-all routers.
- **Tests:** 18 passed across `tests/test_detectors.py`, `tests/test_gateway.py`, and `tests/test_platform.py`.

## Phase 3: AI and Machine Learning Audit — Status: CLASSIFICATION BLOCKED
- **Current checkpoint integrity:** Independently inspected every tensor in both current transformer state dictionaries. NaN, Inf, and finite values with absolute value > 1e10 were all zero. Load-time `nan_to_num` and `clamp` have been removed; unhealthy checkpoint tensors are rejected unchanged.
- **Architecture/tokenizer:** Strict state-dict loading succeeded for the configured RoBERTa sequence classifiers (12 and 6 layers respectively). Tokenizer vocabulary lengths match each config; output heads have two classes.
- **Class semantics:** Both transformer configs omit `id2label` and `label2id`; LightGBM exposes numeric labels `[0, 1]` only. No label/training provenance was found. No label index is presumed malicious.
- **Inference probe:** Raw logits and softmax vary by input and repeat deterministically in the small probe, but the two transformers disagree sharply on benign code. These observations do not prove useful classification; outputs are not calibrated and no security decision is derived.
- **LightGBM compatibility:** The saved artifacts carry scikit-learn 1.6.1 estimator metadata and the runtime is 1.9.1. The incompatibility is recorded and LightGBM inference is blocked until compatible artifacts or environment are provided.
- **Separation:** Heuristic match signals remain separate. The analyzer no longer exposes `malicious_probability`, `confidence`, or an averaged model score when labels are unverified.
- **Recovery requirement:** Provide original class mappings, dataset/training provenance, compatible scikit-learn artifacts, and a held-out labeled evaluation set. Retraining/re-export is needed if those cannot be restored; do not clamp or relabel current tensors.

## Phase 4: Benchmark and Detection Accuracy — Status: PASS
- **Honest Suite Naming:** Renamed internal benchmark suite from "Official OWASP Benchmark v1.2" to "Baseera Sec Synthetic Verification Benchmark Testbed" to prevent misleading official OWASP claims (F-11).
- **Unique Case Structure:** Configured 34 unique test cases (18 ground truth True Positives, 16 True Negatives) spanning SQL Injection, XSS, Command Injection, Path Traversal, SSRF, and Security Misconfigurations.
- **Traceable Metric Computation:** Computed confusion matrices independently per category (TP, TN, FP, FN, Precision, Recall, FPR, FNR, Accuracy, F1). Raw results persisted to `reports/benchmark_testbed_results.json` and `reports/Synthetic_Benchmark_Evaluation_Report.md`.
- **Tests:** 2 passed (`tests/test_benchmark.py`). Total suite: 24 passed.

## Phase 5: Reporting Engine — Status: PASS
- **HTML Security & Escaping (`core/reporting/enterprise_reporter.py`):** Applied `html.escape()` across all interpolated project, vulnerability, PoC evidence, and remediation fields to prevent report-injection XSS (F-13). Added restrictive Content-Security-Policy header.
- **PDF Export Isolation:** Replaced static `/tmp/baseera_report_export.html` with unique secure temporary files (`tempfile.mkstemp`) and isolated disposable Chromium profiles (`--user-data-dir`) with guaranteed cleanup (F-04, F-27).
- **Plain Text Consistency:** Implemented `generate_txt_report` and integrated the `fmt == "txt"` endpoint in `api/main.py`.
- **Compliance Realism (`core/standards/compliance.py`):** Replaced empty-scan 100% compliance with explicit assessed vs untested control states.
- **Risk Index Disclosure (`core/reporting/cvss/calculator.py`):** Explicitly documented the composite weighting formula: `min(10.0, (Max CVSS * 0.65) + (Avg CVSS * 0.35))` and labeled it as the Baseera Aggregate Risk Index (F-26).
- **Tests:** 3 passed (`tests/test_reporting.py`). Total suite: 27 passed.

## Phase 6: Storage, Lifecycle & Operations — Status: PASS
- **Database Schema Cleansing (`core/db/schema.py`):** Removed simulated default values (`0.15` EPSS, `V14.4.1` ASVS, `CWE-200`); all unverified metrics are nullable `None` or `"N/A"` (F-29).
- **Cascade Deletions & Integrity (`core/db/database.py`):** Configured SQLite foreign key listener (`PRAGMA foreign_keys=ON;`) ensuring atomic cascade deletion of vulnerabilities and attack logs when projects are deleted (F-24).
- **Project Retention & Management (`core/db/database.py`, `api/main.py`):** Added `delete_project` and `cleanup_old_projects` routines, and exposed REST endpoints (`GET /api/projects`, `GET /api/projects/{id}`, `DELETE /api/projects/{id}`) for full lifecycle control.
- **Sensitive Log Redaction (`core/logging_config.py`):** Implemented `SensitiveDataRedactor` filter that scrubs Bearer tokens, passwords, API keys, and RSA/EC private keys across all logging handlers (F-23).
- **Tests:** 3 passed (`tests/test_storage_ops.py`). Total suite: 30 passed.

## Phase 7: Final Regression, Benchmark Verification & Deliverables — Status: PASS
- **Regression Suite:** All 30 unit, integration, and platform tests execute and pass cleanly (`pytest tests/`).
- **Benchmark Runner Live Run:** Verified `benchmark/benchmark_runner.py` executes without errors and persists ground-truth evaluation metrics to `reports/benchmark_testbed_results.json`.
- **Documentation Deliverables Created:**
  - `CHANGELOG.md`: Detailed history of all architectural and security fixes across Phases 0–7.
  - `SECURITY.md`: Vulnerability disclosure process, safe operational guidelines, and scope rules.
  - `docs/THREAT_MODEL.md`: Full STRIDE threat analysis, scanner inversion risks, and mitigations.
  - `docs/DETECTOR_SUPPORT_MATRIX.md`: Comprehensive detector verification methods, PoC criteria, and false positive controls.
  - `docs/BENCHMARK_METHODOLOGY.md`: Synthetic benchmark architecture, case inventory, and statistical formulas.
  - `docs/PRODUCTION_READINESS.md`: Executive summary, F-01 through F-30 resolution matrix, compatibility matrix, and setup instructions.
- **Exit Gate (historical):** The original completion claim was overstated and is superseded by the final verification below.

## Final Phase 4 Verification (2026-11-21)

- Full `pytest` suite: **68 passed**.
- `python -m compileall -q .`: passed.
- Synthetic testbed: **34 measured / 34 planned**, 0 execution errors; TP=15, TN=16, FP=0, FN=3; Recall=83.3%, FPR=0%, Accuracy=91.2%, F1=90.9%.
- Three synthetic false negatives remain (two XSS, one SSRF). These measurements do not establish real-world detection performance.
- Report API tests cover HTML, JSON, SARIF, TXT, nullable database fields, and PDF failure isolation; successful PDF rendering is covered only when a local Chromium executable is available.
- API has no user authentication. Loopback checks do not isolate local processes; DNS socket pinning and browser request-gateway coverage remain incomplete.
- The UI’s simulated per-stage progress and fixed fallback scan duration were removed. The workflow labels do not imply PTES certification or comprehensive coverage.
- `docs/PRODUCTION_READINESS.md` and the old OWASP-branded report were corrected to describe the actual synthetic testbed and remaining limitations.
- **Status:** Not production-ready; use only for authorized local testing.
