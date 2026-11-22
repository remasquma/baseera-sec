# Vulnerability Detector Support Matrix - Baseera Sec

This document summarizes implemented detector paths and their evidence limits. It is not a complete coverage claim; findings require analyst review, and unreported cases are not evidence of security.

---

## 1. Detector Capabilities & Verification Matrix

| Vulnerability Type | CWE ID | OWASP Top 10 | Primary Verification Engine | Evidence & PoC Criteria | False Positive Mitigation Strategy |
|---|---|---|---|---|---|
| **SQL Injection (Error-Based)** | CWE-89 | A03:2021-Injection | `SQLDetector` | DBMS error signatures can indicate SQL error disclosure; signatures alone do not prove data extraction or query control. | Baseline comparison; dynamic behavior and unrecognized error formats may affect results. |
| **SQL Injection (Boolean Blind)** | CWE-89 | A03:2021-Injection | `SQLDetector` | Tautological divergence: `AND 1=1` response matches baseline within 60 bytes, while `AND 1=2` strips content by > 80 bytes. | Mandatory repeatability confirmation step to filter out transient network jitter. |
| **Reflected Cross-Site Scripting (XSS)** | CWE-79 | A03:2021-Injection | `XSSDetector` | Canary token `<baseeraXSS...>` reflected into unescaped active DOM contexts (HTML body, attributes, script blocks). | BeautifulSoup context inspection: verifies token is not entity-encoded (`&lt;`) or enclosed in safe tags (`<title>`, `<textarea>`, comments). |
| **DOM-Based XSS** | CWE-79 | A03:2021-Injection | `DeepSpider` | Static source/sink indicators are heuristic; runtime execution and sanitization are not comprehensively verified. | Requires analyst validation; this is not browser-execution proof. |
| **Command Injection (CMDi)** | CWE-78 | A03:2021-Injection | `CMDiDetector` | Mathematical expression evaluation (`expr 48102 + 19283` -> `67385`) and POSIX identity output (`uid=.*gid=`). | Strict regex matching; excludes verbatim mirrored input reflections. |
| **Path Traversal / LFI** | CWE-22 | A01:2021-Broken Access Control | `TraversalDetector` | Exposure of sensitive system files (`/etc/passwd`, `win.ini`) matching root account regex (`root:.*:0:0:`). | Baseline subtraction: ensures detected patterns do not already exist in normal unprobed responses. |
| **Server-Side Request Forgery (SSRF)** | CWE-918 | A10:2021-SSRF | `SSRFDetector` | Limited parameter probes; no out-of-band callback confirmation is implemented. | HTTP scanner requests pass through `RequestGateway`; optional headless browser traffic bypasses it. DNS is not socket-pinned. Do not treat reflection alone as SSRF proof. |
| **Insecure Direct Object Reference (IDOR)** | CWE-639 | A01:2021-Broken Access Control | `IDORDetector` | Account A reads its resource; account B reads its own distinct resource and then requests A's resource. A finding requires the cross-account response to contain matching sensitive identity fields from A's record. | Requires distinct auth headers and same-origin resource URLs. Status or response differences alone do not confirm IDOR; without both accounts the result is inconclusive. |
| **CORS Misconfiguration** | CWE-942 | A05:2021-Security Misconfiguration | `HeaderAuditor` | Arbitrary `Origin` reflection accompanied by `Access-Control-Allow-Credentials: true`. | Verifies credentials header; wildcard `*` without credentials correctly assessed as Low risk. |
| **Sensitive File Exposure (.git / .env)** | CWE-552 | A05:2021-Security Misconfiguration | `PathCrawler` / `ProofValidator` | Valid `.git/HEAD` ref headers (`ref: refs/heads/`) or `.env` configuration keys (`DB_PASSWORD=`, `SECRET_KEY=`). | Rejects generic 200 SPA catch-alls by requiring specific internal file structure validation. |
| **Missing Security Headers** | CWE-319, CWE-1021, CWE-693 | A05:2021-Security Misconfiguration | `HeaderAuditor` | Missing `HSTS`, `CSP`, `X-Frame-Options`, `X-Content-Type-Options`. | Context-aware severity: HSTS on plain HTTP downgraded to Informational; flags missing only when protocol is HTTPS. |
| **Static Code Secrets / SAST** | CWE-798 | A07:2021-Identification & Auth | `LocalPackageAuditor` | Contextual credential assignments are filtered using value length and Shannon entropy; PEM private-key markers are recognized separately. | Known placeholder values are suppressed; values are redacted from findings. Entropy is a heuristic and can miss low-entropy secrets or flag unusual examples. |

---

## 2. Confidence & Risk Scoring Model
Some legacy detector paths still use heuristic or fixed confidence values. These values are not calibrated probabilities. Attack outcomes are limited to the tested request and do not establish that the target is globally secure:

- `EXPLOITED_CONFIRMED`: Mathematical or cryptographic proof of exploitability (e.g., boolean divergence, arithmetic command evaluation, extracted `/etc/passwd` root lines).
- `HEURISTIC_POTENTIAL`: Observable anomaly requiring analyst review (e.g., database syntax leakage without proved control of SQL query structure).
- `TARGET_SECURE`: The selected check did not confirm the specific tested condition; it does not mean the endpoint or target is secure.
- `INCONCLUSIVE`: Required evidence or dual-account credentials were unavailable.
