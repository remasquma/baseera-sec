# Security Policy & Operational Guidelines - Baseera Sec

## 1. Scope & Security Philosophy
Baseera Sec is an experimental local scanner for authorized, defensive security evaluations. Because vulnerability scanners send adversarial payloads over the network and process untrusted target responses, **the scanner itself must be treated as security-sensitive software.**

---

## 2. Safe Scanning Operational Guidelines
When operating Baseera Sec in any environment:

1. **Authorization Mandatory:** Never scan systems or endpoints without prior written authorization from the system owners.
2. **Request Gateway:** Scanner HTTP requests routed through `core/network/request_gateway.py` receive target and redirect checks. Optional Chromium navigation and subresource requests do not use this gateway; SSRF protection is incomplete.
3. **Internal Network Protection:** Private destinations are blocked by default in gateway checks. DNS resolution is not pinned to the connected socket, so DNS rebinding is not fully mitigated. Scanning local environments requires explicit configuration via `allow_internal_targets=True`.
4. **Rate Limits & Budgets:** Configured request budgets and concurrency limits reduce accidental load but do not prevent all denial-of-service effects.

---

## 3. Vulnerability Disclosure Policy
We take vulnerabilities in Baseera Sec seriously. If you discover a security vulnerability within the platform:

- **Do NOT open a public GitHub issue.**
- Submit your vulnerability report privately to the development security team.
- Provide a detailed Proof of Concept (PoC) demonstrating:
  - Affected module and line numbers.
  - Reproduction steps.
  - Expected vs. actual behavior.
  - Impact assessment (CVSS v3.1 vector).

No private reporting contact or response SLA is currently configured in this
repository. Do not include secrets or sensitive target data in public reports.

---

## 4. Platform Security Architecture & Controls

### 4.1 Server-Side Request Forgery (SSRF) Defense
- DNS resolution and redirect destinations are checked by the HTTP request gateway.
- Resolved addresses are not pinned to sockets; this does not fully prevent DNS rebinding.
- Optional headless-browser traffic bypasses the request gateway.

### 4.2 File Upload & Code Ingestion Controls
- Maximum payload limit strictly enforced (25MB).
- Uploaded archives are assigned UUID filenames and unpacked inside disposable temporary directories.
- Strict Zip-Slip mitigation (`os.path.commonpath`), symlink rejection, and decompression bombs caps (50MB / 2,000 files).
- No uploaded files are ever executed or placed into web-accessible directories.

### 4.3 Browser Sandbox Architecture
- Headless Chrome processes are launched without `--no-sandbox`.
- Browser instances execute inside ephemeral temporary user data directories (`--user-data-dir`) with strict process timeouts and automated cleanup.

### 4.4 Data Protection & Redaction
- Configured logging filters redact common Authorization-token, password, API-key, and private-key formats; pattern-based redaction is not exhaustive.
- SQLite connections enforce foreign key integrity (`PRAGMA foreign_keys=ON;`) ensuring atomic cascade deletion.
