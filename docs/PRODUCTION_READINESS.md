# Baseera Sec: Final Phase 4 Verification

## Assessment

Baseera Sec is an experimental, single-user local scanner. This verification
does not establish production readiness, comprehensive security coverage, or
zero false positives. The API has no user authentication and must not be
exposed on a network. Run it on loopback only.

The workflow borrows selected ideas from PTES and NIST SP 800-115; it does not
implement or certify either methodology. The dashboard presents a workflow
overview, not measured per-phase progress.

## Phase 4 changes

- Added Shannon entropy scoring and placeholder suppression to local secret
  scanning. Entropy is a heuristic, not proof that a value is a live secret.
- IDOR confirmation now requires two independently authenticated accounts,
  separate owner/control records on the same origin, and matching sensitive
  identity fields. Missing evidence is inconclusive; response differences
  alone do not prove IDOR.
- Removed the obsolete cloud-AI integration and replaced the former API-key
  status UI with local model diagnostics. Model labels remain unverified, so
  neural outputs are not security classifications or calibrated probabilities.
- API requests are restricted to loopback with local Host/origin checks and
  CORS credentials disabled. This is not user authentication or local-process
  isolation.
- Scanner HTTP requests use `RequestGateway`, but DNS is not pinned to the
  connected socket and optional browser traffic bypasses the gateway. SSRF
  protection is therefore incomplete.
- Updated dashboard copy to avoid claiming full PTES execution, live
  per-stage work, verified EPSS, comprehensive coverage, or fixed scan
  duration.
- Replaced the obsolete OWASP-branded benchmark report with the current
  synthetic testbed results.

## Verification results

Latest full local run:

| Check | Result |
|---|---|
| `python -m compileall -q .` | Passed |
| `python -m pytest -q` | 68 passed |
| Synthetic testbed | 34/34 measured; 0 execution errors |
| Confusion matrix | TP 15, TN 16, FP 0, FN 3 |
| Recall / FPR / accuracy / F1 | 83.3% / 0.0% / 91.2% / 90.9% |
| Local API smoke checks | Dashboard and model status responded; latest benchmark API returned the same 34-case results |
| Browser check | Arabic/English UI and benchmark modal rendered measured values; no external page resources were requested |
| Report API tests | 3 passed: HTML, JSON, SARIF, TXT, nullable fields, PDF generation, and PDF-failure isolation |

These are measurements on the repository's 34-case synthetic suite only, not
the official OWASP Benchmark and not a prediction of performance on real
targets. Three false negatives remain (two XSS, one SSRF).

The nullable-record report fixture produced HTML with `N/A / 10`, JSON with a
`null` CVSS value, and TXT with an unavailable peak score; the PDF endpoint
returned a PDF in this environment. A separate test confirms that PDF renderer
failure returns an explicit error without blocking TXT export. PDF generation
requires Chromium on other installations.

## Known limitations and residual risks

- No user authentication, authorization, or multi-user isolation on the API;
  other local processes can call it.
- Never bind to `0.0.0.0` or publish through a reverse proxy, port forwarding,
  or a shared host.
- DNS rebinding is not fully mitigated because resolved addresses are not
  pinned at the socket layer. Headless-browser traffic is outside the request
  gateway.
- Neural classifier labels and training provenance are unknown. LightGBM
  loading is blocked by a scikit-learn version mismatch. Do not rely on model
  outputs for security decisions.
- Detector coverage is limited and false negatives/positives remain possible.
  The synthetic benchmark is small and not independently validated.
- Log redaction is pattern-based and cannot guarantee removal of every
  sensitive value.
- PDF generation requires a supported local Chromium executable.

## Supported report exports

The API retains HTML, JSON, SARIF, PDF, and TXT export routes. HTML, JSON,
SARIF, and TXT are covered by automated tests using nullable fields. PDF
failure is isolated from other formats; successful real PDF rendering should
only be claimed when Chromium is installed and that path passes.

## Safe local operation

Create a Python virtual environment, install `requirements.txt`, and run the
application using its loopback-bound default. Consult [README.md](../README.md)
and [THREAT_MODEL.md](./THREAT_MODEL.md) for setup and operational limits.
