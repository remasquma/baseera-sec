# Baseera Sec Threat Model

## Trust boundaries

- **Untrusted:** target URLs and responses, discovered links, API specifications,
  uploaded archives and source files, and user-supplied authentication data.
- **Local application:** FastAPI API/UI, scanner, local model artifacts, SQLite,
  and report generation.
- **External network:** target traffic is intentional when a user starts a scan.
  The dashboard does not load external fonts or call a cloud AI service.

## Implemented protections

| Area | Protection | Limit |
|---|---|---|
| API listener | `app.py` binds to `127.0.0.1`; middleware rejects non-loopback clients and non-local Host headers. | There is no user authentication or multi-user isolation. Other local processes can call the API. Do not expose it through a reverse proxy, port forwarding, or `0.0.0.0`. |
| Browser-origin requests | Mutating requests with a non-local Origin or `Sec-Fetch-Site: cross-site` are rejected; CORS credentials are disabled. | This is local-service CSRF mitigation, not API authentication. Missing Origin requests from local programs are accepted. |
| Scan scope | HTTP scanner requests pass through `RequestGateway`, which checks the allowed hostname and validates each redirect destination. Private targets are blocked by default. | Internal-target opt-in deliberately permits private addresses within the configured target hostname. DNS is checked before connecting but the underlying HTTP client does not pin the resolved IP; DNS rebinding is not fully mitigated. |
| Browser crawler | Chrome/Chromium is optional and uses the existing crawler configuration. | Browser navigation and subresource traffic do not pass through `RequestGateway`; treat headless scans as a remaining scope/SSRF risk. |
| Uploads | API limits upload size; scanner limits archive file count, total expanded size and per-file scan size, and extracts to a temporary directory. | Uploaded code is untrusted input. Review archive handling and run uploads with OS-level least privilege. |
| Local models | Transformer tensors are checked and invalid tensors are rejected; unverified labels are not treated as security predictions. | Serialized pickle artifacts must be trusted. Training provenance and label semantics remain unavailable. |
| Reports and logs | Optional report fields are rendered as unavailable; HTML values are escaped; configured log filters redact common secret formats. | Redaction is pattern-based and cannot guarantee removal of every sensitive value from arbitrary logs. |

## Main residual risks

1. The API has no user authentication. Loopback-only binding limits remote
   reachability but does not isolate local users or processes.
2. DNS validation is not socket-level IP pinning, and the optional headless
   browser bypasses the request gateway. Do not treat either control as a
   complete SSRF defense.
3. Internal target mode can access private addresses on the selected hostname;
   use it only for explicitly owned test targets.
4. The detector suite and 34-case synthetic testbed are not comprehensive
   security assurance. False negatives and false positives remain possible.
5. Local neural model outputs are diagnostic only. They are not calibrated
   security probabilities or verified benign/malicious classifications.

The application is intended for single-user local testing, not network
deployment or production security monitoring.
