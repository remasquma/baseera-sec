# Benchmark Methodology & Accuracy Evaluation - Baseera Sec

## 1. Executive Summary & Clarification of Scope
Previous prototype versions of Baseera Sec labeled their internal test runner as the *"Official OWASP Benchmark"*, which was misleading. The real OWASP Benchmark is an automated test suite containing 2,740 test cases designed primarily for Java-based SAST/DAST tools.

To maintain engineering integrity and scientific accuracy, this harness has been formally codified and renamed:
**Baseera Sec Synthetic Verification Benchmark Testbed**

The testbed consists of a standalone, self-contained FastAPI application (`benchmark/testbed.py`) running 34 precisely designed test cases covering both True Positives (vulnerable implementations) and True Negatives (defensively hardened implementations).

---

## 2. Testbed Architecture & Test Case Inventory

The testbed executes on `http://127.0.0.1:8888` and evaluates six major vulnerability categories:

### Distribution of Test Cases (34 Total)
1. **SQL Injection (CWE-89):** 10 Cases (5 True Positives, 5 True Negatives)
   - *TP:* Raw string concatenation, numeric unquoted injection, boolean blind divergence, auth bypass, syntax leakage.
   - *TN:* PreparedStatements, numeric type casting, whitelist validation, safe ORM queries, parameterized wildcards.
2. **Cross-Site Scripting (CWE-79):** 10 Cases (5 True Positives, 5 True Negatives)
   - *TP:* Unescaped body reflection, unquoted attribute reflection, JavaScript block reflection, event handler injection, DOM-based source/sink flows.
   - *TN:* Full HTML entity encoding (`html.escape`), quoted and sanitized attributes, non-executable tag containers (`<textarea>`, `<title>`), safe numeric context, sanitized DOM innerText.
3. **Command Injection (CWE-78):** 5 Cases (3 True Positives, 2 True Negatives)
   - *TP:* Direct `os.system` interpolation, command chaining with semicolons, backtick command execution.
   - *TN:* `shlex.quote` argument sanitization, strict regex IPv4 validation.
4. **Path Traversal / LFI (CWE-22):** 4 Cases (2 True Positives, 2 True Negatives)
   - *TP:* Relative traversal (`../../etc/passwd`), absolute path disclosure (`/etc/passwd`).
   - *TN:* Strict `os.path.basename` extraction, explicit whitelist filename mapping.
5. **Server-Side Request Forgery (CWE-918):** 2 Cases (1 True Positive, 1 True Negative)
   - *TP:* Unrestricted backend fetch of arbitrary remote URLs.
   - *TN:* Strict domain whitelist enforcement blocking private and internal addresses.
6. **Security Misconfiguration (CWE-16 / CWE-942 / CWE-552):** 3 Cases (2 True Positives, 1 True Negative)
   - *TP:* Permissive CORS origin reflection with credentials, public `.env` secrets file exposure.
   - *TN:* Hardened security headers including strict Content Security Policy (CSP) and HSTS.

---

## 3. Evaluation & Association Logic

When evaluating a web scanner against a multi-endpoint benchmark, a critical architectural challenge is **cross-endpoint contamination**: an automated crawler will discover and flag vulnerabilities across the entire site during a scan.

To reduce cross-endpoint attribution errors:
1. **Path-Anchored Association:** The benchmark harness extracts `case_path = urlsplit(case["url"]).path` and verifies that the reported vulnerability's `affected_url` or `poc_evidence` specifically matches `case_path`.
2. **Taxonomy Verification:** The reported vulnerability must match the designated `CWE ID` or canonical category name. This matching rule does not establish that the synthetic cases represent real-world performance.
3. **Ground Truth Validation:** If the target endpoint is classified as `expected_vulnerable = False`, any vulnerability detected on that specific endpoint is scored as a **False Positive (FP)**; if clean, it is scored as a **True Negative (TN)**.

---

## 4. Statistical Metrics & Mathematical Formulas

The harness computes a standard confusion matrix:
- **True Positive (TP):** Vulnerability exists and was accurately detected.
- **True Negative (TN):** Endpoint is secure and scanner reported it clean.
- **False Positive (FP):** Endpoint is secure but scanner incorrectly reported a vulnerability.
- **False Negative (FN):** Vulnerability exists but scanner failed to detect it.

Benchmark case query parameter names must match the testbed route signatures.
The benchmark integrity test validates each case URL and declared parameter
against the corresponding FastAPI endpoint before any score is interpreted.

### Evaluation Formulas:
$$\text{Recall (TPR)} = \frac{\text{TP}}{\text{TP} + \text{FN}}$$

$$\text{False Positive Rate (FPR)} = \frac{\text{FP}}{\text{FP} + \text{TN}}$$

$$\text{False Negative Rate (FNR)} = \frac{\text{FN}}{\text{TP} + \text{FN}}$$

$$\text{Precision} = \frac{\text{TP}}{\text{TP} + \text{FP}}$$

$$\text{Accuracy} = \frac{\text{TP} + \text{TN}}{\text{TP} + \text{TN} + \text{FP} + \text{FN}}$$

$$F_1\text{-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

Only cases that completed with a measured scanner result contribute to the confusion matrix and its metrics. Execution errors are listed separately in the JSON output; they are not silently counted as true negatives or false negatives. The scorecard reports both the planned case count and the number of measured cases.

---

## 5. Execution & Reproducibility

The benchmark can be executed live via CLI or REST API:

### Command Line:
```bash
# Activate virtual environment
source .venv/bin/activate

# Execute benchmark harness
python benchmark/benchmark_runner.py
```

### Output Artifacts:
- Raw Machine-Readable Data: `reports/benchmark_testbed_results.json`
- Formatted Markdown Report: `reports/Synthetic_Benchmark_Evaluation_Report.md`
- `sample_size` is the number of evaluated cases; `planned_cases` and `error_cases` retain execution coverage details.

### REST API:
- `POST /api/v1/benchmark/run`: Triggers asynchronous benchmark execution.
- `GET /api/v1/benchmark/latest`: Retrieves the latest scorecard JSON.
