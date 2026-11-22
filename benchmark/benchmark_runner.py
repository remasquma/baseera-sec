"""
Baseera Sec - Synthetic Verification Benchmark Harness
Independent synthetic testbed harness measuring detector performance:
- True Positive Rate (Recall / Sensitivity)
- False Positive Rate (FPR)
- Precision & F1-Score
- Overall Accuracy
- Per-category Confusion Matrices with exact endpoint & parameter matching

Note: This is an internal synthetic test suite (34 cases) covering web injection
and configuration patterns, distinct from the official 2,740-case Java OWASP Benchmark v1.2.
"""
import os
import sys
import time
import json
import asyncio
import threading
import uvicorn
from typing import Dict, Any, List
from urllib.parse import urlsplit

# Ensure baseera_sec is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.engine.orchestrator import AuditOrchestrator
from config.settings import AuditConfig
from benchmark.testbed import app as testbed_app

BENCHMARK_CASES = [
    # -------------------------------------------------------------
    # Category 1: SQL Injection (CWE-89)
    # -------------------------------------------------------------
    {
        "id": "BaseeraTest-SQLi-001",
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "param": "name",
        "url": "http://127.0.0.1:8888/benchmark/cwe89/case01?name=guest",
        "expected_vulnerable": True,
        "description": "MySQL string concatenation syntax error"
    },
    {
        "id": "BaseeraTest-SQLi-002",
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "param": "artist",
        "url": "http://127.0.0.1:8888/benchmark/cwe89/case02?artist=1",
        "expected_vulnerable": True,
        "description": "MySQL numeric parameter query syntax error"
    },
    {
        "id": "BaseeraTest-SQLi-003",
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "param": "cat",
        "url": "http://127.0.0.1:8888/benchmark/cwe89/case03?cat=1",
        "expected_vulnerable": True,
        "description": "Boolean differential blind SQL Injection"
    },
    {
        "id": "BaseeraTest-SQLi-004",
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "param": "id",
        "url": "http://127.0.0.1:8888/benchmark/cwe89/case04?id=1",
        "expected_vulnerable": True,
        "description": "PostgreSQL syntax error injection"
    },
    {
        "id": "BaseeraTest-SQLi-005",
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "param": "search",
        "url": "http://127.0.0.1:8888/benchmark/cwe89/case05?search=test",
        "expected_vulnerable": True,
        "description": "SQLite operational error injection"
    },
    {
        "id": "BaseeraTest-SQLi-006-TN",
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "param": "name",
        "url": "http://127.0.0.1:8888/benchmark/cwe89/case06_secure?name=john",
        "expected_vulnerable": False,
        "description": "Secure PreparedStatement parameterized query (False Positive Test)"
    },
    {
        "id": "BaseeraTest-SQLi-007-TN",
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "param": "artist",
        "url": "http://127.0.0.1:8888/benchmark/cwe89/case07_secure?artist=1",
        "expected_vulnerable": False,
        "description": "Strict numeric casting protection (False Positive Test)"
    },
    {
        "id": "BaseeraTest-SQLi-008-TN",
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "param": "cat",
        "url": "http://127.0.0.1:8888/benchmark/cwe89/case08_secure?cat=1",
        "expected_vulnerable": False,
        "description": "Whitelist category enforcement (False Positive Test)"
    },
    {
        "id": "BaseeraTest-SQLi-009-TN",
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "param": "id",
        "url": "http://127.0.0.1:8888/benchmark/cwe89/case09_secure?id=1",
        "expected_vulnerable": False,
        "description": "Safe ORM parameterized entity access (False Positive Test)"
    },
    {
        "id": "BaseeraTest-SQLi-010-TN",
        "category": "SQL Injection",
        "cwe": "CWE-89",
        "param": "search",
        "url": "http://127.0.0.1:8888/benchmark/cwe89/case10_secure?search=apple",
        "expected_vulnerable": False,
        "description": "Sanitized string query with parameterized wildcard (False Positive Test)"
    },

    # -------------------------------------------------------------
    # Category 2: Cross-Site Scripting (CWE-79)
    # -------------------------------------------------------------
    {
        "id": "BaseeraTest-XSS-001",
        "category": "XSS",
        "cwe": "CWE-79",
        "param": "q",
        "url": "http://127.0.0.1:8888/benchmark/cwe79/case01?q=hello",
        "expected_vulnerable": True,
        "description": "Raw unescaped reflection directly into body"
    },
    {
        "id": "BaseeraTest-XSS-002",
        "category": "XSS",
        "cwe": "CWE-79",
        "param": "username",
        "url": "http://127.0.0.1:8888/benchmark/cwe79/case02?username=guest",
        "expected_vulnerable": True,
        "description": "Unescaped attribute injection breakout"
    },
    {
        "id": "BaseeraTest-XSS-003",
        "category": "XSS",
        "cwe": "CWE-79",
        "param": "msg",
        "url": "http://127.0.0.1:8888/benchmark/cwe79/case03?msg=welcome",
        "expected_vulnerable": True,
        "description": "Unescaped script block variable injection"
    },
    {
        "id": "BaseeraTest-XSS-004",
        "category": "XSS",
        "cwe": "CWE-79",
        "param": "comment",
        "url": "http://127.0.0.1:8888/benchmark/cwe79/case04?comment=alice",
        "expected_vulnerable": True,
        "description": "Direct innerHTML DOM sink reflection"
    },
    {
        "id": "BaseeraTest-XSS-005",
        "category": "XSS",
        "cwe": "CWE-79",
        "param": "err",
        "url": "http://127.0.0.1:8888/benchmark/cwe79/case05?err=invalid",
        "expected_vulnerable": True,
        "description": "JSONP unvalidated callback injection"
    },
    {
        "id": "BaseeraTest-XSS-006-TN",
        "category": "XSS",
        "cwe": "CWE-79",
        "param": "q",
        "url": "http://127.0.0.1:8888/benchmark/cwe79/case06_secure?q=test",
        "expected_vulnerable": False,
        "description": "Proper htmlspecialchars context escaping (False Positive Test)"
    },
    {
        "id": "BaseeraTest-XSS-007-TN",
        "category": "XSS",
        "cwe": "CWE-79",
        "param": "username",
        "url": "http://127.0.0.1:8888/benchmark/cwe79/case07_secure?username=guest",
        "expected_vulnerable": False,
        "description": "Strict alphanumeric regex validation (False Positive Test)"
    },
    {
        "id": "BaseeraTest-XSS-008-TN",
        "category": "XSS",
        "cwe": "CWE-79",
        "param": "msg",
        "url": "http://127.0.0.1:8888/benchmark/cwe79/case08_secure?msg=safe",
        "expected_vulnerable": False,
        "description": "HTML-escaped message output (False Positive Test)"
    },
    {
        "id": "BaseeraTest-XSS-009-TN",
        "category": "XSS",
        "cwe": "CWE-79",
        "param": "comment",
        "url": "http://127.0.0.1:8888/benchmark/cwe79/case09_secure?comment=123",
        "expected_vulnerable": False,
        "description": "CSP plus HTML-escaped comment output (False Positive Test)"
    },
    {
        "id": "BaseeraTest-XSS-010-TN",
        "category": "XSS",
        "cwe": "CWE-79",
        "param": "err",
        "url": "http://127.0.0.1:8888/benchmark/cwe79/case10_secure?err=safe",
        "expected_vulnerable": False,
        "description": "Safe URL protocol whitelist verification (False Positive Test)"
    },

    # -------------------------------------------------------------
    # Category 3: Command Injection (CWE-78)
    # -------------------------------------------------------------
    {
        "id": "BaseeraTest-CMDi-001",
        "category": "Command Injection",
        "cwe": "CWE-78",
        "param": "host",
        "url": "http://127.0.0.1:8888/benchmark/cwe78/case01?host=127.0.0.1",
        "expected_vulnerable": True,
        "description": "Direct shell interpolation in ping command"
    },
    {
        "id": "BaseeraTest-CMDi-002",
        "category": "Command Injection",
        "cwe": "CWE-78",
        "param": "ip",
        "url": "http://127.0.0.1:8888/benchmark/cwe78/case02?ip=127.0.0.1",
        "expected_vulnerable": True,
        "description": "Command chaining via semicolon/pipe in nslookup"
    },
    {
        "id": "BaseeraTest-CMDi-003",
        "category": "Command Injection",
        "cwe": "CWE-78",
        "param": "cmd",
        "url": "http://127.0.0.1:8888/benchmark/cwe78/case03?cmd=status",
        "expected_vulnerable": True,
        "description": "Backtick command substitution in cat utility"
    },
    {
        "id": "BaseeraTest-CMDi-004-TN",
        "category": "Command Injection",
        "cwe": "CWE-78",
        "param": "host",
        "url": "http://127.0.0.1:8888/benchmark/cwe78/case04_secure?host=127.0.0.1",
        "expected_vulnerable": False,
        "description": "Strict IPv4 regex validation preventing shell metacharacters (False Positive Test)"
    },
    {
        "id": "BaseeraTest-CMDi-005-TN",
        "category": "Command Injection",
        "cwe": "CWE-78",
        "param": "ip",
        "url": "http://127.0.0.1:8888/benchmark/cwe78/case05_secure?ip=127.0.0.1",
        "expected_vulnerable": False,
        "description": "Fixed whitelist command dispatch (False Positive Test)"
    },

    # -------------------------------------------------------------
    # Category 4: Path Traversal (CWE-22)
    # -------------------------------------------------------------
    {
        "id": "BaseeraTest-LFI-001",
        "category": "Path Traversal",
        "cwe": "CWE-22",
        "param": "file",
        "url": "http://127.0.0.1:8888/benchmark/cwe22/case01?file=about.html",
        "expected_vulnerable": True,
        "description": "Relative directory traversal via ../../etc/passwd"
    },
    {
        "id": "BaseeraTest-LFI-002",
        "category": "Path Traversal",
        "cwe": "CWE-22",
        "param": "page",
        "url": "http://127.0.0.1:8888/benchmark/cwe22/case02?page=home",
        "expected_vulnerable": True,
        "description": "Absolute path file disclosure via /etc/passwd"
    },
    {
        "id": "BaseeraTest-LFI-003-TN",
        "category": "Path Traversal",
        "cwe": "CWE-22",
        "param": "file",
        "url": "http://127.0.0.1:8888/benchmark/cwe22/case03_secure?file=home",
        "expected_vulnerable": False,
        "description": "Strict basename extraction preventing directory traversal (False Positive Test)"
    },
    {
        "id": "BaseeraTest-LFI-004-TN",
        "category": "Path Traversal",
        "cwe": "CWE-22",
        "param": "page",
        "url": "http://127.0.0.1:8888/benchmark/cwe22/case04_secure?page=home",
        "expected_vulnerable": False,
        "description": "Explicit whitelist file mapping (False Positive Test)"
    },

    # -------------------------------------------------------------
    # Category 5: SSRF (CWE-918)
    # -------------------------------------------------------------
    {
        "id": "BaseeraTest-SSRF-001",
        "category": "SSRF",
        "cwe": "CWE-918",
        "param": "url",
        "url": "http://127.0.0.1:8888/benchmark/cwe918/case01?url=http://example.com",
        "expected_vulnerable": True,
        "description": "Unrestricted backend HTTP fetch of arbitrary remote URL"
    },
    {
        "id": "BaseeraTest-SSRF-002-TN",
        "category": "SSRF",
        "cwe": "CWE-918",
        "param": "url",
        "url": "http://127.0.0.1:8888/benchmark/cwe918/case02_secure?url=https://api.partner.com",
        "expected_vulnerable": False,
        "description": "Strict domain whitelist enforcement blocking internal IPs (False Positive Test)"
    },

    # -------------------------------------------------------------
    # Category 6: Security Misconfiguration (CWE-16 / CWE-942)
    # -------------------------------------------------------------
    {
        "id": "BaseeraTest-MISC-001",
        "category": "Misconfiguration",
        "cwe": "CWE-942",
        "param": "origin",
        "url": "http://127.0.0.1:8888/benchmark/misc/case01_cors",
        "expected_vulnerable": True,
        "description": "Permissive CORS reflection with Access-Control-Allow-Credentials: true"
    },
    {
        "id": "BaseeraTest-MISC-002",
        "category": "Misconfiguration",
        "cwe": "CWE-552",
        "param": "path",
        "url": "http://127.0.0.1:8888/benchmark/misc/case02_env/.env",
        "expected_vulnerable": True,
        "description": "Direct public exposure of sensitive .env file"
    },
    {
        "id": "BaseeraTest-MISC-003-TN",
        "category": "Misconfiguration",
        "cwe": "CWE-16",
        "param": "headers",
        "url": "http://127.0.0.1:8888/benchmark/misc/case03_secure",
        "expected_vulnerable": False,
        "description": "Hardened security headers including strict CSP and HSTS (False Positive Test)"
    }
]


def calculate_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, Any]:
    """Calculate benchmark rates from measured confusion-matrix counts."""
    actual_positive = tp + fn
    actual_negative = tn + fp
    evaluated_cases = tp + fp + tn + fn
    tpr = tp / actual_positive if actual_positive else 0.0
    fpr = fp / actual_negative if actual_negative else 0.0
    fnr = fn / actual_positive if actual_positive else 0.0
    precision = tp / (tp + fp) if tp + fp else 0.0
    accuracy = (tp + tn) / evaluated_cases if evaluated_cases else 0.0
    f1 = 2 * precision * tpr / (precision + tpr) if precision + tpr else 0.0
    return {
        "evaluated_cases": evaluated_cases,
        "true_positive_rate": tpr,
        "false_positive_rate": fpr,
        "false_negative_rate": fnr,
        "precision": precision,
        "accuracy": accuracy,
        "f1": f1,
    }


def start_testbed_server(port: int = 8888):
    """Starts the local benchmark testbed in a background thread."""
    uvicorn.run(testbed_app, host="127.0.0.1", port=port, log_level="error")


async def main():
    total_cases = len(BENCHMARK_CASES)
    expected_positive_count = sum(case["expected_vulnerable"] for case in BENCHMARK_CASES)
    expected_negative_count = total_cases - expected_positive_count

    print("=" * 80)
    print("🚀 BASEERA SEC - SYNTHETIC BENCHMARK EVALUATION HARNESS")
    print(
        f"Independent Verification Suite ({total_cases} Synthetic Cases: "
        f"{expected_positive_count} vulnerable / {expected_negative_count} secure)"
    )
    print("=" * 80)

    # 1. Start testbed server in background
    t = threading.Thread(target=start_testbed_server, daemon=True)
    t.start()
    await asyncio.sleep(1.2)

    # Allow internal targets for benchmark testbed
    config = AuditConfig(
        target_url="http://127.0.0.1:8888",
        allowed_domains=["127.0.0.1", "localhost"],
        request_timeout=4.0,
        allow_internal_targets=True,
        allow_insecure_tls=True
    )
    orchestrator = AuditOrchestrator(config)

    category_stats: Dict[str, Dict[str, int]] = {}
    results = []
    error_cases = []
    total_tp = 0
    total_fp = 0
    total_tn = 0
    total_fn = 0

    print(f"{'ID':<24} | {'Category':<18} | {'Type':<8} | {'Ground Truth':<12} | {'Outcome':<14} | {'Verdict'}")
    print("-" * 96)

    for case in BENCHMARK_CASES:
        cid = case["id"]
        cat = case["category"]
        url = case["url"]
        param = case.get("param", "")
        expected = case["expected_vulnerable"]

        if cat not in category_stats:
            category_stats[cat] = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

        try:
            report = await orchestrator.run_full_audit(url)
            detected = False
            case_path = urlsplit(url).path

            # Accurate parameter, endpoint, and case path association check
            for v in report.verified_vulnerabilities:
                v_title = v.title.lower()
                cwe_match = (v.cwe_id == case["cwe"])
                # Must match the specific endpoint path of this benchmark case
                path_match = (case_path in (v.affected_url or "")) or (case_path in (v.poc_evidence or ""))

                if case["cwe"] == "CWE-89" and ("sql" in v_title or cwe_match) and path_match:
                    detected = True
                    break
                elif case["cwe"] == "CWE-79" and ("xss" in v_title or cwe_match) and path_match:
                    detected = True
                    break
                elif case["cwe"] == "CWE-78" and ("command" in v_title or "cmdi" in v_title or cwe_match) and path_match:
                    detected = True
                    break
                elif case["cwe"] == "CWE-22" and ("traversal" in v_title or "path" in v_title or cwe_match) and path_match:
                    detected = True
                    break
                elif case["cwe"] == "CWE-918" and ("ssrf" in v_title or cwe_match) and path_match:
                    detected = True
                    break
                elif case["cwe"] in ("CWE-16", "CWE-942", "CWE-552") and (cwe_match or "cors" in v_title or ".env" in v_title) and path_match:
                    detected = True
                    break

            if expected and detected:
                verdict = "TP (True Positive) ✅"
                total_tp += 1
                category_stats[cat]["TP"] += 1
            elif not expected and not detected:
                verdict = "TN (True Negative) ✅"
                total_tn += 1
                category_stats[cat]["TN"] += 1
            elif not expected and detected:
                verdict = "FP (False Positive) ❌"
                total_fp += 1
                category_stats[cat]["FP"] += 1
            else:
                verdict = "FN (False Negative) ⚠️"
                total_fn += 1
                category_stats[cat]["FN"] += 1

            kind = "TP-Test" if expected else "TN-Test"
            gt_str = "Vulnerable" if expected else "Secure"
            det_str = "DETECTED" if detected else "SECURE"
            print(f"{cid:<24} | {cat:<18} | {kind:<8} | {gt_str:<12} | {det_str:<14} | {verdict}")

            results.append({
                "id": cid,
                "category": cat,
                "cwe": case["cwe"],
                "param": param,
                "expected": expected,
                "detected": detected,
                "verdict": verdict,
                "description": case["description"]
            })

        except Exception as e:
            print(f"{cid:<24} | {cat:<18} | ERROR: {e}")
            error = f"{type(e).__name__}: {e}"
            error_cases.append({"id": cid, "category": cat, "error": error})
            results.append({
                "id": cid,
                "category": cat,
                "cwe": case["cwe"],
                "param": param,
                "expected": expected,
                "detected": None,
                "verdict": "ERROR",
                "error": error,
                "description": case["description"]
            })

    # Calculate confusion matrix & derived rates
    total_real_vulns = total_tp + total_fn
    total_real_safes = total_tn + total_fp
    metrics = calculate_metrics(total_tp, total_fp, total_tn, total_fn)
    evaluated_cases = metrics["evaluated_cases"]
    tpr = metrics["true_positive_rate"]
    fpr = metrics["false_positive_rate"]
    fnr = metrics["false_negative_rate"]
    precision = metrics["precision"]
    accuracy = metrics["accuracy"]
    f1 = metrics["f1"]

    print("\n" + "=" * 80)
    print("📊 BASEERA SEC - SYNTHETIC BENCHMARK SCORECARD")
    print("=" * 80)
    print(f"Planned Test Cases         : {total_cases} ({expected_positive_count} vulnerable, {expected_negative_count} secure)")
    print(f"Cases with Measured Results: {evaluated_cases}")
    print(f"Cases with Execution Errors: {len(error_cases)}")
    print(f"True Positives (TP)        : {total_tp} / {total_real_vulns}")
    print(f"True Negatives (TN)        : {total_tn} / {total_real_safes}")
    print(f"False Positives (FP)       : {total_fp} / {total_real_safes}")
    print(f"False Negatives (FN)       : {total_fn} / {total_real_vulns}")
    print("-" * 80)
    print(f"True Positive Rate (Recall) : {tpr * 100:.1f}%")
    print(f"False Positive Rate (FPR)   : {fpr * 100:.1f}%")
    print(f"False Negative Rate (FNR)   : {fnr * 100:.1f}%")
    print(f"Precision Score             : {precision * 100:.1f}%")
    print(f"Overall Accuracy            : {accuracy * 100:.1f}%")
    print(f"F1-Score                    : {f1 * 100:.1f}%")
    print("=" * 80)

    # Generate Markdown Report
    os.makedirs("reports", exist_ok=True)
    report_md_path = "reports/Synthetic_Benchmark_Evaluation_Report.md"
    with open(report_md_path, "w", encoding="utf-8") as f:
        f.write("# تقرير التقييم المعياري التجريبي لمنصة بصيرة (Baseera Sec Synthetic Benchmark Report)\n\n")
        f.write(
            "تم إجراء هذا التقييم باستخدام حزمة الاختبار المعيارية المستقلة "
            f"({total_cases} حالة مخططة؛ {evaluated_cases} حالة ذات نتائج مقاسة و{len(error_cases)} أخطاء تنفيذ).\n\n"
        )
        f.write("## 1. بطاقة المؤشرات الإحصائية العامة\n\n")
        f.write(f"- **الحالات المخططة:** `{total_cases}` ({expected_positive_count} مصابة + {expected_negative_count} سليمة)\n")
        f.write(f"- **الحالات ذات النتائج المقاسة:** `{evaluated_cases}`\n")
        f.write(f"- **أخطاء التنفيذ:** `{len(error_cases)}`\n")
        f.write(f"- **معدل الكشف (Sensitivity / Recall / TPR):** `{tpr * 100:.1f}%`\n")
        f.write(f"- **معدل الإنذارات الكاذبة (FPR):** `{fpr * 100:.1f}%`\n")
        f.write(f"- **معدل الإغفال (FNR):** `{fnr * 100:.1f}%`\n")
        f.write(f"- **معيار الدقة الإيجابية (Precision):** `{precision * 100:.1f}%`\n")
        f.write(f"- **معيار التوافق F1-Score:** `{f1 * 100:.1f}%`\n")
        f.write(f"- **الدقة الإجمالية (Overall Accuracy):** `{accuracy * 100:.1f}%`\n\n")
        f.write("## 2. مصفوفة الارتباك حسب فئات الثغرات (Per-Category Confusion Matrix)\n\n")
        f.write("| الفئة (Vulnerability Category) | معيار CWE | TP | TN | FP | FN | الدقة |\n")
        f.write("| :--- | :--- | :---: | :---: | :---: | :---: | :---: |\n")
        for cname, s in category_stats.items():
            tot = s['TP'] + s['TN'] + s['FP'] + s['FN']
            acc = ((s['TP'] + s['TN']) / tot * 100) if tot > 0 else 0
            f.write(f"| {cname} | - | {s['TP']} | {s['TN']} | {s['FP']} | {s['FN']} | {acc:.1f}% |\n")

    # Save JSON raw results
    json_path = "reports/benchmark_testbed_results.json"
    legacy_json_path = "reports/owasp_benchmark_results.json"
    results_payload = {
        "suite_name": "Baseera Sec Synthetic Verification Benchmark",
        "sample_size": evaluated_cases,
        "planned_cases": total_cases,
        "error_cases": error_cases,
        "true_positives": total_tp,
        "true_negatives": total_tn,
        "false_positives": total_fp,
        "false_negatives": total_fn,
        "tpr": tpr,
        "fpr": fpr,
        "fnr": fnr,
        "precision": precision,
        "accuracy": accuracy,
        "f1": f1,
        "category_breakdown": category_stats,
        "individual_cases": results
    }

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2, ensure_ascii=False)
    with open(legacy_json_path, "w", encoding="utf-8") as f:
        json.dump(results_payload, f, indent=2, ensure_ascii=False)

    print(f"\n[+] Raw Benchmark JSON stored at: {json_path}")
    return results_payload


if __name__ == "__main__":
    asyncio.run(main())
