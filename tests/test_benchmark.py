"""
Unit Tests for Phase 4 - Benchmark Methodology & Accuracy Metrics Calculation
"""
import unittest
from urllib.parse import parse_qs, urlsplit

from benchmark.benchmark_runner import BENCHMARK_CASES, calculate_metrics
from benchmark.testbed import app as benchmark_app


class TestBenchmarkHarness(unittest.TestCase):

    def test_case_integrity(self):
        self.assertEqual(len(BENCHMARK_CASES), 34)
        seen_ids = set()
        tp_count = 0
        tn_count = 0

        for case in BENCHMARK_CASES:
            # All IDs must be unique
            self.assertNotIn(case["id"], seen_ids)
            seen_ids.add(case["id"])

            # Must have required fields
            self.assertIn("category", case)
            self.assertIn("cwe", case)
            self.assertIn("url", case)
            self.assertIn("expected_vulnerable", case)
            self.assertIn("description", case)

            if case["expected_vulnerable"]:
                tp_count += 1
            else:
                tn_count += 1

        self.assertEqual(tp_count, 18)
        self.assertEqual(tn_count, 16)

    def test_metrics_calculation_logic(self):
        metrics = calculate_metrics(tp=18, fn=1, tn=14, fp=1)

        self.assertEqual(metrics["evaluated_cases"], 34)
        self.assertAlmostEqual(metrics["true_positive_rate"], 18 / 19, places=3)
        self.assertAlmostEqual(metrics["false_positive_rate"], 1 / 15, places=3)
        self.assertAlmostEqual(metrics["false_negative_rate"], 1 / 19, places=3)
        self.assertAlmostEqual(metrics["precision"], 18 / 19, places=3)
        self.assertAlmostEqual(metrics["accuracy"], 32 / 34, places=3)
        self.assertGreater(metrics["f1"], 0.90)

    def test_metrics_exclude_cases_without_results(self):
        metrics = calculate_metrics(tp=1, fp=0, tn=1, fn=0)

        self.assertEqual(metrics["evaluated_cases"], 2)
        self.assertEqual(metrics["accuracy"], 1.0)

    def test_case_parameters_match_testbed_endpoint_signatures(self):
        routes = {
            route.path: route
            for route in benchmark_app.routes
            if getattr(route, "path", None)
        }

        for case in BENCHMARK_CASES:
            parsed = urlsplit(case["url"])
            route = routes[parsed.path]
            accepted_query_params = {
                parameter.alias for parameter in route.dependant.query_params
            }
            supplied_query_params = set(parse_qs(parsed.query))

            self.assertTrue(
                supplied_query_params <= accepted_query_params,
                f"{case['id']}: supplied {supplied_query_params}, endpoint accepts {accepted_query_params}",
            )
            if case["category"] != "Misconfiguration":
                self.assertIn(case["param"], accepted_query_params, case["id"])


if __name__ == "__main__":
    unittest.main()
