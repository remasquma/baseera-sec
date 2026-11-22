"""Integrity and inference tests for the local Nazzoor model artifacts."""
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import torch

from core.ai.local_model_analyzer import HanadiModelClassifier
from core.engine.local_scanner import LocalPackageAuditor


class TestLocalAIClassifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.classifier = HanadiModelClassifier()

    def test_artifacts_load_with_unverified_or_incompatible_class_metadata(self):
        self.assertEqual(self.classifier.model_status["codebert"], "LOADED_OK")
        self.assertEqual(self.classifier.model_status["distilroberta"], "LOADED_OK")
        self.assertEqual(
            self.classifier.model_label_status["codebert"],
            "LABEL_SEMANTICS_UNVERIFIED",
        )
        self.assertEqual(
            self.classifier.model_label_status["distilroberta"],
            "LABEL_SEMANTICS_UNVERIFIED",
        )
        self.assertEqual(
            self.classifier.model_compatibility["lightgbm"]["status"],
            "VERSION_MISMATCH",
        )
        self.assertEqual(self.classifier.model_status["lightgbm"], "VERSION_MISMATCH")
        self.assertFalse(self.classifier.is_loaded)

    def test_all_transformer_tensors_are_finite_and_within_bounds(self):
        self.assertEqual(set(self.classifier.model_integrity), {"codebert", "distilroberta"})
        for health in self.classifier.model_integrity.values():
            self.assertTrue(health["is_healthy"])
            self.assertGreater(health["tensor_count"], 0)
            self.assertGreater(health["parameter_count"], 0)
            self.assertEqual(health["nan_count"], 0)
            self.assertEqual(health["inf_count"], 0)
            self.assertEqual(health["large_value_count"], 0)
            self.assertEqual(health["anomalous_tensors"], [])

    def test_tensor_inspection_counts_corruption_without_repairing_it(self):
        state = {
            "finite": torch.tensor([1.0, -2.0]),
            "nonfinite": torch.tensor([float("nan"), float("inf"), float("-inf")]),
            "oversized": torch.tensor([1e11]),
        }

        result = HanadiModelClassifier._inspect_tensor_health(state)

        self.assertEqual(result["tensor_count"], 3)
        self.assertEqual(result["parameter_count"], 6)
        self.assertEqual(result["nan_count"], 1)
        self.assertEqual(result["inf_count"], 2)
        self.assertEqual(result["large_value_count"], 1)
        self.assertFalse(result["is_healthy"])
        self.assertTrue(torch.isnan(state["nonfinite"][0]))
        self.assertGreater(state["oversized"].item(), HanadiModelClassifier.LARGE_WEIGHT_THRESHOLD)

    def test_unhealthy_tensor_checkpoint_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "refusing to alter the checkpoint"):
            HanadiModelClassifier._validate_tensor_health({
                "damaged": torch.tensor([float("nan"), 1e12])
            })

    def test_architecture_and_class_heads_match_the_loaded_models(self):
        self.assertEqual(self.classifier.model_status["codebert"], "LOADED_OK")
        self.assertEqual(self.classifier.model_status["distilroberta"], "LOADED_OK")
        for name, loaded in self.classifier._transformer_models.items():
            self.assertEqual(loaded["config"].model_type, "roberta")
            self.assertEqual(
                loaded["config"].num_hidden_layers,
                sum(
                    key.endswith("attention.self.query.weight")
                    for key in loaded["model"].state_dict()
                    if key.startswith("roberta.encoder.layer.")
                ),
            )
            self.assertEqual(
                loaded["model"].classifier.out_proj.weight.shape[0],
                loaded["config"].num_labels,
                name,
            )
            self.assertEqual(len(loaded["tokenizer"]), loaded["config"].vocab_size)

    def test_label_mappings_are_validated_and_not_inferred_from_indices(self):
        labels, malicious_index, status = HanadiModelClassifier._resolve_label_metadata({}, 2)
        self.assertEqual(labels, {})
        self.assertIsNone(malicious_index)
        self.assertEqual(status, "LABEL_SEMANTICS_UNVERIFIED")

        labels, malicious_index, status = HanadiModelClassifier._resolve_label_metadata(
            {"id2label": {"0": "BENIGN", "1": "MALICIOUS"},
             "label2id": {"BENIGN": 0, "MALICIOUS": 1}},
            2,
        )
        self.assertEqual(labels, {0: "BENIGN", 1: "MALICIOUS"})
        self.assertEqual(malicious_index, 1)
        self.assertEqual(status, "LABELS_VERIFIED_FROM_CONFIG")

        _, index, status = HanadiModelClassifier._resolve_label_metadata(
            {"id2label": {"0": "LABEL_0", "1": "LABEL_1"}}, 2
        )
        self.assertIsNone(index)
        self.assertEqual(status, "MALICIOUS_LABEL_UNVERIFIED")

        _, index, status = HanadiModelClassifier._resolve_label_metadata(
            {"id2label": {"0": "BENIGN", "1": "MALICIOUS"},
             "label2id": {"BENIGN": 1, "MALICIOUS": 0}},
            2,
        )
        self.assertIsNone(index)
        self.assertEqual(status, "INCONSISTENT_LABEL_MAPPINGS")

    def test_failed_model_loading_does_not_fall_back_to_neural_classification(self):
        with (
            patch.object(HanadiModelClassifier, "_load_transformer", side_effect=FileNotFoundError("missing weights")),
            patch.object(HanadiModelClassifier, "_load_lightgbm", side_effect=FileNotFoundError("missing classifier")),
        ):
            classifier = HanadiModelClassifier(model_dir="/missing/codebert")

        result = classifier.score_text("<script>alert(1)</script>")
        self.assertFalse(classifier.is_loaded)
        self.assertEqual(result["status"], "MODEL_INFERENCE_UNAVAILABLE")
        self.assertIsNone(result["is_malicious"])
        self.assertIsNone(result["malicious_probability"])
        self.assertEqual(result["model_scores"], {})
        self.assertEqual(result["rule_based_signals"], ["Cross-Site Scripting (XSS) Marker"])

    def test_outputs_are_raw_and_class_semantics_remain_unverified(self):
        result = self.classifier.score_text(
            "def add(a: int, b: int) -> int:\n    return a + b"
        )

        self.assertEqual(result["score_source"], "UNVERIFIED_LABEL_SEMANTICS")
        self.assertIsNone(result["is_malicious"])
        self.assertIsNone(result["malicious_probability"])
        self.assertIsNone(result["confidence"])
        self.assertEqual(result["model_scores"], {})
        self.assertIsNone(result["ensemble_method"])
        self.assertEqual(result["status"], "PARTIAL_MODEL_INFERENCE_LABELS_UNVERIFIED")
        for name in ("codebert", "distilroberta"):
            inference = result["model_inferences"][name]
            self.assertEqual(inference["label_status"], "LABEL_SEMANTICS_UNVERIFIED")
            self.assertIsNone(inference["predicted_class_label"])
            self.assertIn(inference["predicted_class_index"], (0, 1))
            self.assertEqual(len(inference["raw_logits"]), 2)
            self.assertAlmostEqual(sum(inference["raw_softmax"]), 1.0, places=4)
            self.assertFalse(inference["is_calibrated"])

        lightgbm = result["model_inferences"]["lightgbm"]
        self.assertEqual(lightgbm["status"], "INFERENCE_BLOCKED_VERSION_MISMATCH")
        self.assertEqual(lightgbm["label_status"], "LABEL_SEMANTICS_UNVERIFIED")
        self.assertNotIn("class_probabilities", lightgbm)

    def test_heuristic_signals_are_separate_from_neural_outputs(self):
        result = self.classifier.score_text("<script>alert(1)</script>")

        self.assertIn("Cross-Site Scripting (XSS) Marker", result["rule_based_signals"])
        self.assertEqual(result["signals"], result["rule_based_signals"])
        self.assertIsNone(result["malicious_probability"])
        self.assertEqual(result["model_scores"], {})
        self.assertIn("codebert", result["model_inferences"])

    def test_sast_does_not_promote_unverified_model_decision(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            Path(temp_dir, "sample.py").write_text("value = 1\n", encoding="utf-8")
            unverified_result = {
                "is_malicious": True,
                "malicious_probability": 0.99,
                "score_source": "UNVERIFIED_LABEL_SEMANTICS",
            }
            with patch(
                "core.engine.local_scanner.local_ai_classifier.score_text",
                return_value=unverified_result,
            ):
                _, findings, vulnerabilities = LocalPackageAuditor.audit_package_or_directory(
                    temp_dir
                )

        self.assertEqual(findings, [])
        self.assertEqual(vulnerabilities, [])

    def test_inference_is_repeatable_and_varies_by_input_without_label_claims(self):
        samples = {
            "benign_code": "def add(a, b): return a + b",
            "sql_injection": "SELECT * FROM users WHERE name = 'x' OR '1'='1';",
            "xss": "<script>alert(document.cookie)</script>",
            "command_injection": "subprocess.run(user_input, shell=True, check=False)",
            "ordinary_text": "The weather is clear and the team reviewed the report.",
            "suspicious_code": 'eval(request.args.get("code")); os.system(user_input)',
        }
        outputs = {
            name: self.classifier.score_text(text)
            for name, text in samples.items()
        }

        for name in ("codebert", "distilroberta"):
            benign = outputs["benign_code"]["model_inferences"][name]
            repeated = self.classifier.score_text(samples["benign_code"])["model_inferences"][name]
            self.assertEqual(benign["raw_logits"], repeated["raw_logits"])
            self.assertEqual(benign["raw_softmax"], repeated["raw_softmax"])

            distinct_logits = {
                tuple(result["model_inferences"][name]["raw_logits"])
                for result in outputs.values()
            }
            self.assertGreater(len(distinct_logits), 1)

        self.assertIsNone(outputs["sql_injection"]["malicious_probability"])
        self.assertIsNone(outputs["xss"]["is_malicious"])

    def test_empty_input_does_not_claim_a_benign_prediction(self):
        result = self.classifier.score_text("")

        self.assertEqual(result["status"], "EMPTY_INPUT")
        self.assertIsNone(result["is_malicious"])
        self.assertIsNone(result["malicious_probability"])


if __name__ == "__main__":
    unittest.main()
