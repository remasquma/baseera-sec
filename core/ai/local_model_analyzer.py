"""Inspect and run raw inference on the local Nazzoor model artifacts."""
import json
import logging
import os
import re
import time
import warnings
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("baseera.ai.nazzoor")


class HanadiModelClassifier:
    MODEL_NAMES = ("codebert", "distilroberta", "lightgbm")
    LARGE_WEIGHT_THRESHOLD = 1e10

    def __init__(self, model_dir: Optional[str] = None):
        ai_dir = os.path.dirname(os.path.abspath(__file__))
        default_root = os.path.join(ai_dir, "models", "Nazzoor_Models")
        self.model_dir = model_dir or os.path.join(default_root, "codebert_nazzoor")
        self.model_root = os.path.dirname(self.model_dir) if model_dir else default_root
        self.model_dirs = {
            "codebert": self.model_dir,
            "distilroberta": os.path.join(self.model_root, "distilroberta_nazzoor"),
        }
        self.is_loaded = False
        self._model = None
        self._tokenizer = None
        self._config = None
        self._status = "UNINITIALIZED"
        self.id2label = None
        self.has_saturated_weights = False
        self.model_status: Dict[str, str] = {}
        self.model_integrity: Dict[str, Dict[str, Any]] = {}
        self.model_label_status: Dict[str, str] = {}
        self.model_compatibility: Dict[str, Dict[str, Any]] = {}
        self._transformer_models: Dict[str, Dict[str, Any]] = {}
        self._lightgbm_model = None
        self._tfidf_vectorizer = None
        self._try_load()

    @classmethod
    def _inspect_tensor_health(cls, state_dict: Dict[str, Any]) -> Dict[str, Any]:
        import torch

        tensor_count = 0
        parameter_count = 0
        nan_count = 0
        inf_count = 0
        huge_count = 0
        finite_min = float("inf")
        finite_max = float("-inf")
        finite_sum = 0.0
        finite_square_sum = 0.0
        finite_count = 0
        anomalous_tensors = []

        for name, tensor in state_dict.items():
            if not isinstance(tensor, torch.Tensor):
                raise TypeError(f"Model state entry {name!r} is not a tensor")
            tensor_count += 1
            parameter_count += tensor.numel()
            values = tensor.detach().to(dtype=torch.float64)
            nan_values = torch.isnan(values)
            inf_values = torch.isinf(values)
            finite_values = values[torch.isfinite(values)]
            current_nan = int(nan_values.sum().item())
            current_inf = int(inf_values.sum().item())
            current_huge = int(
                (finite_values.abs() > cls.LARGE_WEIGHT_THRESHOLD).sum().item()
            )
            nan_count += current_nan
            inf_count += current_inf
            huge_count += current_huge

            if finite_values.numel():
                finite_min = min(finite_min, float(finite_values.min().item()))
                finite_max = max(finite_max, float(finite_values.max().item()))
                finite_sum += float(finite_values.sum().item())
                finite_square_sum += float(finite_values.square().sum().item())
                finite_count += finite_values.numel()

            if current_nan or current_inf or current_huge:
                anomalous_tensors.append({
                    "name": name,
                    "nan_count": current_nan,
                    "inf_count": current_inf,
                    "large_value_count": current_huge,
                })

        mean = finite_sum / finite_count if finite_count else None
        variance = (
            max(0.0, finite_square_sum / finite_count - mean * mean)
            if finite_count and mean is not None
            else None
        )
        return {
            "tensor_count": tensor_count,
            "parameter_count": parameter_count,
            "nan_count": nan_count,
            "inf_count": inf_count,
            "large_value_count": huge_count,
            "finite_min": finite_min if finite_count else None,
            "finite_max": finite_max if finite_count else None,
            "finite_mean": mean,
            "finite_std": variance ** 0.5 if variance is not None else None,
            "anomalous_tensors": anomalous_tensors,
            "is_healthy": nan_count == 0 and inf_count == 0 and huge_count == 0,
        }

    @classmethod
    def _validate_tensor_health(cls, state_dict: Dict[str, Any]) -> Dict[str, Any]:
        health = cls._inspect_tensor_health(state_dict)
        if not health["is_healthy"]:
            raise ValueError(
                "Model tensors contain non-finite or oversized weights; refusing to alter the checkpoint: "
                f"NaN={health['nan_count']}, Inf={health['inf_count']}, "
                f"abs(value)>{cls.LARGE_WEIGHT_THRESHOLD:g}={health['large_value_count']}"
            )
        return health

    @staticmethod
    def _resolve_label_metadata(config_data: Dict[str, Any], num_labels: int) -> Tuple[Dict[int, str], Optional[int], str]:
        id2label_data = config_data.get("id2label")
        label2id_data = config_data.get("label2id")
        resolved: Dict[int, str] = {}

        if isinstance(id2label_data, dict):
            try:
                resolved = {int(index): str(label) for index, label in id2label_data.items()}
            except (TypeError, ValueError):
                return {}, None, "INVALID_LABEL_MAPPING"
        elif isinstance(label2id_data, dict):
            try:
                resolved = {int(index): str(label) for label, index in label2id_data.items()}
            except (TypeError, ValueError):
                return {}, None, "INVALID_LABEL_MAPPING"

        if not resolved:
            return {}, None, "LABEL_SEMANTICS_UNVERIFIED"
        if set(resolved) != set(range(num_labels)) or len(set(resolved.values())) != num_labels:
            return {}, None, "INVALID_LABEL_MAPPING"

        if isinstance(id2label_data, dict) and isinstance(label2id_data, dict):
            try:
                inverse = {str(label): int(index) for index, label in id2label_data.items()}
                declared = {str(label): int(index) for label, index in label2id_data.items()}
            except (TypeError, ValueError):
                return {}, None, "INVALID_LABEL_MAPPING"
            if inverse != declared:
                return {}, None, "INCONSISTENT_LABEL_MAPPINGS"

        malicious_labels = {"malicious", "vulnerable", "unsafe"}
        malicious_indices = [
            index for index, label in resolved.items()
            if label.strip().casefold() in malicious_labels
        ]
        if len(malicious_indices) == 1:
            return resolved, malicious_indices[0], "LABELS_VERIFIED_FROM_CONFIG"
        return resolved, None, "MALICIOUS_LABEL_UNVERIFIED"

    def _load_transformer(self, model_dir: str) -> Dict[str, Any]:
        weights_path = os.path.join(model_dir, "model.safetensors")
        config_path = os.path.join(model_dir, "config.json")
        tokenizer_path = os.path.join(model_dir, "tokenizer.json")
        if not os.path.isdir(model_dir):
            raise FileNotFoundError(f"Model directory not found: {model_dir}")
        if not all(os.path.isfile(path) for path in (weights_path, config_path, tokenizer_path)):
            raise FileNotFoundError(f"Model weights or metadata missing in {model_dir}")

        import safetensors.torch
        from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer

        with open(config_path, "r", encoding="utf-8") as config_file:
            config_data = json.load(config_file)
        if not isinstance(config_data, dict):
            raise ValueError(f"Model config must be a JSON object: {config_path}")

        tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)
        config = AutoConfig.from_pretrained(model_dir, local_files_only=True)
        config._attn_implementation = "eager"
        raw_tensors = safetensors.torch.load_file(weights_path)
        tensor_health = self._validate_tensor_health(raw_tensors)
        if config.model_type != "roberta":
            raise ValueError(f"Unsupported model architecture: {config.model_type}")
        if config.architectures and "RobertaForSequenceClassification" not in config.architectures:
            raise ValueError(f"Unexpected model architecture metadata: {config.architectures}")
        if len(tokenizer) != config.vocab_size:
            raise ValueError(
                f"Tokenizer vocabulary ({len(tokenizer)}) does not match model vocab_size ({config.vocab_size})"
            )
        head_weight = raw_tensors.get("classifier.out_proj.weight")
        if head_weight is None or head_weight.ndim != 2:
            raise ValueError("Classification output layer is missing or malformed")
        num_labels = int(head_weight.shape[0])
        label_mapping, malicious_index, label_status = self._resolve_label_metadata(
            config_data, num_labels
        )
        if config.num_labels != num_labels:
            raise ValueError(
                f"Configured label count ({config.num_labels}) does not match output layer ({num_labels})"
            )

        model = AutoModelForSequenceClassification.from_config(config)
        model.load_state_dict(raw_tensors, strict=True)
        model.to("cpu")
        model.eval()
        return {
            "model": model,
            "tokenizer": tokenizer,
            "config": config,
            "id2label": label_mapping,
            "malicious_class_index": malicious_index,
            "label_status": label_status,
            "tensor_health": tensor_health,
        }

    def _load_lightgbm(self) -> None:
        import joblib
        import lightgbm
        import sklearn

        model_path = os.path.join(self.model_root, "lgbm_model.pkl")
        vectorizer_path = os.path.join(self.model_root, "tfidf_vectorizer.pkl")
        if not os.path.isfile(model_path) or not os.path.isfile(vectorizer_path):
            raise FileNotFoundError(f"LightGBM or TF-IDF artifact missing in {self.model_root}")

        from sklearn.exceptions import InconsistentVersionWarning

        with warnings.catch_warnings(record=True) as captured_warnings:
            warnings.simplefilter("always", InconsistentVersionWarning)
            vectorizer = joblib.load(vectorizer_path)
            model = joblib.load(model_path)

        if not callable(getattr(vectorizer, "transform", None)):
            raise TypeError("TF-IDF artifact does not provide transform()")
        if not callable(getattr(model, "predict_proba", None)):
            raise TypeError("LightGBM artifact does not provide predict_proba()")

        classes = list(model.classes_)
        if len(classes) < 2:
            raise ValueError(f"LightGBM model must expose at least two classes, got {classes!r}")

        self._tfidf_vectorizer = vectorizer
        self._lightgbm_model = model
        self.model_label_status["lightgbm"] = "LABEL_SEMANTICS_UNVERIFIED"
        version_warnings = [
            str(warning.message)
            for warning in captured_warnings
            if isinstance(warning.message, InconsistentVersionWarning)
        ]
        self.model_compatibility["lightgbm"] = {
            "status": "VERSION_MISMATCH" if version_warnings else "VERSION_MATCH",
            "warnings": version_warnings,
            "runtime_scikit_learn": sklearn.__version__,
        }
        if version_warnings:
            logger.warning(
                "Blocking LightGBM inference: serialized scikit-learn version differs from runtime %s",
                sklearn.__version__,
            )
        logger.info(
            "Loaded local LightGBM %s and scikit-learn %s model artifacts",
            lightgbm.__version__,
            sklearn.__version__,
        )

    def _try_load(self) -> None:
        for name, model_dir in self.model_dirs.items():
            try:
                start = time.perf_counter()
                loaded = self._load_transformer(model_dir)
                self._transformer_models[name] = loaded
                self.model_status[name] = "LOADED_OK"
                self.model_integrity[name] = loaded["tensor_health"]
                self.model_label_status[name] = loaded["label_status"]
                logger.info("Loaded %s model in %.2fs", name, time.perf_counter() - start)
                if name == "codebert":
                    self._model = loaded["model"]
                    self._tokenizer = loaded["tokenizer"]
                    self._config = loaded["config"]
                    self.id2label = loaded["id2label"]
                    self.has_saturated_weights = not loaded["tensor_health"]["is_healthy"]
            except ImportError as exc:
                self.model_status[name] = f"MISSING_DEPS: {exc}"
                logger.warning("Dependencies missing for %s: %s", name, exc)
            except Exception as exc:
                self.model_status[name] = f"LOAD_ERROR: {exc}"
                logger.exception("Could not load %s model", name)

        try:
            self._load_lightgbm()
            self.model_status["lightgbm"] = (
                "VERSION_MISMATCH"
                if self.model_compatibility["lightgbm"]["status"] == "VERSION_MISMATCH"
                else "LOADED_OK"
            )
        except ImportError as exc:
            self.model_status["lightgbm"] = f"MISSING_DEPS: {exc}"
            logger.warning("Dependencies missing for LightGBM model: %s", exc)
        except Exception as exc:
            self.model_status["lightgbm"] = f"LOAD_ERROR: {exc}"
            logger.exception("Could not load LightGBM model")

        loaded_count = sum(self.model_status.get(name) == "LOADED_OK" for name in self.MODEL_NAMES)
        self.is_loaded = loaded_count == len(self.MODEL_NAMES)
        self._status = (
            "INFERENCE_ONLY_LABELS_UNVERIFIED"
            if self.is_loaded and any(
                status != "LABELS_VERIFIED_FROM_CONFIG"
                for status in self.model_label_status.values()
            )
            else "LOADED_OK"
            if self.is_loaded
            else f"PARTIAL_LOAD ({loaded_count}/3)"
        )

    def _score_transformer(self, text: str, loaded: Dict[str, Any]) -> Dict[str, Any]:
        import torch

        started = time.perf_counter()
        inputs = loaded["tokenizer"](
            text,
            return_tensors="pt",
            truncation=True,
            max_length=512,
        )
        with torch.no_grad():
            outputs = loaded["model"](**inputs)
            logits = outputs.logits[0]
            probabilities = torch.softmax(logits, dim=-1).tolist()

        if len(probabilities) != int(loaded["config"].num_labels):
            raise ValueError("Transformer output class count does not match model config")
        predicted_index = int(torch.argmax(logits).item())
        labels = loaded.get("id2label") or {}
        return {
            "predicted_class_index": predicted_index,
            "predicted_class_label": labels.get(predicted_index),
            "raw_logits": [round(float(value), 4) for value in logits.tolist()],
            "raw_softmax": [round(float(value), 4) for value in probabilities],
            "label_status": loaded["label_status"],
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "is_calibrated": False,
        }

    def _score_lightgbm(self, text: str) -> Dict[str, Any]:
        if self.model_compatibility.get("lightgbm", {}).get("status") == "VERSION_MISMATCH":
            return {
                "status": "INFERENCE_BLOCKED_VERSION_MISMATCH",
                "label_status": "LABEL_SEMANTICS_UNVERIFIED",
                "compatibility": self.model_compatibility["lightgbm"],
            }
        started = time.perf_counter()
        features = self._tfidf_vectorizer.transform([text])
        probabilities = self._lightgbm_model.predict_proba(features)[0]
        classes = list(self._lightgbm_model.classes_)
        return {
            "predicted_class": str(classes[int(probabilities.argmax())]),
            "class_probabilities": {
                str(label): float(probability)
                for label, probability in zip(classes, probabilities)
            },
            "classes": [str(label) for label in classes],
            "label_status": "LABEL_SEMANTICS_UNVERIFIED",
            "latency_ms": round((time.perf_counter() - started) * 1000, 2),
            "is_calibrated": False,
        }

    def score_text(self, text: str) -> Dict[str, Any]:
        if not text or not isinstance(text, str):
            return {
                "status": "EMPTY_INPUT",
                "model_status": self._status,
                "is_malicious": None,
                "malicious_probability": None,
                "confidence": None,
                "score_source": "UNVERIFIED_LABEL_SEMANTICS",
                "rule_match_weight": 0.0,
                "rule_based_signals": [],
                "signals": [],
                "model_scores": {},
                "model_inferences": {},
            }

        safe_input = text[:2048]
        rule_signals, rule_match_weight = self._extract_rule_signals(safe_input)
        model_results: Dict[str, Dict[str, Any]] = {}

        for name, loaded in self._transformer_models.items():
            try:
                result = self._score_transformer(safe_input, loaded)
                result["status"] = "INFERENCE_SUCCESS"
                result["engine"] = name
                model_results[name] = result
            except Exception as exc:
                logger.exception("Inference failed for %s model", name)
                model_results[name] = {"status": "INFERENCE_FAILED", "error": str(exc)}

        if self._lightgbm_model is not None and self._tfidf_vectorizer is not None:
            try:
                result = self._score_lightgbm(safe_input)
                result.setdefault("status", "INFERENCE_SUCCESS")
                result["engine"] = "lightgbm_tfidf"
                model_results["lightgbm"] = result
            except Exception as exc:
                logger.exception("Inference failed for LightGBM model")
                model_results["lightgbm"] = {"status": "INFERENCE_FAILED", "error": str(exc)}

        inference_count = sum(
            result.get("status") == "INFERENCE_SUCCESS"
            for result in model_results.values()
        )
        ensemble_status = (
            "MODEL_INFERENCE_COMPLETE_LABELS_UNVERIFIED"
            if inference_count == len(self.MODEL_NAMES)
            else "PARTIAL_MODEL_INFERENCE_LABELS_UNVERIFIED"
            if inference_count
            else "MODEL_INFERENCE_UNAVAILABLE"
        )
        codebert_result = model_results.get("codebert")
        return {
            "status": ensemble_status,
            "model_status": self._status,
            "model_statuses": dict(self.model_status),
            "model_name": "Nazzoor Local Model Artifacts",
            "is_malicious": None,
            "malicious_probability": None,
            "confidence": None,
            "score_source": "UNVERIFIED_LABEL_SEMANTICS",
            "model_scores": {},
            "ensemble_method": None,
            "neural_inference": codebert_result,
            "model_inferences": model_results,
            "rule_match_weight": rule_match_weight,
            "rule_based_signals": rule_signals,
            "signals": rule_signals,
            "engine": "Nazzoor raw inference; classification unavailable",
        }

    def _extract_rule_signals(self, text: str) -> Tuple[List[str], float]:
        score = 0.0
        signals = []
        patterns = [
            (r"(?i)(?:or\s+['\"]?1['\"]?\s*=\s*['\"]?1|union\s+select|select\s+.*\s+from|sleep\(\d+\)|benchmark\(|'\s*or\s*['\"]|--|\b1=1\b)", 0.88, "SQL Injection Pattern"),
            (r"(?i)(?:<script.*?>|onerror\s*=|javascript\s*:|onload\s*=|alert\(|<iframe|document\.cookie)", 0.85, "Cross-Site Scripting (XSS) Marker"),
            (r"(?i)(?:\.\./|\.\.\\|\.env|etc/passwd|\.git/config|boot\.ini)", 0.92, "Directory Traversal & Sensitive File Leak"),
            (r"(?i)(?:api_key|password|secret|private_key|token)\s*[:=]\s*['\"][^'\"]{5,}", 0.75, "Exposed Secret / Credential Artifact"),
            (r"(?i)(?:eval\(|exec\(|system\(|passthru\(|shell_exec\()", 0.80, "Dangerous Dynamic Execution Function"),
        ]

        for pattern, weight, label in patterns:
            if re.search(pattern, text):
                score = max(score, weight)
                signals.append(label)
        return signals, score


local_ai_classifier = HanadiModelClassifier()
