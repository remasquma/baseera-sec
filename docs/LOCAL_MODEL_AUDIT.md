# Local Model Audit

## Scope and conclusion

This audit covers the checked-in CodeBERT and DistilRoBERTa checkpoints and the
TF-IDF/LightGBM artifacts under `core/ai/models/Nazzoor_Models/`. No model files
were modified or replaced.

**Operational conclusion:** neural forward passes work for both transformers,
but the classifier is **not approved for benign/malicious decisions**. The
transformer label mappings are absent, output scores are uncalibrated, and a
small probe showed sharp disagreements between the two models. LightGBM
inference is blocked because its serialized scikit-learn artifacts were created
with version 1.6.1 while this runtime is 1.9.1.

## Artifact integrity and compatibility

| Artifact | Tensors | Parameters | NaN | Inf | `abs(weight) > 1e10` | Min | Max | Mean | Std. dev. |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| CodeBERT | 201 | 124,647,170 | 0 | 0 | 0 | -1.7809 | 4.1537 | -0.005674 | 0.085533 |
| DistilRoBERTa | 105 | 82,119,938 | 0 | 0 | 0 | -1.3792 | 1.8671 | -0.006689 | 0.097999 |

Both use `RobertaForSequenceClassification`; strict state-dict loading
succeeded. Each output head has two classes. Each effective configuration has
two labels, and its tokenizer vocabulary (50,265) matches `vocab_size` (50,265).
Neither source `config.json` provides `id2label` or `label2id`; the
LightGBM artifact only declares numeric classes `[0, 1]`. There is no verified
mapping from these class IDs to benign/malicious.

The current files provide no training dataset, model card, source provenance,
or authoritative label mapping. Therefore this inspection found no evidence of
non-finite/oversized weights, architecture mismatch, or tokenizer-size
mismatch, but cannot establish training correctness or explain the conflicting
outputs. The earlier report of NaN/Inf or huge values was not reproduced on
these current in-repository checkpoints.

## Six-input inference probe

The table gives raw logits, softmax values, and predicted numeric index. Values
are diagnostic only; neither index is assigned a security meaning. All
reported stable fields (logits, softmax, predicted index, and status) repeated
identically when each input was run twice. Latency is excluded because it is
runtime-dependent.

| Input | CodeBERT: logits; softmax; class | DistilRoBERTa: logits; softmax; class |
|---|---|---|
| Benign code | `[3.4216, -4.5226]`; `[0.9996, 0.0004]`; `0` | `[-4.2281, 4.3082]`; `[0.0002, 0.9998]`; `1` |
| SQL injection marker | `[-2.6248, 3.2598]`; `[0.0028, 0.9972]`; `1` | `[4.2541, -4.4020]`; `[0.9998, 0.0002]`; `0` |
| XSS marker | `[3.6593, -4.7662]`; `[0.9998, 0.0002]`; `0` | `[-4.4477, 4.6061]`; `[0.0001, 0.9999]`; `1` |
| Command-injection marker | `[-2.1968, 2.5315]`; `[0.0088, 0.9912]`; `1` | `[3.9268, -4.1450]`; `[0.9997, 0.0003]`; `0` |
| Ordinary text | `[3.4088, -4.3725]`; `[0.9996, 0.0004]`; `0` | `[3.6434, -3.7367]`; `[0.9994, 0.0006]`; `0` |
| Suspicious code | `[-0.1341, -0.2597]`; `[0.5313, 0.4687]`; `0` | `[-4.2978, 4.4416]`; `[0.0002, 0.9998]`; `1` |

Outputs vary with input, but the models strongly disagree on benign code and
reverse their numeric predictions for several probes. Without label semantics
and a labeled validation set, this is **not evidence of useful discrimination**.
No accuracy, recall, or calibrated malicious probability can be claimed from
these probes.

## Changes and remaining work

- Removed load-time `nan_to_num`/clamping. A checkpoint with non-finite or
  oversized tensors is rejected unchanged.
- Kept neural outputs (per-model logits, softmax, numeric class, and status)
  distinct from rule-based signals. The analyzer does not emit a malicious
  decision, confidence, or aggregate model score while labels are unverified.
- Guarded local SAST so it cannot convert an unverified model decision into a
  vulnerability finding.
- LightGBM inference remains disabled on the detected scikit-learn version
  mismatch; the artifact's numeric classes remain semantically unverified.

Before enabling classification, restore trusted label mappings and training
provenance and evaluate each model on a held-out labeled dataset. Calibrate
scores only if probabilities are needed. For LightGBM, use the artifact's
compatible scikit-learn environment or re-export/retrain from the original
trusted training data. If labels and provenance cannot be recovered, retrain
with documented labels and a reproducible dataset; do not relabel or repair the
current weights by clamping.
