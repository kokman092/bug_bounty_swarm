"""
vuln_lab/analysis/regression_diff.py
───────────────────────────────────
Version Differential & Regression Tracker.

Compares benchmark performance across engine versions (v1 to v6) and reports:
  - Confusion Matrix (TP, FP, FN, TN)
  - Precision, Recall, and F1 Differentials (Delta)
  - Per-Vulnerability Category Accuracy
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass
class ConfusionMatrix:
    tp: int
    fp: int
    fn: int
    tn: int
    nhv: int = 0

    @property
    def total(self) -> int:
        return self.tp + self.fp + self.fn + self.tn + self.nhv

    @property
    def precision(self) -> float:
        return (self.tp / (self.tp + self.fp)) * 100 if (self.tp + self.fp) > 0 else 100.0

    @property
    def recall(self) -> float:
        return (self.tp / (self.tp + self.fn)) * 100 if (self.tp + self.fn) > 0 else 100.0

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return (2 * p * r / (p + r)) if (p + r) > 0 else 0.0


class RegressionDiffTracker:
    """Tracks regression deltas across versions and datasets."""

    def compute_diff(self, old_cm: ConfusionMatrix, new_cm: ConfusionMatrix) -> dict[str, Any]:
        return {
            "precision_delta": round(new_cm.precision - old_cm.precision, 1),
            "recall_delta": round(new_cm.recall - old_cm.recall, 1),
            "f1_delta": round(new_cm.f1_score - old_cm.f1_score, 1),
            "fp_reduction": old_cm.fp - new_cm.fp,
            "fn_reduction": old_cm.fn - new_cm.fn,
        }

    def format_confusion_matrix_table(self, title: str, cm: ConfusionMatrix) -> str:
        return f"""
================================================================================
CONFUSION MATRIX & METRICS: {title}
================================================================================
  True Positives  (TP) : {cm.tp:<5} (Real vulnerabilities correctly confirmed)
  False Positives (FP) : {cm.fp:<5} (Secure/Ambiguous wrongly called confirmed)
  False Negatives (FN) : {cm.fn:<5} (Real vulnerabilities missed)
  True Negatives  (TN) : {cm.tn:<5} (Secure cases correctly identified)
  Needs Human Val (NHV): {cm.nhv:<5} (Ambiguous cases conservatively routed)
--------------------------------------------------------------------------------
  Precision: {cm.precision:>6.1f}%  |  Recall: {cm.recall:>6.1f}%  |  F1 Score: {cm.f1_score:>6.1f}
================================================================================
"""
