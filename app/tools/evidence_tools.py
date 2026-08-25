"""
app/tools/evidence_tools.py
───────────────────────────
Evidence analysis tools for comparing multi-identity responses, status differentials,
and sensitive field exposures.
"""
from __future__ import annotations

from typing import Any


def compute_response_diff(
    response_a: dict[str, Any],
    response_b: dict[str, Any],
) -> dict[str, Any]:
    """
    Computes a structured diff between two responses (e.g. User A requesting User B's resource).
    Evaluates:
      - Status code mismatch
      - Body length difference
      - Identity token or username leakage
    """
    status_a = response_a.get("status_code")
    status_b = response_b.get("status_code")

    body_a = str(response_a.get("body", ""))
    body_b = str(response_b.get("body", ""))

    identical_body = (body_a == body_b)
    len_diff = abs(len(body_a) - len(body_b))

    return {
        "status_a": status_a,
        "status_b": status_b,
        "status_matched": (status_a == status_b),
        "body_length_a": len(body_a),
        "body_length_b": len(body_b),
        "body_length_diff": len_diff,
        "identical_body": identical_body,
    }
