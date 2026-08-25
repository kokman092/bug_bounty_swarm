"""
tests/unit/test_finding_dedup.py
────────────────────────────────
Unit tests for finding deduplication and hypothesis exclusion.
"""
from app.findings.schemas import Hypothesis, TestStep, VulnClass


class TestFindingDeduplication:

    def test_hypothesis_model_validation(self):
        hyp = Hypothesis(
            hypothesis_id="hyp-1",
            vuln_class=VulnClass.IDOR,
            endpoint="/api/orders/1",
            title="IDOR on orders",
            rationale="Sequential IDs without ownership check",
            test_steps=[
                TestStep(
                    step_number=1,
                    description="Get order 1 with user token",
                    method="GET",
                    path="/api/orders/1",
                    headers={"Authorization": "Bearer token_a"},
                )
            ],
            no_further_hypotheses=False,
        )

        assert hyp.vuln_class == VulnClass.IDOR
        assert len(hyp.test_steps) == 1
        assert hyp.test_steps[0].method == "GET"

    def test_dedup_string_generation(self):
        hyp1 = Hypothesis(
            hypothesis_id="h1",
            vuln_class=VulnClass.IDOR,
            endpoint="/api/orders/1",
            title="IDOR 1",
            rationale="Test",
        )
        hyp2 = Hypothesis(
            hypothesis_id="h2",
            vuln_class=VulnClass.IDOR,
            endpoint="/api/orders/1",
            title="IDOR 2",
            rationale="Test 2",
        )

        key1 = f"{hyp1.vuln_class.value}:{hyp1.endpoint}"
        key2 = f"{hyp2.vuln_class.value}:{hyp2.endpoint}"
        assert key1 == key2

        already_proposed = [key1]
        assert key2 in already_proposed
