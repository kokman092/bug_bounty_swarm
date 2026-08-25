"""
tests/unit/test_scope_ingestion.py
──────────────────────────────────
Unit tests for ScopeIngestionAgent.
"""
import pytest

from app.agents.scope_ingestion import ScopeIngestionAgent
from app.targets.schemas import ScopeType


class TestScopeIngestion:

    @pytest.mark.asyncio
    async def test_ingest_policy_fallback_parsing(self):
        agent = ScopeIngestionAgent(researcher_handle="test_hacker")
        policy_text = """
        Scope:
        - https://api.mycompany.com
        - https://store.mycompany.com
        """

        targets = await agent.ingest_policy(policy_text, program_name="MyCompany")

        assert len(targets) > 0
        for t in targets:
            assert t.added_by == "test_hacker"
            assert "X-Bug-Bounty" in t.custom_headers
            assert "test_hacker" in t.custom_headers["X-Bug-Bounty"]

    def test_researcher_handle_formatting(self):
        agent = ScopeIngestionAgent(researcher_handle="@super_researcher")
        assert agent.researcher_handle == "super_researcher"
