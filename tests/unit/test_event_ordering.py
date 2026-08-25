"""
tests/unit/test_event_ordering.py
─────────────────────────────────
Unit tests for event sanitization, size capping, and model serialization.
"""
from app.events.schemas import AgentEvent, EventType
from app.events.service import sanitize_payload, truncate_payload


class TestEventProcessing:

    def test_sanitize_payload_redacts_tokens(self):
        raw = {
            "auth": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.xyz",
            "key": "api_key=sk-1234567890abcdef",
            "nested": {
                "header": "Authorization: Basic admin:password123",
                "password": "supersecretpassword",
            },
            "safe": "public_recon_data",
        }
        sanitized = sanitize_payload(raw)

        assert "[REDACTED]" in sanitized["auth"]
        assert "[REDACTED]" in sanitized["key"]
        assert "[REDACTED]" in sanitized["nested"]["header"]
        assert "[REDACTED]" in sanitized["nested"]["password"]
        assert sanitized["safe"] == "public_recon_data"

    def test_truncate_payload_under_limit(self):
        small_payload = {"key": "value", "count": 42}
        payload, is_truncated = truncate_payload(small_payload, max_bytes=1024)
        assert is_truncated is False
        assert payload == small_payload

    def test_truncate_payload_exceeding_limit(self):
        large_payload = {
            "summary": "OK",
            "huge_field": "X" * 20000,
        }
        payload, is_truncated = truncate_payload(large_payload, max_bytes=1000)
        assert is_truncated is True
        assert "[Truncated" in payload["huge_field"]
        assert payload["summary"] == "OK"

    def test_agent_event_serialization(self):
        event = AgentEvent(
            event_id="evt-123",
            investigation_id="inv-456",
            sequence_number=1,
            phase="RECON",
            event_type=EventType.AGENT_STARTED,
            agent_name="ReconAgent",
            payload={"target": "https://example.com"},
        )
        dumped = event.model_dump(mode="json")
        assert dumped["sequence_number"] == 1
        assert dumped["event_type"] == "AGENT_STARTED"
        assert dumped["agent_name"] == "ReconAgent"
