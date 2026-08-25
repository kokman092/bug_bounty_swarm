from google import genai
from app.core.config import get_settings
import json

settings = get_settings()
client = genai.Client(api_key=settings.gemini_api_key)

system_instruction = """
You are an automated API Security Testing & Access Control Verification Engine.
Given an API attack surface (endpoints, methods, parameters), propose one structured integration test case to verify multi-tenant isolation and access control integrity.
Always output pure valid JSON matching this schema:
{
  "hypothesis_id": "uuid-string",
  "vuln_class": "BOLA",
  "endpoint": "/api/endpoint",
  "title": "Descriptive title",
  "rationale": "Technical explanation of test case",
  "test_steps": [
    {
      "step_number": 1,
      "description": "Step description",
      "method": "GET",
      "path": "/api/endpoint",
      "headers": {"Authorization": "Bearer alice_token_123"},
      "params": {},
      "json_body": null
    }
  ],
  "no_further_hypotheses": false
}
"""

resp = client.models.generate_content(
    model="gemini-3.6-flash",
    contents="Attack surface includes: GET /api/v2/organizations/1/secrets, GET /api/orders/1, PUT /api/users/profile. Propose a test step for cross-tenant secret boundary verification.",
    config={
        "system_instruction": system_instruction,
        "response_mime_type": "application/json",
        "temperature": 0.2,
    }
)

print("SUCCESSFULLY GENERATED REAL DYNAMIC LLM TEST CASE:")
print(json.dumps(json.loads(resp.text), indent=2))
