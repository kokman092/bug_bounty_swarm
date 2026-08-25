import json
from google import genai
from app.core.config import get_settings

settings = get_settings()
client = genai.Client(api_key=settings.gemini_api_key)

SYSTEM_INSTRUCTION = """
You are an automated API Access Control & Security Verification Engine.
Your role is to design structured integration test cases to verify multi-tenant isolation, authorization boundaries, and parameter validation.

Input:
- Discovered API endpoints and methods from live target scanning
- Previously executed test cases (to avoid duplicate testing)
- Feedback from previous test evaluations (explaining why a test showed sufficient vs insufficient boundary violation)

Task:
Propose ONE structured test case to verify an authorization boundary or input constraint.
If review feedback indicates that an endpoint properly enforces isolation (e.g. server returned only the caller's own data), analyze the feedback and pivot to verify a different endpoint.

Output pure JSON matching this exact schema:
{
  "hypothesis_id": "uuid-string",
  "vuln_class": "BOLA",
  "endpoint": "/api/endpoint",
  "title": "Descriptive test case title",
  "rationale": "Clear explanation of the access control or boundary isolation being verified",
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

If all attack surfaces have been thoroughly tested, set "no_further_hypotheses": true.
"""

attack_surface = {
  "priority_endpoints": [
    {
      "endpoint": "/api/v3/secure/profile/1",
      "method": "GET",
      "vuln_classes_to_test": ["BOLA"],
      "risk_reasoning": "Profile endpoint with user ID path parameter."
    },
    {
      "endpoint": "/api/v2/organizations/1/secrets",
      "method": "GET",
      "vuln_classes_to_test": ["BOLA", "Sensitive Data Exposure"],
      "risk_reasoning": "Organization secret storage with tenant ID path parameter."
    },
    {
      "endpoint": "/api/integrations/webhook/test",
      "method": "POST",
      "vuln_classes_to_test": ["SSRF"],
      "risk_reasoning": "Outbound webhook dispatcher."
    }
  ]
}

# Test Iteration 1: Initial Proposal
prompt_iter1 = f"""
Current Iteration: 1

Live Target Attack Surface:
{json.dumps(attack_surface, indent=2)}

Already Tested Endpoints:
[]

Previous Test Evaluation Feedback:
None (Initial test run)

Propose the first priority integration test case.
"""

resp1 = client.models.generate_content(
    model="gemini-3.6-flash",
    contents=prompt_iter1,
    config={
        "system_instruction": SYSTEM_INSTRUCTION,
        "response_mime_type": "application/json",
        "temperature": 0.2,
    },
)

print("ITERATION 1 DYNAMIC GEMINI RESPONSE:")
print(json.dumps(json.loads(resp1.text), indent=2))

# Test Iteration 2: Feedback-driven Pivot
prompt_iter2 = f"""
Current Iteration: 2

Live Target Attack Surface:
{json.dumps(attack_surface, indent=2)}

Already Tested Endpoints:
["BOLA:/api/v3/secure/profile/1"]

Previous Test Evaluation Feedback:
"Adversarial: Server returned caller's own profile (User 2) without cross-account leakage. Access control is properly enforced on /api/v3/secure/profile/1."

Analyze the feedback and propose a pivoted integration test case for a different high-risk endpoint.
"""

resp2 = client.models.generate_content(
    model="gemini-3.6-flash",
    contents=prompt_iter2,
    config={
        "system_instruction": SYSTEM_INSTRUCTION,
        "response_mime_type": "application/json",
        "temperature": 0.2,
    },
)

print("\nITERATION 2 DYNAMIC GEMINI RESPONSE (PIVOTED AFTER FEEDBACK):")
print(json.dumps(json.loads(resp2.text), indent=2))
