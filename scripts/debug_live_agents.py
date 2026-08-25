import asyncio
import json
from google import genai
from app.core.config import get_settings
from app.agents.recon import ReconAgent
from app.agents.attack_surface import AttackSurfaceAgent
from app.agents.hunter import SYSTEM_INSTRUCTION

async def debug():
    settings = get_settings()
    client = genai.Client(api_key=settings.gemini_api_key)
    
    recon = ReconAgent("inv-debug", "http://127.0.0.1:5000")
    recon_res = await recon.run()
    print("RECON RESULT:", json.dumps(recon_res, indent=2))
    
    asa = AttackSurfaceAgent("inv-debug")
    asa_res = await asa.run(recon_res)
    print("\nATTACK SURFACE RESULT:", json.dumps(asa_res, indent=2))
    
    prompt = f"""
Current Iteration: 1

Live Target Attack Surface:
{json.dumps(asa_res, indent=2)}

ALREADY PROPOSED HYPOTHESES:
[]

PREVIOUS REVIEW FEEDBACK:
None (Initial attempt)

Instructions:
1. Select the most promising attack vector from the attack surface.
2. Generate structured HTTP test steps. For BOLA/IDOR, test cross-tenant access using 'bob_token_456' on resources belonging to user 1.
"""
    print("\nHUNTER PROMPT SENT TO GEMINI:\n", prompt)
    
    resp = client.models.generate_content(
        model="gemini-3.6-flash",
        contents=prompt,
        config={
            "system_instruction": SYSTEM_INSTRUCTION,
            "response_mime_type": "application/json",
            "temperature": 0.2,
        },
    )
    print("\nHUNTER RAW GEMINI TEXT:")
    print(repr(resp.text))
    print("\nPARSED JSON:")
    if resp.text:
        print(json.dumps(json.loads(resp.text), indent=2))
    else:
        print("resp.text is EMPTY! Candidates / usage:")
        print(resp)

asyncio.run(debug())
