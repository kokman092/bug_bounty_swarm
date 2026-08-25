"""
ingest_h1_policy.py
───────────────────
CLI tool to automatically ingest HackerOne / Bugcrowd program policies,
extract in-scope domains and wildcards, and inject your researcher username into headers.
"""
import asyncio
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).parent.resolve()))

from app.agents.scope_ingestion import ScopeIngestionAgent


async def main():
    print("\033[1;32m" + "=" * 80 + "\033[0m")
    print("\033[1;32m🎯 BUGBOUNTY SWARM — AUTOMATIC SCOPE & RESEARCHER INGESTION AGENT\033[0m")
    print("\033[1;32m" + "=" * 80 + "\033[0m\n")

    # Get username
    if len(sys.argv) > 1:
        username = sys.argv[1]
    else:
        username = input("Enter your HackerOne username / handle: ").strip() or "security_researcher"

    # Get policy input (or sample)
    print("\nPaste the HackerOne program scope text below (Press ENTER on an empty line when done):")
    lines = []
    while True:
        try:
            line = input()
            if not line:
                break
            lines.append(line)
        except EOFError:
            break

    policy_text = "\n".join(lines)
    if not policy_text.strip():
        print("\n[!] No policy text provided. Using default demo scope.")
        policy_text = """
        Program: Example Bug Bounty Program
        In-Scope Assets:
        - *.example.com (Web application)
        - https://api.example.com/v1 (REST API)
        Out-of-Scope:
        - *.thirdparty.com
        - /logout
        Requirements:
        Please include header: X-Bug-Bounty: hackerone-<username>
        """

    print(f"\n[1/2] 🤖 ScopeIngestionAgent analyzing policy for researcher @{username}...")
    agent = ScopeIngestionAgent(researcher_handle=username)
    targets = await agent.ingest_policy(policy_text, program_name="H1Program")

    print(f"\n[2/2] ✅ Successfully Ingested {len(targets)} In-Scope Targets:")
    for t in targets:
        print(f"\n  🎯 \033[1;36mTarget ID:\033[0m    {t.target_id}")
        print(f"     \033[1;33mScope Type:\033[0m   {t.scope_type.value}")
        print(f"     \033[1;33mScope Value:\033[0m  {t.scope_value}")
        print(f"     \033[1;33mNormalized:\033[0m   {t.url_normalized}")
        print(f"     \033[1;33mHeaders:\033[0m      {t.custom_headers}")
        print(f"     \033[1;33mOut of Scope:\033[0m {t.out_of_scope_patterns}")

    print("\n\033[1;32m" + "=" * 80 + "\033[0m")
    print(f"\033[1;32m🎉 Scope configured! You can now run the swarm with your target.\033[0m")
    print("\033[1;32m" + "=" * 80 + "\033[0m\n")


if __name__ == "__main__":
    asyncio.run(main())
