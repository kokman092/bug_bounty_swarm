from google import genai
from app.core.config import get_settings

settings = get_settings()
client = genai.Client(api_key=settings.gemini_api_key)

models_to_test = [
    "gemini-2.5-flash-lite",
    "gemini-3.5-flash",
    "gemini-3.5-flash-lite",
    "gemini-flash-latest",
    "gemini-flash-lite-latest",
    "gemma-4-26b-a4b-it",
]

for m in models_to_test:
    try:
        resp = client.models.generate_content(
            model=m,
            contents="Say 'OK'",
        )
        print(f"Model '{m}': SUCCESS -> {resp.text.strip()}")
    except Exception as e:
        print(f"Model '{m}': FAILED -> {e}")
