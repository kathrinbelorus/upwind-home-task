import os

# Must be set before the app is imported, because settings are read at import.
os.environ["API_KEY"] = "test-key-0123456789abcdef"
# Never call the real Gemini from tests, even if a key is in .env.
os.environ["GEMINI_API_KEY"] = ""
