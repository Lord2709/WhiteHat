import os
from typing import Optional

from dotenv import load_dotenv


# Load .env from the same directory as backend entrypoint.
load_dotenv(os.path.join(os.path.dirname(__file__), ".env"))


def env_key(name: str) -> Optional[str]:
    """Read non-placeholder API keys from environment."""
    val = os.getenv(name, "").strip()
    return val if val and not val.startswith("your_") else None


ENV_GEMINI_KEY = env_key("GEMINI_API_KEY")
ENV_ANTHROPIC_KEY = env_key("ANTHROPIC_API_KEY")
ENV_NVD_KEY = env_key("NVD_API_KEY")
SAMPLE_DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "sample_data"))
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
DB_PATH = os.path.join(DATA_DIR, "whitehat.db")
