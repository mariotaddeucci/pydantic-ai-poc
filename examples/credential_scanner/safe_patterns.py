"""
Example 2: Safe patterns — should be FALSE POSITIVE or not flagged at all.
"""
import os
from config import settings


# Environment variable reference — safe
DATABASE_URL = os.environ.get("DATABASE_URL", "postgresql://localhost/test")

# Settings object — safe
SECRET_KEY = settings.SECRET_KEY

# getenv pattern — safe
API_TOKEN = os.getenv("API_TOKEN", "")

# Empty/placeholder — safe (ruff won't flag empty strings)
DEBUG_PASSWORD = ""

# Placeholder value — should be UNCERTAIN (could be mock or real)
DEV_SECRET = "your-secret-key-here"

# Documentation example — FALSE POSITIVE
EXAMPLE_TOKEN = "sk-example-not-a-real-key"


class AppConfig:
    # Retrieved via method, not hardcoded
    def get_password(self):
        return os.environ["DB_PASS"]
