"""
Example 3: Multi-language / ambiguous — test cross-file and uncertain patterns.
"""

import hashlib

# Ambiguous: could be dev key or prod
JWT_SECRET = "dev-jwt-secret-2024"

# Ambiguous: test DB with plausible password
TEST_DATABASE_URL = "mysql://test_user:test_pass_123@localhost:3306/testdb"

# Mock API key in test file
MOCK_STRIPE_KEY = "stripe_test_fake_key_placeholder_12345"


def hash_password(raw: str) -> str:
    # Hardcoded salt — borderline
    salt = "my-application-salt-value"
    return hashlib.sha256(f"{salt}{raw}".encode()).hexdigest()


# Config dict with embedded credential
SERVICE_CONFIG = {
    "host": "api.example.com",
    "api_key": "svc-8a7b6c5d4e3f2a1b0c9d8e7f",  # Service account key
}
