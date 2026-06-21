"""
Example 1: Hardcoded API keys and tokens — should flag as EXPOSED.
"""

import os

# Real-looking OpenAI key pattern
OPENAI_API_KEY = "sk-proj-1A2b3C4d5E6f7G8h9I0jK1lM2n3O4p5Q6r"

# Real-looking GitHub PAT
GITHUB_TOKEN = "ghp_1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0"

# Real-looking AWS key pattern
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


class Config:
    # Hardcoded in class attribute
    DATABASE_URL = "postgresql://admin:SuperSecret123!@localhost:5432/prod"


# Hardcoded password variable — triggers bandit B105
password = "Pr0dS3cr3t!2024"


def connect(host="db.internal", passwd="r00t_p@ss"):
    # Hardcoded password as function arg default — triggers bandit B106/B107
    return os.popen(f"mysql -u root -h {host} -p'{passwd}'")
