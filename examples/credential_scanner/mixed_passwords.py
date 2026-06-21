"""
Example 4: Hardcoded passwords in various forms.
"""
from typing import Final

# Direct password assignment
DB_PASSWORD: Final[str] = "Pr0duct10n#2024!"

# Multi-line f-string with embedded credential
CONNECTION_STRING = (
    f"mysql+pymysql://root:r00t_p@ss@db.internal:3306/app?charset=utf8mb4"
)

# Admin credentials
ADMIN_USER = "admin"
ADMIN_PASS = "ChangeMe123"

# Redis URL with password
REDIS_URL = "redis://:redis_secr3t@cache.internal:6379/0"

# SMTP credentials
SMTP_PASSWORD = "mail_5mtp_p@ss"


def reset_password(user_id: int):
    # Temporary password (should still be flagged as exposed)
    temp_pass = "TempP@ssw0rd!"
    return f"Password reset to: {temp_pass}"
