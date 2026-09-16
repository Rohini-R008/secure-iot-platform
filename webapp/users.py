"""Seed user store with bcrypt-hashed passwords and roles.

In production these would live in a database. For this project a small seed
keeps the RBAC logic legible. Passwords are hashed at import time so no
plaintext password is ever held longer than needed to hash it.
"""
import bcrypt

# Roles
ROLE_OPERATOR = "operator"  # view-only
ROLE_ADMIN = "admin"        # can revoke device credentials

# Default credentials for the demo. CHANGE THESE if you deploy anywhere real.
_SEED = [
    {"username": "operator", "password": "operator123", "role": ROLE_OPERATOR},
    {"username": "admin", "password": "admin123", "role": ROLE_ADMIN},
]


def _hash(password: str) -> bytes:
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())


# Build the user table with hashed passwords (plaintext discarded after this).
USERS = {
    u["username"]: {"role": u["role"], "pw_hash": _hash(u["password"])}
    for u in _SEED
}


def verify_user(username: str, password: str) -> str | None:
    """Return the user's role if credentials are valid, else None."""
    record = USERS.get(username)
    if record is None:
        return None
    if bcrypt.checkpw(password.encode("utf-8"), record["pw_hash"]):
        return record["role"]
    return None


def get_role(username: str) -> str | None:
    record = USERS.get(username)
    return record["role"] if record else None