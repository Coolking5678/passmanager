"""
password_logic.py
Password strength validation and secure random password generation.
"""

import re
import secrets
import string


# Characters available for generated passwords
_ALPHABET = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{}|;:,.<>?"


def check_strength(password: str) -> tuple[bool, str]:
    """
    Evaluate the strength of a password.

    Checks:
        - Length >= 8 characters
        - At least one uppercase letter
        - At least one lowercase letter
        - At least one digit
        - At least one special character

    Args:
        password: The password string to evaluate.

    Returns:
        A tuple of (is_strong: bool, feedback: str).
        'is_strong' is True only when ALL checks pass.
        'feedback' describes the current strength level with missing criteria.
    """
    if not password:
        return False, ""

    checks = {
        "length":    len(password) >= 8,
        "uppercase": bool(re.search(r"[A-Z]", password)),
        "lowercase": bool(re.search(r"[a-z]", password)),
        "digit":     bool(re.search(r"\d", password)),
        "special":   bool(re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password)),
    }

    passed = sum(checks.values())
    is_strong = all(checks.values())

    missing = []
    if not checks["length"]:
        missing.append("8+ characters")
    if not checks["uppercase"]:
        missing.append("uppercase letter")
    if not checks["lowercase"]:
        missing.append("lowercase letter")
    if not checks["digit"]:
        missing.append("number")
    if not checks["special"]:
        missing.append("special character")

    if is_strong:
        return True, "Strong ✓"
    elif passed >= 3:
        feedback = "Medium – missing: " + ", ".join(missing)
        return False, feedback
    else:
        feedback = "Weak – missing: " + ", ".join(missing)
        return False, feedback


def get_strength_level(password: str) -> str:
    """
    Return a simple one-word strength label: 'Weak', 'Medium', or 'Strong'.
    Used by the UI to colour-code the feedback label.
    """
    if not password:
        return ""

    checks = [
        len(password) >= 8,
        bool(re.search(r"[A-Z]", password)),
        bool(re.search(r"[a-z]", password)),
        bool(re.search(r"\d", password)),
        bool(re.search(r"[!@#$%^&*()\-_=+\[\]{}|;:,.<>?]", password)),
    ]
    passed = sum(checks)

    if passed == 5:
        return "Strong"
    elif passed >= 3:
        return "Medium"
    else:
        return "Weak"


def generate_strong_password(length: int = 16) -> str:
    """
    Generate a cryptographically secure random password.

    Guarantees at least one character from each required category so the
    generated password always passes the strength check.

    Args:
        length: Total length of the generated password (minimum 8).

    Returns:
        A random password string of the requested length.
    """
    length = max(length, 8)

    # Guarantee at least one of each required character type
    required = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice("!@#$%^&*()-_=+[]{}|;:,.<>?"),
    ]

    # Fill the rest of the password from the full alphabet
    rest = [secrets.choice(_ALPHABET) for _ in range(length - len(required))]

    # Combine and shuffle to avoid predictable positions
    password_chars = required + rest
    secrets.SystemRandom().shuffle(password_chars)
    return "".join(password_chars)
