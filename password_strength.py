"""
Password Strength Checker (Cybersecurity Edition)
- Does NOT store or transmit passwords.
- Uses regex-based policy checks + entropy estimate.
- Optional check against a local list of common/leaked passwords (data/common_passwords.txt).
"""

from __future__ import annotations
import math
import re
from pathlib import Path

SYMBOLS = r"!@#$%^&*()\-_=+\[\]{}\\|;:'\",<.>/?`~"
SYMBOL_SET = set(SYMBOLS)  # for counting charset size

CHECKS = {
    "length>=8": lambda s: len(s) >= 8,
    "has_lower": lambda s: re.search(r"[a-z]", s) is not None,
    "has_upper": lambda s: re.search(r"[A-Z]", s) is not None,
    "has_digit": lambda s: re.search(r"\d", s) is not None,
    "has_symbol": lambda s: re.search(rf"[{re.escape(SYMBOLS)}]", s) is not None,
    "length>=12": lambda s: len(s) >= 12,
}

def load_common_passwords(path: str | Path = "../data/common_passwords.txt") -> set[str]:
    p = Path(path)
    if not p.exists():
        # Fallback minimal set if file missing (still works)
        return {"123456", "password", "qwerty", "abc123", "111111"}
    return {line.strip().lower() for line in p.read_text(encoding="utf-8").splitlines() if line.strip()}

def _charset_size(pw: str) -> int:
    size = 0
    if re.search(r"[a-z]", pw): size += 26
    if re.search(r"[A-Z]", pw): size += 26
    if re.search(r"\d", pw):    size += 10
    if re.search(rf"[{re.escape(SYMBOLS)}]", pw):
        size += len(SYMBOL_SET)
    return size

def _pretty_time(seconds: float) -> str:
    # convert seconds to a human-friendly string
    units = [
        ("years", 365.25 * 24 * 3600),
        ("days", 24 * 3600),
        ("hours", 3600),
        ("minutes", 60),
        ("seconds", 1),
        ("milliseconds", 1e-3),
        ("microseconds", 1e-6),
        ("nanoseconds", 1e-9),
    ]
    for name, unit in units:
        if seconds >= unit:
            value = seconds / unit
            return f"{value:.2f} {name}"
    return "instant"

def evaluate_password(pw: str, common_set: set[str] | None = None) -> dict:
    """
    Returns:
      {
        'label': 'Very Weak'|'Weak'|'Medium'|'Strong'|'Very Strong',
        'score': int 0..6,
        'checks': {name: bool, ...},
        'suggestions': [str, ...],
        'entropy_bits': float,
        'est_crack_time': '2.3 years',
        'found_in_common': bool
      }
    """
    # common/leaked check (local only; never sent online)
    if common_set is None:
        common_set = load_common_passwords()
    found_in_common = pw.lower() in common_set

    # run checks
    results = {name: fn(pw) for name, fn in CHECKS.items()}

    # score (max 6): base on checks (length>=8, >=12, lower, upper, digit, symbol)
    score = sum(int(v) for v in results.values())

    # suggestions
    suggestions = []
    if not results["length>=8"]:
        suggestions.append("Use at least 8 characters (12+ recommended).")
    if not results["has_lower"]:
        suggestions.append("Add at least one lowercase letter.")
    if not results["has_upper"]:
        suggestions.append("Add at least one uppercase letter.")
    if not results["has_digit"]:
        suggestions.append("Add at least one number.")
    if not results["has_symbol"]:
        suggestions.append("Add at least one symbol (e.g., !@#$%).")
    if found_in_common:
        suggestions.insert(0, "This password appears in common/leaked lists. Choose a different one.")

    # label mapping
    if found_in_common or len(pw) < 6:
        label = "Very Weak"
    elif score >= 6:
        label = "Very Strong"
    elif score >= 4:
        label = "Strong"
    elif score >= 3:
        label = "Medium"
    else:
        label = "Weak"

    # entropy + cracking time estimate (rough, educational)
    charset = _charset_size(pw)
    entropy_bits = len(pw) * math.log2(charset) if charset else 0.0
    # expected guesses ~ 2^(entropy-1). Assume 1e9 guesses/sec (single high-end GPU).
    guesses_per_sec = 1e9
    expected_guesses = 2 ** max(entropy_bits - 1, 0)
    est_seconds = expected_guesses / guesses_per_sec if guesses_per_sec else float("inf")
    est_crack_time = _pretty_time(est_seconds)

    return {
        "label": label,
        "score": score,
        "checks": results,
        "suggestions": suggestions or ["Looks good! Consider using a password manager."],
        "entropy_bits": round(entropy_bits, 2),
        "est_crack_time": est_crack_time,
        "found_in_common": found_in_common,
    }
