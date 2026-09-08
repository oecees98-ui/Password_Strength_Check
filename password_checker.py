#!/usr/bin/env python3
"""
Password Strength Checker
--------------------------
A beginner-friendly cybersecurity tool that analyzes password strength
using multiple criteria: length, character variety, entropy, and
comparison against a list of commonly leaked/weak passwords.

Usage:
    python password_checker.py
    python password_checker.py --password "MyP@ssw0rd123"
"""

import argparse
import math
import re
import sys
import os

# A small sample of extremely common/weak passwords for demonstration.
# In a real-world tool you'd load a much larger list (e.g. rockyou.txt).
COMMON_PASSWORDS_FILE = os.path.join(os.path.dirname(__file__), "common_passwords.txt")


def load_common_passwords(filepath):
    try:
        with open(filepath, "r", encoding="utf-8") as f:
            return set(line.strip().lower() for line in f if line.strip())
    except FileNotFoundError:
        return set()


def calculate_entropy(password: str) -> float:
    """Estimate password entropy in bits based on character pool size."""
    pool_size = 0
    if re.search(r"[a-z]", password):
        pool_size += 26
    if re.search(r"[A-Z]", password):
        pool_size += 26
    if re.search(r"[0-9]", password):
        pool_size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool_size += 32  # rough estimate of common special characters

    if pool_size == 0:
        return 0.0

    return round(len(password) * math.log2(pool_size), 2)


def check_password(password: str, common_passwords: set) -> dict:
    """Run all checks and return a report dictionary."""
    report = {
        "length": len(password),
        "has_lower": bool(re.search(r"[a-z]", password)),
        "has_upper": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_special": bool(re.search(r"[^a-zA-Z0-9]", password)),
        "entropy_bits": calculate_entropy(password),
        "is_common": password.lower() in common_passwords,
        "has_sequential": bool(re.search(r"(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef)", password.lower())),
        "has_repeated_chars": bool(re.search(r"(.)\1{2,}", password)),
    }

    score = 0
    feedback = []

    if report["length"] >= 12:
        score += 2
    elif report["length"] >= 8:
        score += 1
    else:
        feedback.append("Use at least 8 characters (12+ recommended).")

    for key, msg in [
        ("has_lower", "Add lowercase letters."),
        ("has_upper", "Add uppercase letters."),
        ("has_digit", "Add numbers."),
        ("has_special", "Add special characters (e.g. !@#$%)."),
    ]:
        if report[key]:
            score += 1
        else:
            feedback.append(msg)

    if report["is_common"]:
        score = 0
        feedback.append("This password appears in a list of commonly used/leaked passwords. Avoid it.")

    if report["has_sequential"]:
        score -= 1
        feedback.append("Avoid sequential characters like '1234' or 'abcd'.")

    if report["has_repeated_chars"]:
        score -= 1
        feedback.append("Avoid repeating the same character 3+ times in a row.")

    score = max(0, min(score, 6))

    strength_levels = {
        0: "Very Weak",
        1: "Weak",
        2: "Weak",
        3: "Moderate",
        4: "Strong",
        5: "Strong",
        6: "Very Strong",
    }

    report["score"] = score
    report["strength"] = strength_levels[score]
    report["feedback"] = feedback if feedback else ["Great password!"]

    return report


def print_report(password: str, report: dict):
    print("\n" + "=" * 50)
    print(" PASSWORD STRENGTH REPORT")
    print("=" * 50)
    print(f"Password length     : {report['length']}")
    print(f"Estimated entropy   : {report['entropy_bits']} bits")
    print(f"Strength rating     : {report['strength']}  (score {report['score']}/6)")
    print(f"Found in common list: {'YES - unsafe!' if report['is_common'] else 'No'}")
    print("-" * 50)
    print("Suggestions:")
    for tip in report["feedback"]:
        print(f"  - {tip}")
    print("=" * 50 + "\n")


def main():
    parser = argparse.ArgumentParser(description="Check the strength of a password.")
    parser.add_argument("--password", "-p", help="Password to check (omit to be prompted securely)")
    args = parser.parse_args()

    common_passwords = load_common_passwords(COMMON_PASSWORDS_FILE)

    if args.password:
        password = args.password
    else:
        import getpass
        password = getpass.getpass("Enter a password to check (input hidden): ")

    if not password:
        print("No password entered.")
        sys.exit(1)

    report = check_password(password, common_passwords)
    print_report(password, report)


if __name__ == "__main__":
    main()
