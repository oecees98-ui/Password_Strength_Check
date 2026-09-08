# Password Strength Checker

A cybersecurity tool written in Python that analyzes how strong a password is.

## Features

- Checks password **length**, **character variety** (upper/lower/digits/special characters)
- Calculates an **entropy estimate** (in bits) — a standard measure of password unpredictability
- Flags passwords found in a list of **commonly leaked/weak passwords**
- Detects **sequential characters** (`1234`, `abcd`) and **repeated characters** (`aaa`)
- Gives a strength rating: `Very Weak` → `Very Strong`
- Provides actionable feedback for improving a weak password

## Why this project matters

Weak and reused passwords are one of the top causes of account compromise. This project demonstrates practical understanding of:
- Password policy enforcement
- Entropy and information theory basics as applied to security
- Building simple, testable security tooling in Python

## Getting Started

### Requirements
- Python 3.7+
- No external dependencies (uses only the standard library)

### Installation
```bash
git clone https://github.com/yourusername/password-strength-checker.git
cd password-strength-checker
```

### Usage

Run interactively (input is hidden as you type):
```bash
python password_checker.py
```

Or pass a password directly (useful for testing, not recommended for real passwords in shell history):
```bash
python password_checker.py --password "MyP@ssw0rd123"
```

### Example Output

```
==================================================
 PASSWORD STRENGTH REPORT
==================================================
Password length     : 13
Estimated entropy   : 85.28 bits
Strength rating     : Very Strong  (score 6/6)
Found in common list: No
--------------------------------------------------
Suggestions:
  - Great password!
==================================================
```

## Project Structure
```
password-strength-checker/
├── password_checker.py     # Main script
├── common_passwords.txt    # Sample list of common/weak passwords
└── README.md
```

## Possible Improvements (good "next steps" to show growth)
- Load a much larger breached-password corpus (e.g. Have I Been Pwned's list)
- Add a simple Tkinter or web (Flask) front end
- Integrate the [zxcvbn](https://github.com/dropbox/zxcvbn) library for more realistic strength estimates
- Add unit tests with `pytest`

## License
MIT License — free to use for learning and portfolio purposes.
