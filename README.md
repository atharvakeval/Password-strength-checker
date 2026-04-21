# Password Strength Checker — Cybersecurity Project

Weak passwords are a top cause of breaches. This tool evaluates password strength using policy checks, entropy estimation, and a local “common password” list. No passwords are stored or transmitted.

## Features
- ✅ Policy checks: length, lowercase, uppercase, digit, symbol
- ✅ Entropy (bits) + rough crack-time estimate
- ✅ Local check against common/leaked passwords
- ✅ CLI + Tkinter GUI
- ✅ No external dependencies; Python standard library only

## Quick Start
```bash
# Windows (PowerShell or CMD) — from the repo folder
python src/cli.py
# or
python src/gui_tkinter.py

Security
Everything runs locally. The app never logs, stores, or sends your password.
Screenshots
Strong password
Very weak password
Both the screenshot is present in the screenshot folder 
