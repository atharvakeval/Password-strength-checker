Password Strength Checker — Cybersecurity Project

Weak passwords are still a top cause of breaches. This tool evaluates password strength using regex-based policy checks, entropy estimation, and a local “common password” list. No passwords are stored or transmitted.

 Features
- Policy checks: length, lowercase, uppercase, digit, symbol
- Entropy (bits) + rough crack-time estimate
- Local check against common/leaked passwords
- CLI + Tkinter GUI
- No external dependencies; Python standard library only

Quick Start
bash
git clone <your-repo-url>
cd password-strength-checker/src
python cli.py
# or GUI
python gui_tkinter.py

Screenshots
GUI Example
![GUI Example 1](screenshots/gui1.png)
![GUI Example 2](screenshots/gui2.png)
