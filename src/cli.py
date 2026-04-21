import argparse
import getpass
from password_strength import evaluate_password, load_common_passwords

def main():
    parser = argparse.ArgumentParser(description="Password Strength Checker (Cybersecurity)")
    parser.add_argument("-p", "--password", help="Password to check (omit to enter securely)")
    parser.add_argument("--common", default=None,
                        help="Path to common passwords file (optional)")
    args = parser.parse_args()

    pw = args.password or getpass.getpass("Enter a password to check (input hidden): ")
    common = load_common_passwords(args.common) if args.common else load_common_passwords()
    result = evaluate_password(pw, common)

    print("\n=== Password Report ===")
    print(f"Strength     : {result['label']} (score {result['score']}/6)")
    print(f"Entropy      : {result['entropy_bits']} bits")
    print(f"Crack time*  : ~{result['est_crack_time']}")
    print(f"In common db : {'Yes' if result['found_in_common'] else 'No'}")
    print("\nPolicy checks:")
    for name, ok in result["checks"].items():
        print(f"  {'✔' if ok else '✘'} {name}")

    print("\nFeedback:")
    for tip in result["suggestions"]:
        print(f"  - {tip}")

    print("\n*Educational estimate assuming ~1e9 guesses/sec.")

if __name__ == "__main__":
    main()
