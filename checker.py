#!/usr/bin/env python3  # Shebang so the script can run as an executable on Unix-like systems
# -*- coding: utf-8 -*-  # Declares file encoding for clarity (optional but good practice)

"""
Password Strength Checker (CLI)
- Validates a password against common rules (length, upper, lower, digit, special).
- Outputs a rating: Weak / Medium / Strong and suggestions to improve.
"""

import re  # Import regex module for pattern matching
import argparse  # Import argparse for command-line argument parsing
import sys  # Import sys for exiting with specific codes if needed
import getpass  # Import getpass to securely prompt for passwords without echoing

def evaluate_password(password: str) -> dict:
    """
    Evaluate password strength and return details.
    :param password: the password string to evaluate
    :return: dictionary with rating, score, and suggestions
    """
    # Initialize a dictionary to store checks for each rule
    checks = {
        "length_8_plus": len(password) >= 8,  # True if length is at least 8
        "length_12_plus": len(password) >= 12,  # True if length is at least 12 (bonus)
        "has_upper": bool(re.search(r"[A-Z]", password)),  # True if any uppercase letter exists
        "has_lower": bool(re.search(r"[a-z]", password)),  # True if any lowercase letter exists
        "has_digit": bool(re.search(r"\d", password)),  # True if any digit exists
        "has_special": bool(re.search(r"[^A-Za-z0-9]", password)),  # True if any non-alphanumeric char exists
    }

    # Count how many core rules (excluding the 12+ bonus) are satisfied
    core_rules_met = sum([
        checks["length_8_plus"],  # Count length >= 8
        checks["has_upper"],      # Count uppercase presence
        checks["has_lower"],      # Count lowercase presence
        checks["has_digit"],      # Count digit presence
        checks["has_special"],    # Count special char presence
    ])

    # Start score with number of core rules met
    score = core_rules_met  # Score is initially how many rules are met
    if checks["length_12_plus"]:  # If length >= 12, give a bonus point
        score += 1  # Add one bonus point for longer passwords

    # Decide rating thresholds
    # Strong if at least 4 core rules met and length >= 12 (or score >= 5 including bonus)
    # Medium if at least 3 core rules met
    # Otherwise Weak
    if score >= 5:  # Typically means 4 rules + 12+ length bonus, or all 5 rules met
        rating = "Strong"  # Label the password as Strong
    elif core_rules_met >= 3:  # Meets a decent subset of rules
        rating = "Medium"  # Label the password as Medium
    else:
        rating = "Weak"  # Otherwise label as Weak

    # Build suggestions to improve the password
    suggestions = []  # Start with an empty suggestions list
    if not checks["length_8_plus"]:  # If length is less than 8
        suggestions.append("Use at least 8 characters.")  # Suggest minimum length
    if not checks["length_12_plus"]:  # If length is less than 12
        suggestions.append("Aim for 12+ characters for stronger security.")  # Suggest stronger length
    if not checks["has_upper"]:  # If no uppercase letters
        suggestions.append("Add uppercase letters (A–Z).")  # Suggest uppercase
    if not checks["has_lower"]:  # If no lowercase letters
        suggestions.append("Add lowercase letters (a–z).")  # Suggest lowercase
    if not checks["has_digit"]:  # If no digits
        suggestions.append("Include numbers (0–9).")  # Suggest digits
    if not checks["has_special"]:  # If no special characters
        suggestions.append("Include special characters (e.g., ! @ # $ % ^ & *).")  # Suggest special chars
    if password and password.lower() in ["password", "letmein", "qwerty", "123456", "12345678", "iloveyou"]:
        suggestions.append("Avoid common or easily guessed passwords.")  # Warn against common passwords

    # Return a structured result
    return {
        "rating": rating,  # Final rating string
        "score": score,  # Numeric score based on rules met + bonus
        "length": len(password),  # Length of the password
        "checks": checks,  # Detailed rule checks
        "suggestions": suggestions,  # Suggestions list
    }

def main() -> int:
    """
    Entry point for CLI usage.
    :return: exit code (0 for success)
    """
    # Create argument parser with description for help output
    parser = argparse.ArgumentParser(description="Password Strength Checker (CLI)")  # Parser setup
    # Add optional --password argument so user can pass the password directly
    parser.add_argument("-p", "--password", type=str, help="Password to evaluate (omit to be prompted securely).")  # Arg
    # Parse the arguments from the command line
    args = parser.parse_args()  # Parse CLI args

    # If user passed --password, use it; otherwise securely prompt
    if args.password:  # Check if password was provided via CLI
        pwd = args.password  # Assign provided password to variable
    else:
        print("No password provided. You will be prompted securely (input hidden).")  # Inform the user
        pwd = getpass.getpass("Enter password: ")  # Securely prompt without echo

    # Evaluate the password using our function
    result = evaluate_password(pwd)  # Get the evaluation result dictionary

    # Nicely format and print the result
    print("\n=== Password Strength Report ===")  # Section header
    print(f"Length      : {result['length']}")  # Show length
    print(f"Score       : {result['score']} (rules met + bonus)")  # Show score details
    print(f"Rating      : {result['rating']}")  # Show rating label

    # Print which rules passed/failed
    print("\nRule Checks:")  # Subheader
    for rule, ok in result["checks"].items():  # Loop through each rule
        status = "✅" if ok else "❌"  # Pick checkmark or cross
        print(f"  {status} {rule}")  # Print rule line

    # Print suggestions if any
    if result["suggestions"]:  # Only show if there are suggestions
        print("\nSuggestions:")  # Suggestions header
        for s in result["suggestions"]:  # Loop through suggestions
            print(f"  • {s}")  # Print bullet line
    else:
        print("\nGreat job! No suggestions. 🎉")  # Congratulatory message if none

    return 0  # Return success exit code

# Standard Python pattern to only run main() if this file is executed directly
if __name__ == "__main__":  # Check if module is run as script
    sys.exit(main())  # Call main and exit with its return code
