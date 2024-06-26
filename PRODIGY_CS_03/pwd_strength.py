import re

def assess_password_strength(password):
    length_score = 0
    uppercase_score = 0
    lowercase_score = 0
    digit_score = 0
    special_char_score = 0

    # Length
    if len(password) >= 8:
        length_score = 1
    elif len(password) >= 6:
        length_score = 0.5

    # Uppercase
    if re.search(r'[A-Z]', password):
        uppercase_score = 1

    # Lowercase
    if re.search(r'[a-z]', password):
        lowercase_score = 1

    # Digit
    if re.search(r'\d', password):
        digit_score = 1

    # Special character
    if re.search(r'[^A-Za-z0-9]', password):
        special_char_score = 1

    # Calculate total score
    total_score = length_score + uppercase_score + lowercase_score + digit_score + special_char_score

    # Assess strength based on total score
    if total_score == 5:
        return "Strong"
    elif total_score >= 3:
        return "Moderate"
    else:
        return "Weak"

def main():
    while True:
        password = input("Enter a password to assess its strength: ")
        if password:
            strength = assess_password_strength(password)
            print(f"Strength: {strength}")
            break
        else:
            print("Please enter a password.")

if __name__ == "__main__":
    main()