def caesar_cipher_encrypt(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                encrypted_text += chr((ord(char) - 97 + shift) % 26 + 97)
            elif char.isupper():
                encrypted_text += chr((ord(char) - 65 + shift) % 26 + 65)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_cipher_decrypt(text, shift):
    decrypted_text = ""
    for char in text:
        if char.isalpha():
            if char.islower():
                decrypted_text += chr((ord(char) - 97 - shift) % 26 + 97)
            elif char.isupper():
                decrypted_text += chr((ord(char) - 65 - shift) % 26 + 65)
        else:
            decrypted_text += char
    return decrypted_text

def main():
    while True:
        choice = input("Do you want to encrypt or decrypt? (encrypt/decrypt): ").lower()
        if choice == "encrypt":
            message = input("Enter the message to encrypt: ")
            shift = int(input("Enter the shift value: "))
            encrypted_message = caesar_cipher_encrypt(message, shift)
            print("Encrypted message:", encrypted_message)
            break
        elif choice == "decrypt":
            message = input("Enter the message to decrypt: ")
            shift = int(input("Enter the shift value: "))
            decrypted_message = caesar_cipher_decrypt(message, shift)
            print("Decrypted message:", decrypted_message)
            break
        else:
            print("Invalid choice. Please enter 'encrypt' or 'decrypt'.")

if __name__ == "__main__":
    main()