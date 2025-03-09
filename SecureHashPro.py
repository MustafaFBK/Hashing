import hashlib
import hmac
from Crypto.Hash import MD4
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import getpass

# Constants
SALT_SIZE = 16  # 16 bytes (128 bits) for salt
AES_KEY_SIZE = 32  # 32 bytes (256 bits) for AES key
HMAC_KEY_SIZE = 32  # 32 bytes (256 bits) for HMAC key

def generate_salt():
    """
    Generate a random salt for password hashing.

    Returns:
        bytes: Random salt.
    """
    return os.urandom(SALT_SIZE)

def generate_md5(password, salt):
    """Generate MD5 hash."""
    return hashlib.md5(salt + password.encode()).hexdigest()

def generate_sha1(password, salt):
    """Generate SHA-1 hash."""
    return hashlib.sha1(salt + password.encode()).hexdigest()

def generate_sha256(password, salt):
    """Generate SHA-256 hash."""
    return hashlib.sha256(salt + password.encode()).hexdigest()

def generate_ntlm(password):
    """Generate NTLM (NT) hash."""
    password_bytes = password.encode('utf-16le')  # Encode to UTF-16 little-endian for NTLM hash
    return MD4.new(password_bytes).hexdigest()

def encrypt_data(data, key):
    """
    Encrypt data using AES-256-CBC.

    Args:
        data (str): Data to encrypt.
        key (bytes): AES encryption key.

    Returns:
        tuple: A tuple containing the encrypted data and initialization vector (IV).
    """
    iv = os.urandom(16)  # 16 bytes (128 bits) for IV
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_data = cipher.encrypt(pad(data.encode(), AES.block_size))
    return encrypted_data, iv

def decrypt_data(encrypted_data, key, iv):
    """
    Decrypt data using AES-256-CBC.

    Args:
        encrypted_data (bytes): Encrypted data.
        key (bytes): AES encryption key.
        iv (bytes): Initialization vector.

    Returns:
        str: Decrypted data.
    """
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(encrypted_data), AES.block_size)
    return decrypted_data.decode()

def generate_hmac(data, key):
    """
    Generate HMAC for data integrity.

    Args:
        data (bytes): Data to generate HMAC for.
        key (bytes): HMAC key.

    Returns:
        str: HMAC hexdigest.
    """
    return hmac.new(key, data, hashlib.sha256).hexdigest()

def display_menu():
    """Display the menu options."""
    print("\nChoose an option:")
    print("1. Generate MD5 Hash")
    print("2. Generate SHA-1 Hash")
    print("3. Generate SHA-256 Hash")
    print("4. Generate NTLM (NT) Hash")
    print("5. Encrypt Password (AES-256-CBC)")
    print("6. Decrypt Password (AES-256-CBC)")
    print("7. Generate HMAC for Data")
    print("8. Exit")

def main():
    # Banner
    print(r"""
 ____                           _   _           _     ____
/ ___|  ___  ___ _   _ _ __ ___| | | | __ _ ___| |__ |  _ \ _ __ ___
\___ \ / _ \/ __| | | | '__/ _ \ |_| |/ _` / __| '_ \| |_) | '__/ _ \
 ___) |  __/ (__| |_| | | |  __/  _  | (_| \__ \ | | |  __/| | | (_) |
|____/ \___|\___|\__,_|_|  \___|_| |_|\__,_|___/_| |_|_|   |_|  \___/
By Mustafa Banikhalaf
    """)

    # Input password from user (using getpass for secure input)
    password = getpass.getpass("\nEnter password: ")

    # Generate salt
    salt = generate_salt()
    print(f"\nGenerated Salt: {salt.hex()}")

    while True:
        display_menu()
        choice = input("\nEnter your choice (1-8): ")

        if choice == "1":
            # MD5 Hash
            md5_hash = generate_md5(password, salt)
            print(f"\n<=== MD5 Hash ===>\n{md5_hash}")

        elif choice == "2":
            # SHA-1 Hash
            sha1_hash = generate_sha1(password, salt)
            print(f"\n<=== SHA-1 Hash ===>\n{sha1_hash}")

        elif choice == "3":
            # SHA-256 Hash
            sha256_hash = generate_sha256(password, salt)
            print(f"\n<=== SHA-256 Hash ===>\n{sha256_hash}")

        elif choice == "4":
            # NTLM (NT) Hash
            nt_hash = generate_ntlm(password)
            print(f"\n<=== NTLM (NT) Hash ===>\n{nt_hash}")

        elif choice == "5":
            # AES Encryption
            aes_key = os.urandom(AES_KEY_SIZE)
            print(f"\nGenerated AES Key: {aes_key.hex()}")
            encrypted_password, iv = encrypt_data(password, aes_key)
            print(f"\n<=== Encrypted Password ===>\n{encrypted_password.hex()}")
            print(f"<=== Initialization Vector (IV) ===>\n{iv.hex()}")

        elif choice == "6":
            # AES Decryption
            aes_key_hex = input("Enter AES Key (hex): ")
            iv_hex = input("Enter Initialization Vector (IV) (hex): ")
            encrypted_password_hex = input("Enter Encrypted Password (hex): ")

            try:
                aes_key = bytes.fromhex(aes_key_hex)
                iv = bytes.fromhex(iv_hex)
                encrypted_password = bytes.fromhex(encrypted_password_hex)
                decrypted_password = decrypt_data(encrypted_password, aes_key, iv)
                print(f"\n<=== Decrypted Password ===>\n{decrypted_password}")
            except ValueError:
                print("\nInvalid input. Please enter valid hex values.")

        elif choice == "7":
            # HMAC Generation
            hmac_key = os.urandom(HMAC_KEY_SIZE)
            print(f"\nGenerated HMAC Key: {hmac_key.hex()}")
            hmac_value = generate_hmac(password.encode(), hmac_key)
            print(f"\n<=== HMAC for Password ===>\n{hmac_value}")

        elif choice == "8":
            # Exit
            print("\nExiting the program. Goodbye!")
            break

        else:
            print("\nInvalid choice. Please select a valid option (1-8).")

if __name__ == "__main__":
    main()
