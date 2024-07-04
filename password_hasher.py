import hashlib
import hmac
from Crypto.Hash import MD4
import getpass

def generate_hashes(password):
    """
    Generate various hashes for a given password.

    Args:
        password (str): The password to hash.

    Returns:
        tuple: A tuple containing the MD5, SHA-1, SHA-256, and NTLM hashes.
    """
    # Convert password to bytes
    password_bytes = password.encode('utf-16le')  # Encode to UTF-16 little-endian for NTLM hash

    # MD5 hash
    md5_hash = hashlib.md5(password.encode()).hexdigest()

    # SHA-1 hash
    sha1_hash = hashlib.sha1(password.encode()).hexdigest()

    # SHA-256 hash
    sha256_hash = hashlib.sha256(password.encode()).hexdigest()

    # NTLM (NT) hash (MD4 hash of UTF-16 little-endian encoded password)
    md4_hash = MD4.new(password_bytes).hexdigest()

    return md5_hash, sha1_hash, sha256_hash, md4_hash

def main():
    
    
    print("""
 _   _    _    ____  _   _  _____ ____  _  __
| | | |  / \  / ___|| | | ||  ___| __ )| |/ /
| |_| | / _ \ \___ \| |_| || |_  |  _ \| ' / 
|  _  |/ ___ \ ___) |  _  ||  _| | |_) | . \ 
|_| |_/_/   \_\____/|_| |_||_|   |____/|_|\_\

By MustafaFBK Password Hasher v1.0
""")
    
  
    
    
    # Input password from user (using getpass for secure input)
    password = getpass.getpass("\nEnter password to hash: ")

    # Generate hashes
    md5_hash, sha1_hash, sha256_hash, nt_hash = generate_hashes(password)

    # Print hashes
    print("\nHashes ===> \n")
    print(f"<=== MD5 ===> \n{md5_hash}")
    print(f"<=== SHA-1 ===> \n{sha1_hash}")
    print(f"<=== SHA-256 ===> \n{sha256_hash}")
    print(f"<=== NTLM(NT) ===> \n{nt_hash}")

if __name__ == "__main__":
    main()
