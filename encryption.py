# shar7 el code: el file be import fernet 3lshan na3mel encryption w decryption b AES-128
# el file da kaman be import hashlib 3lshan na3mel hashing lel passwords
# be3mel funtion make_key_from_password 3lshan ya3mel key lel encryption based 3ala el password
# be7awel el password le bytes 3lshan betkon ashal lel computer eno yet3amel ma3 bytes 3an charcters
# behash el password 1000 mara 3lshan yeb2a strong
# be3mel base64 encoding 3lshan yeb2a el key text format mesh bytes format for Fernet
# be3mel encrypt_file function 3lshan ya5od el password wel file content w yerga3 el encrypted version
# be3mel decrypt_file function 3lshan ya5od el password wel encrypted content w yerga3 el original content
# test: run the file alone to test the encryption and decryption process, and also test with a wrong password to check security 
#-----------------------------------------------------------------------------------------------------------------------------------------
# Fernet: Encryption tool that scrambles and unscrambles using AES-128
# It takes a key to encrypt or decrypt your files
from cryptography.fernet import Fernet

# Hashlib: Creates hashes (digital fingerprints) of data
# A hash turns input into fixed random-looking output
# One-way: Cannot reverse a hash to get the original password
# We hash the password many times to stop hackers
import hashlib

# This function takes a password and creates an encryption key
# Same password creates the same key
def make_key_from_password(password):
    # Convert password from string to bytes (computers need bytes)
    password_bytes = password.encode()
    
    # Hash the password 1000 times to make it strong
    # Each bit becomes different from the original
    for i in range(1000):
        password_bytes = hashlib.sha256(password_bytes).digest()
    
    # using base64 to make it from bytes to character. return the encryption tool
    from base64 import urlsafe_b64encode
    # Convert the hashed password (bytes) into a text format key
    key = urlsafe_b64encode(password_bytes)
    return Fernet(key)


# Encrypt function: Takes password and file. returns encrypted version
def encrypt_file(password, file_content):
    cipher = make_key_from_password(password)
    return cipher.encrypt(file_content)


# Decrypt function: Takes password and encrypted file. returns original
def decrypt_file(password, encrypted_content):
    cipher = make_key_from_password(password)
    return cipher.decrypt(encrypted_content)


# TEST (run this file alone to test)
if __name__ == "__main__":
    print()
    print("TESTING AES ENCRYPTION SYSTEM")
    print()
    
    my_password = "mysecret123"
    print("1. Using password: " + my_password)
    print()
    
    secret = b"Hello, this is my secret document!"
    print("2. Original message: " + secret.decode())
    print()
    
    # Encrypt - turns message into garbage
    encrypted = encrypt_file(my_password, secret)
    print("3. Encrypted (looks like garbage): " + str(encrypted[:50]) + "...")
    print()
    
    # Decrypt - turns garbage back to original
    decrypted = decrypt_file(my_password, encrypted)
    print("4. Decrypted back: " + decrypted.decode())
    print()
    
    if secret == decrypted:
        print("SUCCESS! Encryption and decryption work perfectly!")
    else:
        print("FAILED! Something went wrong!")
    print()
    
    # Test wrong password
    print("Testing security: Wrong password attempt")
    print()
