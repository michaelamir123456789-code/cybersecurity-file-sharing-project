# shar7 el code: el file be import AES 3lshan na3mel encryption w decryption b AES-256
#import pad w unpad 3lshan na3mel padding lel data 3lshan yeb2a length sah w yesha8al el AES 
# el file da kaman be import hashlib 3lshan na3mel hashing lel passwords fa el input yet8ayar w el hacker ma3rafsh el password asly
# el file da kaman be import os 3lshan na3mel random salt w IV (Initialization Vector) 3lshan yeb2a el encryption akthar amn
# el file da kaman be import base64 3lshan na3mel encoding lel encrypted data w el key 3lshan yeb2a text format ashal lel storage w el sharing
# be3mel funtion make_key_from_password 3lshan ya3mel key lel encryption based 3ala el password
# be7awel el password le bytes 3lshan betkon ashal lel computer eno yet3amel ma3 bytes 3an charcters
# behash el password 100,000 mara 3lshan yeb2a strong (Aster 1000 mara 3lshan el security a3la)
# be3mel base64 encoding 3lshan yeb2a el key text format mesh bytes format
# be3mel encrypt_file function 3lshan ya5od el password wel file content w yerga3 el encrypted version
# be3mel decrypt_file function 3lshan ya5od el password wel encrypted content w yerga3 el original content
# test: run the file alone to test the encryption and decryption process, and also test with a wrong password to check security 
#-----------------------------------------------------------------------------------------------------------------------------------------

# AES: Encryption tool bet scrambles and unscrambles using AES-256 (Military Grade)
# beta5od key 3lshan encrypt or decrypt your files
from Crypto.Cipher import AES

# Padding: Makes data length correct for AES blocks (16 bytes)
from Crypto.Util.Padding import pad, unpad

# Hashlib: Creates hashes (digital fingerprints) of data
# A hash turns input into fixed random-looking output
# hashlib 3lshan na3mel hashing lel passwords fa el input yet8ayar kaza mara to stop hackers 
# betkon one way: (maynfa3sh a reverse el hash 3lshan ageb el original password)
import hashlib

# os: Provides random bytes for salt and IV (Initialization Vector)
import os

# base64: Converts bytes to text format for easy storage
import base64


# FUNCTION 1: make_key_from_password (Be3mel funtion make_key_from_password 3lshan ya3mel key lel encryption based 3ala el password)
# This function takes a password and creates an AES-256 encryption key
# Same password creates the same key (if same salt is used)
def make_key_from_password(password, salt=None):
    # Convert password from string to bytes (computers need bytes)
    # Be7awel el password le bytes 3lshan betkon ashal lel computer
    password_bytes = password.encode()
    # If no salt provided, generate random 16 bytes
    # Salt makes each key unique even if passwords are the same
    if salt is None:
        salt = os.urandom(16)  # 16 bytes random
    
    # Hash the password 100,000 times to make it strong
    # PBKDF2 = Password-Based Key Derivation Function 2
    # ba8ayar el password 100,000 mara 3lshan yeb2a strong (Aster 1000 mara)
    # Each bit becomes different from the original
    # 100,000 iterations makes it very hard for hackers to crack
    key = hashlib.pbkdf2_hmac(
        'sha256',           # Hash algorithm (SHA-256 is very secure)
        password_bytes,     # The password in bytes
        salt,               # Random salt
        100000,             # 100,000 iterations (Aster 1000 mara)
        dklen=32            # 32 bytes = 256 bits (AES-256)
    )
    
    # Return both the key and the salt (salt needed for decryption)
    return key, salt


# FUNCTION 2: encrypt_file
# Encrypt function: Takes password and file content, returns encrypted version
# Be3mel encrypt_file function 3lshan ya5od el password wel file content w yerga3 el encrypted version
def encrypt_file(password, file_content):
    # STEP 1: Generate random salt (16 bytes)
    # Salt protects against rainbow table attacks
    salt = os.urandom(16)

    # STEP 2: Generate random IV (16 bytes)
    # IV = Initialization Vector (makes same file encrypt differently each time)
    iv = os.urandom(16)

    # STEP 3: Make the AES-256 key from password and salt
    key, _ = make_key_from_password(password, salt)

    # STEP 4: Create AES cipher in CBC mode with the IV
    # CBC = Cipher Block Chaining (each block depends on previous)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # STEP 5: Pad the data to be multiple of 16 bytes (AES block size)
    padded_data = pad(file_content, AES.block_size)
    
    # STEP 6: Encrypt the padded data
    # Encrypt - turns message into garbage
    ciphertext = cipher.encrypt(padded_data)
    
    # STEP 7: Combine salt + IV + ciphertext
    combined = salt + iv + ciphertext
    
    # Using base64 to make it from bytes to characters
    # Be3mel base64 encoding 3lshan yeb2a el key text format mesh bytes format
    encrypted_b64 = base64.b64encode(combined).decode('utf-8')
    
    # Return the encrypted version as text
    return encrypted_b64


# FUNCTION 3: decrypt_file
# Decrypt function: Takes password and encrypted content, returns original
# Be3mel decrypt_file function 3lshan ya5od el password wel encrypted content w yerga3 el original content
def decrypt_file(password, encrypted_b64):
    
    # STEP 1: Decode from base64 back to bytes
    encrypted_data = base64.b64decode(encrypted_b64)
    
    # STEP 2: Extract salt (first 16 bytes)
    salt = encrypted_data[:16]
    
    # STEP 3: Extract IV (next 16 bytes)
    iv = encrypted_data[16:32]
    
    # STEP 4: Extract ciphertext (everything after 32 bytes)
    ciphertext = encrypted_data[32:]
    
    # STEP 5: Recreate the same key using password and extracted salt
    key, _ = make_key_from_password(password, salt)
    
    # STEP 6: Create AES cipher for decryption
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # STEP 7: Decrypt the ciphertext
    decrypted_padded = cipher.decrypt(ciphertext)
    
    # STEP 8: Remove padding to get original data
    original_data = unpad(decrypted_padded, AES.block_size)
    
    # Return the original file content
    return original_data


# ============================================================
# TEST (run this file alone to test)
# ============================================================

# test: run the file alone to test the encryption and decryption process, 
# and also test with a wrong password to check security
if __name__ == "__main__":
    print()
    print("TESTING AES-256 ENCRYPTION SYSTEM")
    print()
    
    # Test with a password
    my_password = "mysecret123"
    print("1. Using password: " + my_password)
    print()
    
    # Create a secret message to test
    secret = b"Hello, this is my secret document! This is AES-256 military grade encryption."
    print("2. Original message: " + secret.decode())
    print()
    
    # ENCRYPT: Turn the message into garbage (to confuse any spies)
    # Encrypt - turns message into garbage
    encrypted = encrypt_file(my_password, secret)
    print("3. Encrypted (looks like garbage): " + str(encrypted[:50]) + "...")
    print()
    
    # DECRYPT: Turn the garbage back to original
    # Decrypt - turns garbage back to original
    decrypted = decrypt_file(my_password, encrypted)
    print("4. Decrypted back: " + decrypted.decode())
    print()
    
    # Check if it worked
    if secret == decrypted:
        print("✅ SUCCESS! Encryption and decryption work perfectly!")
    else:
        print("❌ FAILED! Something went wrong!")
    print()
    
    # TEST WRONG PASSWORD - This is important for security!
    # If someone tries wrong password, it MUST fail
    print("Testing security: Wrong password attempt")
    print("-"*40)
    
    try:
        # Try to decrypt with WRONG password
        wrong_decrypt = decrypt_file("wrongpassword", encrypted)
        print("❌ ERROR: This shouldn't work! Wrong password decrypted?")
    except Exception as e:
        print("✅ GOOD! Wrong password cannot decrypt.")
        print(f"   Error: Wrong password rejected successfully")
    
