# shar7 el code: be protect your files be eno be scrambling them fa el hacker may3rfsh ye2raha.
# lw 7ad bs ma3ah el correct password hay3raf unscramble them.
# 3 function: 
# 1. make_key_from_password(password, salt=None): be3mel storng 256-bit encryption key ba3d ma ya3mel lel password scramble 100,000 times
# 2. encrypt_file(password, file_content): Takes your password and file, scrambles the file using AES-256, and returns a garbage-looking encrypted string.
# 3. decrypt_file(password, encrypted_b64):Takes your password and the garbage-looking encrypted string, unscrambles it, and returns your original file.
# el file be import AES 3lshan na3mel encryption w decryption b AES-256
# import pad w unpad deh 2 tools 3lshan el AES be work bs 3ala data be  specific size (16 bytes at a time)
# pad: lw el file beta3y mesh 16 byte el pad bet7ot dummy bytes 3lshan temla el fadel 
# unpad: beshel el dummy bytes after decryption 
# import hashlib: 3lshan na3mel hashing lel passwords fa el input w ye5arag fixed-length random-looking output.
# behash el password 100,000 mara 3lshan yeb2a strong 
# import hashlib: w da be5aly el hacker may3rafsh el password el asly w el hash one way ya3ny maynfa3sh a reverse el hash to get the original password
# import os: deh bet generate random bytes. el random bytes deh ben7tagha lel salt and IV to make each encryption unique.
# import base64: tool bet convert raw bytes into text characters.
# import base64: da useful 3lshan be5aly el text easier to store in databases and files than raw bytes.
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
# betkon one way(mohema): (maynfa3sh a reverse el hash 3lshan ageb el original password) 
import hashlib

# os: Provides random bytes for salt and IV (Initialization Vector)
import os

# base64: Converts bytes to text format for easy storage
import base64


# FUNCTION 1: make_key_from_password (Be3mel funtion make_key_from_password 3lshan ya3mel key lel encryption mein el password)
# This function takes a password and salt optional (lw mafish salt, it will create one)
def make_key_from_password(password, salt=None):

    # Convert password from string to bytes (computers need bytes)
    # be7awel el password le bytes 3lshan el computer mesh befham el strings howa befham el bytes.
    # w da mohem 3lshan lama ya3mel encryption el computer yeshta8al 3ala bytes
    password_bytes = password.encode()

    # lw mafish salt hay generate random 16 bytes
    # Salt makes each key unique even if passwords are the same
    if salt is None:
        salt = os.urandom(16)  # 16 bytes random
    
    # This is the most important line. It creates the actual encryption key.
    # PBKDF2 = special function bet5od el password w te stretches it into a longer key
    # 100,000 iterations (lel normal user hay5od wa2t about 1 second laken lel hacker trying billions of passwords,
    # each guess takes 100,000 times longer)
    key = hashlib.pbkdf2_hmac(
        'sha256',           # Hash algorithm (SHA-256 is very secure)(used by Bitcoin)
        password_bytes,     # The password in bytes
        salt,               # Random salt
        100000,             # 100,000 (be3mel hash lel password 100,000 mara)(3lshan tekon sa3ba 3ala el hacker eno ye guess el password)
        dklen=32            # deh ba2a el bet5aly el final key 32 bytes long = 256 bits (AES-256)
    )
    
    # Return both the key (32 bytes) and the salt (salt needed for decryption)
    return key, salt


# FUNCTION 2: encrypt_file
# Encrypt function: Takes password and file content, returns encrypted version
# Be3mel encrypt_file function 3lshan ya5od el password wel file content w yerga3 el encrypted version
def encrypt_file(password, file_content):

    # STEP 1: Generate random salt (16 bytes)
    # salt: be generate leik 16 bytes w haykono different fi kol mara bet3mel fieha encryption le file
    # ya3ny 7ata lw 3amlt encryption le nafs el file aktar mein mara be nafs el password fi kol mara encrypted output will look completely different 
    # w da hay5aly el attacker mesh 3aref el patterns 
    salt = os.urandom(16)

    # STEP 2: Generate random IV (16 bytes)
    # 16 bytes beshta8alo ma3 el salt 3lshan ye5alo kol encryption unique
    # ex: like starting at a random position in a book before you start reading.
    iv = os.urandom(16)

    # STEP 3: Make the AES-256 key from password and salt
    # be ya5od el password w el salt el ehna 3amlna fo2 w ye7othom fel function w ya3mel el key
    # el _ el kel key,_ deh bet5alena ne ignore el return value beta3 el salt 3lshan we already have it.
    key, _ = make_key_from_password(password, salt)

    # STEP 4: creates the actual AES cipher object that will do the encryption. It needs three things:
    # 1. key: el 32 bytes AES-256 key
    # 2. AES.MODE_CBC: be2ol en ehna han use CBC mode (Cipher Block Chaining).
    # CBC(Cipher Block Chaining) = kol block of data be depends 3ala el block el ablo w da be5aleh more secure
    # 3. iv: the random Initialization Vector
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # STEP 5: Pad the data to be multiple of 16 bytes (AES block size)
    # el AES BE work be 16 bytes fa lw masalan el file beta3ak 11 bytes el pad hayzawed 3adad el bytes le 7ad ma yekon 16
    # The pad function adds special bytes that tell us later how much padding was added.
    padded_data = pad(file_content, AES.block_size)
    
    # STEP 6: Encrypt the padded data
    # be5od el padded_data w ya3melha scrambles it bel key and IV
    # ciphertext: message malhash ma3ana, ma7desh hay3rf ye2raha mein 8eir el key
    ciphertext = cipher.encrypt(padded_data)
    
    # STEP 7: Combine salt + IV + ciphertext
    # We need to save all three together because we need all of them to decrypt later.
    combined = salt + iv + ciphertext
    
    # Using base64 to make it from bytes to characters
    # Be converts the combined bytes le Base64 string (turns raw bytes into text characters that are safe to store in databases and text files)
    # The .decode('utf-8') turns the bytes into a regular string. 
    encrypted_b64 = base64.b64encode(combined).decode('utf-8')
    
    # Return the encrypted version as text (w da el hayt3melo save fel DB aw el file)
    return encrypted_b64


# FUNCTION 3: decrypt_file
# decrypt_file function: 3lshan ya5od el password wel encrypted Base64 string w yerga3 el original content
def decrypt_file(password, encrypted_b64):
    
    # STEP 1: reverses the Base64 encoding mein string le raw bytes. w da 3aks el 3amlna fi 2a5er el encryption
    encrypted_data = base64.b64decode(encrypted_b64)
    
    # STEP 2: Extract salt (first 16 bytes)
    # lama 3amlna el encryption 7atena fel awel el salt ba3d keda el IV ba3d keda el ciphertext
    salt = encrypted_data[:16]
    
    # STEP 3: Extract IV (from the next 16 bytes (bytes 16 to 31))
    iv = encrypted_data[16:32]
    
    # STEP 4: Extract ciphertext (everything after 32 bytes)  (da el actual encrypted data)
    ciphertext = encrypted_data[32:]
    
    # STEP 5: Recreate the same key using password and extracted salt
    # ba recreates the same key bel password w extracted salt, 3lshan we use the same salt, we get the exact same key that was used for encryption. 
    # This is why we need to save the salt with the encrypted data.
    key, _ = make_key_from_password(password, salt)
    
    # STEP 6: Create AES cipher for decryption
    # ba use the same key w same IV el used for encryption (da keda el 3aks el encryption cipher)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    
    # STEP 7: Decrypt the ciphertext
    # ba5od el ciphertext w unscrambles it el result el padded data (with the extra bytes we added)
    decrypted_padded = cipher.decrypt(ciphertext)
    
    # STEP 8: Remove padding to get original data
    # bashel el pad el at7at be eno yebos 3ala 2a5er last byte to know how many padding bytes were added, ba3dein removes them.
    # The result is the original file content.
    original_data = unpad(decrypted_padded, AES.block_size)
    
    # Return the original file content (al el user hayshofo lama ye view el file)
    return original_data


# TEST (run this file alone to test)
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
    # el b deh bet2ol en da bytes mesh regular string.
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
    
    # Check if it worked (bet2aked en el decrypted message matches the original)
    if secret == decrypted:
        print("✅ SUCCESS! Encryption and decryption work perfectly!")
    else:
        print("❌ FAILED! Something went wrong!")
    print()
    
    # TEST WRONG PASSWORD - This is important for security!
    # If someone tries wrong password, it MUST fail
    print("Testing security: Wrong password attempt")
    print("-"*40)
    
    # tests security: It tries to decrypt the file with the wrong password. It should FAIL. 
    # The try-except catches the failure and prints that the wrong password was correctly rejected.
    # This is a good thing it means your files are safe from hackers who don't have the password.
    try:
        # Try to decrypt with WRONG password
        wrong_decrypt = decrypt_file("wrongpassword", encrypted)
        print("❌ ERROR: This shouldn't work! Wrong password decrypted?")
    except Exception as e:
        print("✅ GOOD! Wrong password cannot decrypt.")
        print(f"   Error: Wrong password rejected successfully")
    
