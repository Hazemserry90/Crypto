# Import necessary cryptographic libraries
from Crypto.Cipher import DES, PKCS1_OAEP  # For DES and RSA encryption
from Crypto.PublicKey import RSA  # For RSA key generation
from Crypto.Random import get_random_bytes  # For generating random keys
from Crypto.Util.Padding import pad, unpad  # For padding data to match block size
from Crypto.Protocol.KDF import HKDF  # For key derivation (Diffie-Hellman)
from Crypto.Hash import SHA256  # For hashing (Diffie-Hellman)

# ==============================================
# Part 1: Symmetric Encryption with DES
# ==============================================

def encrypt_file_des(input_file, output_file, key):
    cipher = DES.new(key, DES.MODE_CBC)  # Initialize DES cipher in CBC mode
    iv = cipher.iv  # Get the initialization vector (random data for CBC)

    with open(input_file, 'rb') as f:
        plaintext = f.read()  # Read the plaintext from the input file

    padded_plaintext = pad(plaintext, DES.block_size)  # Pad plaintext to match DES block size
    ciphertext = cipher.encrypt(padded_plaintext)  # Encrypt the padded plaintext

    with open(output_file, 'wb') as f:
        f.write(iv + ciphertext)  # Save the IV and ciphertext in the output file

    print(f"File encrypted using DES and saved to {output_file}")
    return key  # Return the key for future decryption

def decrypt_file_des(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        iv = f.read(8)  # Extract the IV (first 8 bytes of the file)
        ciphertext = f.read()  # Extract the ciphertext

    cipher = DES.new(key, DES.MODE_CBC, iv)  # Initialize the DES cipher with IV
    padded_plaintext = cipher.decrypt(ciphertext)  # Decrypt the ciphertext
    plaintext = unpad(padded_plaintext, DES.block_size)  # Remove padding to get original plaintext

    with open(output_file, 'wb') as f:
        f.write(plaintext)  # Write plaintext to the output file

    print(f"File decrypted using DES and saved to {output_file}")


# ==============================================
# Bonus: Key Distribution Center (KDC) using Needham-Schroeder Protocol
# ==============================================

class KDC:
    def __init__(self):
        self.keys = {}  # Store user IDs and their associated keys

    def register_user(self, user_id, key):
        self.keys[user_id] = key  # Associate a unique key with each user

    def generate_session_key(self, user_a, user_b):
        session_key = get_random_bytes(8)  # Generate an 8-byte session key
        return session_key  # Return the session key for secure communication

# ==============================================
# Part 2: Asymmetric Encryption with RSA
# ==============================================

def generate_rsa_keys():
    key = RSA.generate(2048)  # Generate a 2048-bit RSA key pair

    with open('private_key.pem', 'wb') as f:
        f.write(key.export_key())  # Save the private key to a file

    with open('public_key.pem', 'wb') as f:
        f.write(key.publickey().export_key())  # Save the public key to a file

    print("RSA key pair generated and saved to private_key.pem and public_key.pem.")


def rsa_encrypt(input_file, output_file, public_key_file):
    with open(public_key_file, 'rb') as f:
        public_key = RSA.import_key(f.read())  # Load the public key

    cipher = PKCS1_OAEP.new(public_key)  # Initialize RSA cipher with OAEP padding
#Crypto.Cipher.PKCS1_OAEP module It is used to create a cipher object that enables encryption and decryption using the RSA algorithm with Optimal Asymmetric Encryption Padding (OAEP).
    with open(input_file, 'rb') as f:
        plaintext = f.read()  # Read the plaintext

    ciphertext = cipher.encrypt(plaintext)  # Encrypt the plaintext

    with open(output_file, 'wb') as f:
        f.write(ciphertext)  # Save ciphertext to the output file

    print(f"File encrypted using RSA and saved to {output_file}")


def rsa_decrypt(input_file, output_file, private_key_file):
    with open(private_key_file, 'rb') as f:
        private_key = RSA.import_key(f.read())  # Load the private key

    cipher = PKCS1_OAEP.new(private_key)  # Initialize RSA cipher with private key

    with open(input_file, 'rb') as f:
        ciphertext = f.read()  # Read the ciphertext

    plaintext = cipher.decrypt(ciphertext)  # Decrypt the ciphertext

    with open(output_file, 'wb') as f:
        f.write(plaintext)  # Save plaintext to the output file

    print(f"File decrypted using RSA and saved to {output_file}")


# ==============================================
# Bonus: Diffie-Hellman Key Exchange
# ==============================================

def diffie_hellman():
    alice_private_key = get_random_bytes(32)  # Generate Alice's private key (32 bytes)
    bob_private_key = get_random_bytes(32)  # Generate Bob's private key (32 bytes)

    alice_public_key = SHA256.new(alice_private_key).digest()  # Derive Alice's public key
    bob_public_key = SHA256.new(bob_private_key).digest()  # Derive Bob's public key

    alice_shared_secret = SHA256.new(alice_private_key + bob_public_key).digest()  # Compute shared secret
    bob_shared_secret = SHA256.new(bob_private_key + alice_public_key).digest()  # Bob computes the same shared secret

    session_key = HKDF(alice_shared_secret, 32, b'', SHA256)  # Derive a session key using HKDF
    # b'' to raw binary
    print("Session key generated using Diffie-Hellman key exchange.")
    return session_key


# ==============================================
# Main Program
# ==============================================

if __name__ == "__main__":
    # Symmetric Encryption (DES)
    des_key = get_random_bytes(8)
    encrypt_file_des('large_file.txt', 'encrypted_file.des', des_key)
    decrypt_file_des('encrypted_file.des', 'decrypted_file.txt', des_key)

    # KDC (Needham-Schroeder Protocol)
    kdc = KDC()
    alice_key = get_random_bytes(8)
    bob_key = get_random_bytes(8)
    kdc.register_user('Alice', alice_key)
    kdc.register_user('Bob', bob_key)
    session_key = kdc.generate_session_key('Alice', 'Bob')

    # Asymmetric Encryption (RSA)
    generate_rsa_keys()
    rsa_encrypt('data.txt', 'encrypted_data.rsa', 'public_key.pem')
    rsa_decrypt('encrypted_data.rsa', 'decrypted_data.txt', 'private_key.pem')

    # Diffie-Hellman Key Exchange
    session_key = diffie_hellman()
