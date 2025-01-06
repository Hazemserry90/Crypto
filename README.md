1. Symmetric Encryption with DES

Description

DES (Data Encryption Standard) is a symmetric encryption algorithm where the same key is used for both encryption and decryption.

Functions

encrypt_file_des(input_file, output_file, key)

Purpose: Encrypt a file using DES in CBC mode.

Parameters:

input_file: Path to the plaintext file to be encrypted.

output_file: Path to save the encrypted file.

key: An 8-byte encryption key.

Process:

Initialize the DES cipher in CBC mode.

Pad the plaintext to match the DES block size.

Encrypt the padded plaintext.

Save the IV and ciphertext to the output file.

decrypt_file_des(input_file, output_file, key)

Purpose: Decrypt a file encrypted with DES in CBC mode.

Parameters:

input_file: Path to the encrypted file.

output_file: Path to save the decrypted file.

key: The 8-byte encryption key used for encryption.

Process:

Extract the IV and ciphertext from the input file.

Initialize the DES cipher with the IV.

Decrypt the ciphertext and remove padding.

Save the plaintext to the output file.

2. Key Distribution Center (KDC) using Needham-Schroeder Protocol

Description

The Needham-Schroeder protocol allows secure session key exchange between two parties (e.g., Alice and Bob) with the help of a trusted Key Distribution Center (KDC).

Class: KDC

register_user(user_id, key)

Purpose: Register a user with a unique key.

Parameters:

user_id: Unique identifier for the user.

key: The user's secret key.

generate_session_key(user_a, user_b)

Purpose: Generate a session key for secure communication between two users.

Parameters:

user_a: Identifier for the first user.

user_b: Identifier for the second user.

Output:

Returns an 8-byte session key.

3. Asymmetric Encryption with RSA

Description

RSA is a public-key encryption algorithm used for secure data transmission.

Functions

generate_rsa_keys()

Purpose: Generate a 2048-bit RSA key pair and save them to files.

Output:

Saves private_key.pem and public_key.pem.

rsa_encrypt(input_file, output_file, public_key_file)

Purpose: Encrypt a file using RSA and a public key.

Parameters:

input_file: Path to the plaintext file.

output_file: Path to save the encrypted file.

public_key_file: Path to the RSA public key file.

Process:

Load the public key.

Encrypt the plaintext using RSA with OAEP padding.

Save the ciphertext to the output file.

rsa_decrypt(input_file, output_file, private_key_file)

Purpose: Decrypt a file encrypted with RSA and a private key.

Parameters:

input_file: Path to the encrypted file.

output_file: Path to save the decrypted file.

private_key_file: Path to the RSA private key file.

Process:

Load the private key.

Decrypt the ciphertext using RSA with OAEP padding.

Save the plaintext to the output file.

4. Diffie-Hellman Key Exchange

Description

Diffie-Hellman is a key exchange algorithm used to securely derive a shared secret between two parties.

Function: diffie_hellman()

Purpose: Perform a Diffie-Hellman key exchange and derive a session key.

Process:

Generate private keys for Alice and Bob.

Derive public keys using SHA256.

Compute a shared secret by combining the private key of one party and the public key of the other.

Derive a session key using HKDF with the shared secret.

Output:

A session key derived from the shared secret.

Main Program Workflow

Symmetric Encryption:

Encrypt and decrypt a file using DES.

Key Distribution:

Register users and generate a session key using the KDC.

Asymmetric Encryption:

Generate RSA key pairs.

Encrypt and decrypt a file using RSA.

Diffie-Hellman Key Exchange:

Perform key exchange to derive a session key.

Security Notes

DES Limitations:

DES is outdated and not considered secure due to its small key size (56 bits). Use AES for stronger encryption.

RSA Recommendations:

Use a key size of at least 2048 bits for secure encryption.

Ensure proper key management to avoid compromise.

Diffie-Hellman:

Use sufficiently large private keys and secure hash functions for deriving public keys.

Prefer Elliptic Curve Diffie-Hellman (ECDH) for better security and efficiency.

Padding:

Always use proper padding schemes (e.g., PKCS7 for DES, OAEP for RSA) to avoid vulnerabilities.

