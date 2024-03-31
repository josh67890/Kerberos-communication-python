from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
from base64 import b64encode, b64decode
import os
import hashlib


def hash_password(password):
    # Create a new SHA-256 hash object
    sha256 = hashlib.sha256()

    # Update the hash object with the password bytes
    sha256.update(password.encode('utf-8'))

    # Get the hexadecimal representation of the hashed password
    hashed_password = sha256.hexdigest()

    return hashed_password[:32] #size of key - 128 bits



def encrypt(plaintext, key, iv):

    # Pad the plaintext using PKCS7 padding
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()

    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Encrypt the padded data
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    return ciphertext

def decrypt(iv, ciphertext, key):
    # Create an AES cipher object with CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()

    # Unpad the data using PKCS7 unpadding
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()

    # Return the plaintext as bytes
    return plaintext

# iv = os.urandom(16)
# key = os.urandom(32)
# text = os.urandom(15)
# x = encrypt(text, key, iv)
# y = decrypt(iv, x, key)
# print(x,'\n', len(x))
# print(y)