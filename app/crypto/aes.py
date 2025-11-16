"""AES-128(ECB)+PKCS#7 helpers (use library).""" 
#File imports
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes

#AES encryption
def aes_encryption(key: bytes, plaintext: bytes):
    #Initialize PKCS#7 padding
    padder = padding.PKCS7(128).padder()

    #Initialize cipher and encryptor
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    encryptor = cipher.encryptor()

    return encryptor.update(padder.update(plaintext)+ padder.finalize()) + encryptor.finalize()

#DES encryption
def aes_decryption(key: bytes, ciphertext: bytes):
    #Initialize cipher and decryptor
    cipher = Cipher(algorithms.AES(key), modes.ECB())
    decryptor = cipher.decryptor()

    #Initialize PKCS#7 unpadding
    unpadder = padding.PKCS7(128).unpadder()

    return unpadder.update(decryptor.update(ciphertext) + decryptor.finalize()) + unpadder.finalize()

