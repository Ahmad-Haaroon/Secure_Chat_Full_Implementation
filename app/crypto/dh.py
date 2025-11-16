"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation.""" 

#File imports
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dh
import os

#Generate keypairs for DH
def generate_key_pairs(g: int = 2, k: int = 2048, parameters = None):
    #First generate the parameters
    if(parameters==None):
        parameters = dh.generate_parameters(generator=g, key_size=k)

    #Now derive the keys
    private_key = parameters.generate_private_key()
    public_key = private_key.public_key()
    return private_key, public_key

#Serializing public key to send over network
def serialize_public_key(public_key):
    return public_key.public_bytes(encoding=serialization.Encoding.PEM,
                                   format=serialization.PublicFormat.SubjectPublicKeyInfo,).decode()

#Deserializing public key recieved over network
def deserialize_public_key(pem_string: str):
    return serialization.load_pem_public_key(pem_string.encode())

#Deriving AES key from secret (16 byte)
def derive_aes_key(private_key,peer_public_key):
    #First compute shared secret
    shared_secret = private_key.exchange(peer_public_key)

    #Now derive AES key
    digest=hashes.Hash(hashes.SHA256())
    digest.update(shared_secret)
    full_hash=digest.finalize()
    return full_hash[:16]