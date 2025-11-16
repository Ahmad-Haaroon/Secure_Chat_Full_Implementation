"""X.509 validation: signed-by-CA, validity window, CN/SAN.""" 

#File imports
from datetime import datetime, timezone;
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.exceptions import InvalidSignature
import os

#Loading certificate
def load_certificate(path: str):
    with open(path,"rb") as file:
        return x509.load_pem_x509_certificate(file.read())
    
def load_certificate_from_pem_string(pem_string: str):
    return x509.load_pem_x509_certificate(pem_string.encode())
    
#Loading key
def load_private_key(path: str):
    with open(path,"rb") as file:
        return serialization.load_pem_private_key(file.read(), None)

#Getting common name(/cn)
def get_common_name(certificate: x509.Certificate):
    try:
        cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
    except:
        cn = None
    return cn

#Validating certificate
def validate_certificate(certificate: x509.Certificate, ca_certificate: x509.Certificate, expected_cn_value: str):
    #Verifying signature
    try:
        ca_public_key = ca_certificate.public_key()
        ca_public_key.verify(certificate.signature,
                             certificate.tbs_certificate_bytes,
                             padding.PKCS1v15(),
                             certificate.signature_hash_algorithm,)
        
    except InvalidSignature:
        raise ValueError("Bad_certificate: Invalid Signature")
    
    #Check validity dates
    now = datetime.now(timezone.utc)
    if (certificate.not_valid_before_utc > now):
        raise ValueError("Bad_certificate: Certificate not yet valid")
    if (certificate.not_valid_after_utc < now):
        raise ValueError("Bad_certificate: Expired certificate")
    
    #Check CN match
    cn_check = get_common_name(certificate)
    if (expected_cn_value != cn_check):
        raise ValueError(f"Bad_certificate: CN mismatch - Expected {expected_cn_value}, got {cn_check}")
    
    return True