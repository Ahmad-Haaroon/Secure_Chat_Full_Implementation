"""Create Root CA (RSA + self-signed X.509) using cryptography.""" 

#File imports
import argparse;
from datetime import datetime, timezone, timedelta;
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
import os

CERTIFICATE_DIRECTORY = "certificates"

def main():
    #Parsing
    parser = argparse.ArgumentParser()
    parser.add_argument("--cn",required=True,help="Common Name (CN) for Root CA")
    args = parser.parse_args()

    #Checking directory
    os.makedirs(CERTIFICATE_DIRECTORY,exist_ok=True)

    #Generating CA private key
    print("Generating CA private key...")
    ca_private_key = rsa.generate_private_key(65537,2048)
    ca_private_key_path = os.path.join(CERTIFICATE_DIRECTORY,"ca.key.pem")

    with open(ca_private_key_path,"wb") as file:
        file.write(ca_private_key.private_bytes(serialization.Encoding.PEM,
                                             serialization.PrivateFormat.TraditionalOpenSSL,
                                             serialization.NoEncryption(),))
        
    print("Saved private key")

    #Creating certificate
    print("Creating self-signed CA certificate...")
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.cn)])
    ca_certificate = (x509.CertificateBuilder()
                   .subject_name(subject)
                   .issuer_name(issuer)
                   .public_key(ca_private_key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.now(timezone.utc))
                   .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
                   .sign(private_key=ca_private_key, algorithm=hashes.SHA256()))
    ca_certificate_path = os.path.join(CERTIFICATE_DIRECTORY,"ca.cert.pem")

    with open(ca_certificate_path,"wb") as file:
        file.write(ca_certificate.public_bytes(serialization.Encoding.PEM))
    print("Saved certificate")

    print("\nRoot CA generation complete\n")

if __name__ == "__main__":
    main()
