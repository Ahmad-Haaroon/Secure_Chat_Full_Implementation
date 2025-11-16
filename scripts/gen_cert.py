"""Issue server/client cert signed by Root CA (SAN=DNSName(CN)).""" 

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
    parser.add_argument("--out",required=True,help="Output path prefix (e.g., certs/server)")
    args = parser.parse_args()

    #Checking directory
    os.makedirs(CERTIFICATE_DIRECTORY,exist_ok=True)

    #Loading keys and certificates
    ca_key = None
    ca_certificate = None
    ca_key_path = os.path.join(CERTIFICATE_DIRECTORY, "ca.key.pem")
    ca_certificate_path = os.path.join(CERTIFICATE_DIRECTORY, "ca.cert.pem")

    if (not(os.path.exists(ca_key_path)) or not(os.path.exists(ca_certificate_path))):
        print("Missing CA key or certificate. Run gen_ca.py first.")
        exit(1)

    with open(ca_key_path,"rb") as file:
        ca_key = serialization.load_pem_private_key(file.read(),password=None)

    with open(ca_certificate_path,"rb") as file:
        ca_certificate = x509.load_pem_x509_certificate(file.read())

    #Generate RSA key
    print("Generating RSA private key...")
    key = rsa.generate_private_key(65537,2048)

    key_path = f"{args.out}.key.pem"
    certificate_path = f"{args.out}.cert.pem"

    #Saving key
    with open(key_path, "wb") as file:
        file.write(key.private_bytes(serialization.Encoding.PEM,
                                     serialization.PrivateFormat.TraditionalOpenSSL,
                                     serialization.NoEncryption(),))
        
    print("Saved private key")

    #Creating certificate
    print("Creating certificate signed by CA...")
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, args.cn)])
    certificate = (x509.CertificateBuilder()
                   .subject_name(subject)
                   .issuer_name(ca_certificate.subject)
                   .public_key(key.public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(datetime.now(timezone.utc))
                   .not_valid_after(datetime.now(timezone.utc) + timedelta(days=3650))
                   .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                   .sign(private_key=ca_key, algorithm=hashes.SHA256()))

    #Saving certificate
    with open(certificate_path,"wb") as file:
        file.write(ca_certificate.public_bytes(serialization.Encoding.PEM))
    print("Saved certificate")

    print("\nCertificate generation complete\n")

if __name__ == "__main__":
    main()