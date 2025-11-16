"""Client skeleton — plain TCP; no TLS. See assignment spec."""

#File imports
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import dh
import socket
import json
import os

from app.crypto.pki import load_certificate, load_certificate_from_pem_string, load_private_key, validate_certificate
import app.crypto.dh as dh_help

from dotenv import load_dotenv
load_dotenv()

#Defaults
RECIEVE_SIZE=4096

def main():
    #Stage 1: Certificates
    #Loading client certificate and key
    ca_certificate = load_certificate(os.getenv("CA_CERT"))
    client_certificate = load_certificate(os.getenv("CLIENT_CERT"))
    client_key = load_private_key(os.getenv("CLIENT_KEY"))

    #Establishing initial connection
    socket_connection = socket.socket()
    socket_connection.connect(("localhost", int(os.getenv("CHAT_PORT"))))
    print("Server is connected!\n")

    #Recieving inital message with certificate
    data = socket_connection.recv(RECIEVE_SIZE)
    server_message = json.loads(data.decode())
    server_certificate = load_certificate_from_pem_string(server_message["cert"])

    #Validating certificate
    try:
        validate_certificate(server_certificate,ca_certificate,"server.local")
        print("Server validated.")
    except Exception as e:
        print("Error: ", str(e))
        socket_connection.send(b"Bad_certificate")
        socket_connection.close()
        return
    
    #Sending client certificate
    message = {"type": "hello_reply",
               "cert": client_certificate.public_bytes(encoding=serialization.Encoding.PEM).decode(),
               "nonce": os.urandom(16).hex()}
    socket_connection.send(json.dumps(message).encode())

    print("Certificate exchange completed.")

    #Stage 2:DH Keys
    #Recieving server public key
    print("\nStarting DH key exchange...")
    data = socket_connection.recv(RECIEVE_SIZE)
    server_message = json.loads(data.decode())
    server_public_key = dh_help.deserialize_public_key(server_message["pub"])

    #Generating DH keypairs
    parameters = server_public_key.public_numbers().parameter_numbers
    client_private_key, client_public_key = dh_help.generate_key_pairs(parameters=
                                            dh.DHParameterNumbers(parameters.p,parameters.g).parameters())

    #Sending client public key
    message = {"type": "dh_pub",
               "pub": dh_help.serialize_public_key(client_public_key)}
    socket_connection.send(json.dumps(message).encode())

    #Derive AES key
    session_key = dh_help.derive_aes_key(client_private_key,server_public_key)

    print("Keys have been exchanged!")
    print("\nExchange complete, key = ",session_key.hex())

if __name__ == "__main__":
    main()
