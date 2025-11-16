"""Server skeleton — plain TCP; no TLS. See assignment spec."""

#File imports
from cryptography.hazmat.primitives import serialization
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
    #Loading server certificate and key
    ca_certificate = load_certificate(os.getenv("CA_CERT"))
    server_certificate = load_certificate(os.getenv("SERVER_CERT"))
    server_key = load_private_key(os.getenv("SERVER_KEY"))

    #Establishing initial connection
    socket_connection = socket.socket()
    socket_connection.bind(("0.0.0.0", int(os.getenv("CHAT_PORT"))))
    socket_connection.listen(1)
    print("Server is listening...")

    connect, addr = socket_connection.accept()
    print(f"Client is connected! (from {addr})\n")

    #Sending initial message with certificate
    message = {"type": "hello",
               "cert": server_certificate.public_bytes(encoding=serialization.Encoding.PEM).decode(),
               "nonce": os.urandom(16).hex()}
    connect.send(json.dumps(message).encode())

    #Recieving client response with certificate
    data = connect.recv(RECIEVE_SIZE)
    client_message = json.loads(data.decode())
    client_certificate = load_certificate_from_pem_string(client_message["cert"])

    #Validating certificate
    try:
        validate_certificate(client_certificate,ca_certificate,"client.local")
        print("Client validated.")
    except Exception as e:
        print("Error: ", str(e))
        connect.send(b"Bad_certificate")
        connect.close()
        return

    print("Certificate exchange completed.")

    #Stage 2:DH Keys
    #Generating DH keypairs
    print("\nStarting DH key exchange...")
    server_private_key, server_public_key = dh_help.generate_key_pairs()

    #Sending server public key
    message = {"type": "dh_public",
               "pub": dh_help.serialize_public_key(server_public_key)}
    connect.send(json.dumps(message).encode())

    #Recieving client public key
    data = connect.recv(RECIEVE_SIZE)
    client_message = json.loads(data.decode())
    client_public_key = dh_help.deserialize_public_key(client_message["pub"])

    #Derive AES key
    session_key = dh_help.derive_aes_key(server_private_key,client_public_key)

    print("Keys have been exchanged!")
    print("\nExchange complete, key = ",session_key.hex())

if __name__ == "__main__":
    main()
