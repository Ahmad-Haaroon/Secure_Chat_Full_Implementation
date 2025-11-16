"""Client skeleton — plain TCP; no TLS. See assignment spec."""

#File imports
from cryptography.hazmat.primitives import serialization
import socket
import json
import os

from app.crypto.pki import load_certificate, load_certificate_from_pem_string, load_private_key, validate_certificate
from dotenv import load_dotenv
load_dotenv()

def main():
    #Loading client certificate and key
    ca_certificate = load_certificate(os.getenv("CA_CERT"))
    client_certificate = load_certificate(os.getenv("CLIENT_CERT"))
    client_key = load_private_key(os.getenv("CLIENT_KEY"))

    #Establishing initial connection
    socket_connection = socket.socket()
    socket_connection.connect(("localhost", int(os.getenv("CHAT_PORT"))))
    print("Server is connected!\n")

    #Recieving inital message with certificate
    data = socket_connection.recv(4096)
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

if __name__ == "__main__":
    main()
