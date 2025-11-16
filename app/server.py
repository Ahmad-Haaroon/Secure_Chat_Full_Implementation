"""Server skeleton — plain TCP; no TLS. See assignment spec."""

#File imports
from cryptography.hazmat.primitives import serialization
import socket
import json
import os

from app.crypto.pki import load_certificate, load_certificate_from_pem_string, load_private_key, validate_certificate
from dotenv import load_dotenv
load_dotenv()

def main():
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
    data = connect.recv(4096)
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

if __name__ == "__main__":
    main()
