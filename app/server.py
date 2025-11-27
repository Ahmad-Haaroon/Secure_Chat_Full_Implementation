"""Server skeleton — plain TCP; no TLS. See assignment spec."""

#File imports
from cryptography.hazmat.primitives import serialization
import socket
import json
import os
import base64
import json

from app.crypto.pki import load_certificate, load_certificate_from_pem_string, load_private_key, validate_certificate
import app.crypto.dh as dh_help
import app.crypto.aes as aes_help
import app.storage.db as db_storage

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

    #Stage 2:Encrypted login and registration
    #Generating Ephemeral(temporary) DH keypairs
    print("\nStarting Login DH key exchange...")
    server_private_key, server_public_key = dh_help.generate_key_pairs()

    #Sending server public key
    message = {"type": "ephemeral_dh_public",
               "pub": dh_help.serialize_public_key(server_public_key)}
    connect.send(json.dumps(message).encode())

    #Recieving client public key
    data = connect.recv(RECIEVE_SIZE)
    client_message = json.loads(data.decode())
    client_public_key = dh_help.deserialize_public_key(client_message["pub"])

    # 2) receive client's ephemeral public
    data = connect.recv(8192)
    msg = json.loads(data.decode())
    if msg.get("type") != "ephemeral_dh_reply":
        connect.send(json.dumps({"status":"error","msg":"expected dh reply"}).encode())
        connect.close(); return

    client_pub = dh_mod.load_public_key(msg["pub"])
    shared = dh_mod.compute_shared_secret(srv_priv, client_pub)
    k_reg = dh_mod.derive_aes_key(shared)  # 16 bytes

    # 3) receive encrypted registration/login payload
    data = connect.recv(8192)
    outer = json.loads(data.decode())
    if outer.get("type") != "secure_payload":
        connect.send(json.dumps({"status":"error","msg":"expected secure payload"}).encode())
        connect.close(); return

    ct = base64.b64decode(outer["ct"])
    pt = aes_mod.aes_decrypt(k_reg, ct)
    payload = json.loads(pt.decode())

    # 4) dispatch register / login
    if payload.get("type") == "register":
        email = payload["email"]
        username = payload["username"]
        password = payload["password"]
        salt = os.urandom(16)
        h = __import__("hashlib").sha256()
        h.update(salt + password.encode())
        pwd_hash_hex = h.hexdigest()
        ok = storage.create_user(email, username, salt, pwd_hash_hex)
        if ok:
            connect.send(json.dumps({"status":"ok","msg":"registered"}).encode())
        else:
            connect.send(json.dumps({"status":"error","msg":"username/email exists"}).encode())
    elif payload.get("type") == "login":
        username = payload.get("username")
        user = storage.get_user_by_username(username)
        if not user:
            connect.send(json.dumps({"status":"error","msg":"bad credentials"}).encode())
        else:
            salt = user["salt"]          # raw bytes
            stored_hash = user["pwd_hash"]
            if storage.verify_password(stored_hash, salt, payload["password"]):
                connect.send(json.dumps({"status":"ok","msg":"login ok"}).encode())
                # proceed to session DH (long-lived chat key) here
            else:
                connect.send(json.dumps({"status":"error","msg":"bad credentials"}).encode())
    else:
        connect.send(json.dumps({"status":"error","msg":"unknown op"}).encode())



    #Stage 3:DH Keys
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


#python3 -m app.client
#python3 -m app.server
#python3 scripts/gen_ca.py --cn "SecureChat Root CA" 
#python3 scripts/gen_cert.py --cn server.local --out certificates/server
#python3 scripts/gen_cert.py --cn client.local --out certificates/client