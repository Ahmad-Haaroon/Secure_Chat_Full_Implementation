
# SecureChat – Assignment #2 (CS-3002 Information Security, Fall 2025)

#By Ahmad Haaroon, 22I-1295, Section H

#Implementation:
	-Certificates are first generated via gen_ca.py and gen_cert.py, for the Certificate Authority (CA), server and client
	-server.py runs server code, client.py runs client code
		.Certificate is validated
		.Then DH keys are exchanged
		.AES keys are derived from this
	-dh.py provides helped functions for Diffie-Hielman code.
	-aes.py provides encryption and decryption for AES encoding
