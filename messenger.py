import os
import pickle
import string
import cryptography
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        raise Exception("not implemented!")
        return

    '''
    cert: name, public key
    Hash and Sign the Client's public key using the server_signing_key using ECDSA, and return it.
    '''
    def signCert(self, cert):
        return self.server_signing_key.sign(cert[1], ec.ECDSA(hashes.SHA256))

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}

    '''
    Generates a Private Key and Public Key using x25519, saves both, and sends over the name of the messenger, along with the public key.
    '''
    def generateCertificate(self):
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        return self.name, self.public_key

    '''
    certificate: name, public key
    signature: result of signCert(certificate)
    Uses "Verify" to check to see if the certificate was signed by the server.
    '''
    def receiveCertificate(self, certificate, signature):
        try:
            self.server_signing_pk.verify(signature, certificate[1], ec.ECDSA(hashes.SHA256()))
        except:
            print("CANNOT VERIFY SIGNATURE")
        self.conns.add(certificate[0])#adds name
        self.certs.add(certificate[1])#adds public key

    def sendMessage(self, name, message):
        raise Exception("not implemented!")
        return

    def receiveMessage(self, name, header, ciphertext):
        raise Exception("not implemented!")
        return

    def report(self, name, message):
        raise Exception("not implemented!")
        return
