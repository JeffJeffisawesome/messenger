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
    Hash and Sign the Client's public key using the server_signing_key using ECDSA, and return it, along with the name in front.
    '''
    def signCert(self, cert):
        return cert[0], self.server_signing_key.sign(cert[1], ec.ECDSA(hashes.SHA256))

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
    certificate = name, signed public key of certificate owner.
    Uses "Verify" to check to see if the certificate was signed by the server. If there are no exceptions, add the name to self.conns, and add the public key to certs.
    '''
    def receiveCertificate(self, certificate, signature):
        try:
            self.server_signing_pk.verify(signature, certificate[1], ec.ECDSA(hashes.SHA256()))
        except:
            print("CANNOT VERIFY SIGNATURE")
        self.conns.add(certificate[0])
        self.certs.add(certificate[1])

    def sendMessage(self, name, message):
        raise Exception("not implemented!")
        return

    '''
    name = self.name
    header = sender's current ratchet public key
    ciphertext: ciphertext of the sender's message
    '''
    def receiveMessage(self, name, header, ciphertext):
        raise Exception("not implemented!")
        return

    def report(self, name, message):
        raise Exception("not implemented!")
        return
