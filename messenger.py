import os
import pickle
import string
import cryptography
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import HKDF
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

    Returns: Signature of public Key
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
    Returns: Name, Public Key
    '''
    def generateCertificate(self):
        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        return self.name, self.public_key

    '''
    certificate: name, public key
    signature: result of signCert(certificate)

    Uses "Verify" to check to see if the certificate was signed by the server.
    
    Returns: Nothing
    '''
    def receiveCertificate(self, certificate, signature):
        try:
            self.server_signing_pk.verify(signature, certificate[1], ec.ECDSA(hashes.SHA256()))
        except:
            print("CANNOT VERIFY SIGNATURE")
        self.certs[certificate[0]] = certificate[1]#adds to dictionary the name to the public key. We can update the key later.
        #The root_key is the shared secret
        self.root_key = self.private_key.exchange(certificate[1])
        
    '''
    rk: root key
    dh_out: previous dh_out from the previous operation of kdf using DH_output as "in" and chain key as "key"
    '''
    def KDF_RK(self, rk, dh_out):
        return HKDF(algorithm=hashes.SHA256(), length=64, salt=rk,info=b'Derivation of Root Key').derive(dh_out)


    def sendMessage(self, name, message):
        raise Exception("not implemented!")
        return


    def receiveMessage(self, name, header, ciphertext):
        raise Exception("not implemented!")
        return

    def report(self, name, message):
        raise Exception("not implemented!")
        return
