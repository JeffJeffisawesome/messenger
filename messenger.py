import os
import pickle
import string
import cryptography
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography import HKDF
from cryptography import hmac
from cryptography import aesgcm
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
        self.certs[certificate[0]] = certificate[1]#adds to dictionary the name, pointing to it's corresponding public key
        #we can generate the shared key when we need it later.
    
    '''
    Creates a new message header containing the DH ratchet public key form the key pair in dh_pair, previous chain length pn, and the message number n
    '''
    def HEADER(dh_pair, pn, n):
        dh = dh_pair.public_key()
        return dh, pn, n

    '''
    NOTE: In the original signal spec, 'state' is synonymous with our self.conns[name]
    The original signal spec did not account for messaging to multiple people, so we also
    need to add the 'name' parameter to the next following functions to account for it.

    Additionally, AD byte sequence is discarded, as written in spec
    '''

    def RatchetEncrypt(self, name, plaintext):
        self.conns[name]['CKs'], mk = self.KDF_CK(self.conns[name]['CKs'])
        header = self.HEADER(self.conns[name]['DHs'], self.conns[name]['PN'], self.conns[name]['Ns'])
        self.conns[name]['Ns'] += 1
        return header, aesgcm.encrypt(mk, plaintext, header)

    '''
    NOTE: Commented out the functions for checking skipped message keys
    Apparently those don't need to be accounted for. Can delete later.
    
    name: we need the name to access. self.conns[name] dict
    header: message header:
    ciphertext: ciphertext

    returns: Original message, using aesgcm.decrypt

    See Section 3.5
    '''
    def RatchetDecrypt(self, name, header, ciphertext):
        '''plaintext = self.TrySkippedMessageKeys(header, name, header, ciphertext)
        if plaintext != None:
            return plaintext
        if header.dh != self.conns[name]['DHr']:
            SkipMessageKeys'''
        self.conns[name]['CKr'], mk = self.KDF_CK(self.conns[name]['CKr'])
        self.conns[name]['Nr'] += 1
        return aesgcm.decrypt(mk, ciphertext, header)
    def DHRatchet(self, name, header):
        self.conns[name]['PN'] = self.conns[name]['Ns']
        self.conns[name]['Ns'] = 0
        self.conns[name]['Nr'] = 0
        self.conns[name]['DHr'] = header.dh
        self.conns[name]['RK'], self.conns[name]['CKr'] = self.KDF_RK(self.conns[name]['RK'], self.conns[name]['DHs'].exchange(self.conns[name]['DHr']))
        self.conns[name]['DHs'] = X25519PrivateKey.generate()
        self.conns[name]['RK'], self.conns[name]['CKs'] = self.KDF_RK(self.conns[name]['RK'], self.conns[name]['DHs'].exchange(self.conns[name]['DHr']))
    '''
    def TrySkippedMessageKeys(self, name, header, ciphertext):
        if (header.dh, header.n) in self.conns[name]['MKSKIPPED']:
            mk = self.conns[name]['MKSKIPPED'][header.dh, header.n]
            del self.conns[name]['MKSKIPPED'][header.dh, header.n]
            return aesgcm.decrypt(mk, ciphertext, header)
        else:
            return None
    
    def SkipMessageKeys(self, name, until):
            if self.conns[name]['Nr'] + 
    '''
    '''
    Returns: 64 bytes, 32 byte message key, 32 byte chain key
    '''
    def KDF_CK(ck):
        h = hmac.HMAC(ck, hashes.SHA256)
        h.update(0x01)
        mk = h.finalize()
        h.update(0x02)
        ck = h.finalize()
        return mk, ck
    
    '''
    rk: root key
    dh_out: previous dh_out from the previous operation of kdf using DH_output as "in" and chain key as "key"
    Output: 64 bytes, which will be split into 32, 32, one used for the new rk, and for the chain key
    '''
    def KDF_RK(rk, dh_out):
        return HKDF(algorithm=hashes.SHA256(), length=64, salt=rk,info=b'KDF_RK_HE').derive(dh_out)

    '''
    name: receiver's name (who we want to send to)
    message: message

    returns: header, ciphertext
    '''
    def sendMessage(self, name, message):
        #Initialize, if we haven't sent a message yet
        #Section 3.3 of Signal Doc
        if self.conns[name] == None:
            #Name -> Another dictionary containing values {DHs, DHr, RK, CKs, CKr, Ns, Nr, PN, MKSKIPPED}
            #To access/edit values, self.conns[name]['DHs'], for example
            DHs = X25519PrivateKey.generate()
            DHr = self.certs[name] #Receiver's public key
            shared_key = self.private_key.exchange(DHr)
            RK, CKs = self.KDF_RK(shared_key, DHs.exchange(DHr))
            self.conns[name] = {'DHs': DHs, 'DHr': DHr, 'RK': RK, 'CKs': CKs, 'CKr': None, 'Ns': 0, 'Nr': 0, 'PN': 0, 'MKSKIPPED': {}}
        
        #TODO
        raise Exception("not implemented!")
        return

    '''
    name: name of the sender
    header (Section 2.6): contains the message's number in the sending chain (N = 0, 1, 2, ...) and length in the previous sending chain
    ciphertext: ciphertext
    
    returns: the original message
    '''
    def receiveMessage(self, name, header, ciphertext):
        #Initialized according to section 3.3 of Signal Spec
        if self.conns[name] == None:
            #To access/edit values, do self.conns[name]['DHs'], for example
            DHs = self.private_key
            RK = self.private_key.exchange(self.certs[name]) #shared_key
            self.conns[name] = {'DHs': DHs, 'DHr': None, 'RK': RK, 'CKs': None, 'CKr': None, 'Ns': 0, 'Nr': 0, 'PN': 0, 'MKSKIPPED': {}}
        

        #TODO
        raise Exception("not implemented!")
        return

    def report(self, name, message):
        raise Exception("not implemented!")
        return
