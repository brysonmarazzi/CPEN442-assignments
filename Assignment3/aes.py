import base64
import hashlib
from Crypto import Random
from Crypto.Cipher import AES

class AESCipher(object):

    def __init__(self, key): 
        self.bs = AES.block_size
        if(isinstance(key, bytes)):
            self.key = hashlib.sha256(key).digest()
        else:
            self.key = hashlib.sha256(str(key).encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = Random.new().read(AES.block_size)
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return base64.b64encode(iv + cipher.encrypt(raw))

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES.block_size]
        cipher = AES.new(self.key, AES.MODE_CBC, iv)
        return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')


    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs).encode()

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s)-1:])]


bytestring = "YAMAN".encode()
cipher = AESCipher("helo")
cipher2 = AESCipher("wassup".encode())

cipher_text = cipher.encrypt(bytestring)
cipher_text2 = cipher2.encrypt(bytestring)
print(cipher.decrypt(cipher_text))
print(cipher2.decrypt(cipher_text2))