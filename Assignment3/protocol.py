import hashlib
import secrets
from aes import AESCipher

#define 
stateZero = 0
stateOne = 1
stateTwo = 2
stateThree = 3

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT

    def __init__(self, sharedSecret):
        self._key = None
        self.identifier = None
        self.protocolState = 0
        self.nonce = None
        self.rSender = None
        self.r = None
        self.g = None
        self.p = None
        self.sharedSecret = sharedSecret
        self.aesCipherSharedKey = AESCipher(sharedSecret) # Shared secret is hashed inside AESCipher constructor
        self.aesCipherSessionKey = None
        self.mydh = None
        self.theirdh = None
        self.commonDH = None


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        self.nonce = secrets.token_urlsafe(16)
        print(self.nonce)
        print(self.identifier)
        print(self.nonce + self.identifier)
        self.protocolState = 1
        return stateZero.to_bytes(1, "big") + self.nonce + self.identifier


    # Checking if a received message is part of your protocol (called from app.py)
    # TODO: IMPLMENET THE LOGIC
    def IsMessagePartOfProtocol(self, message):
        print(message)
        print(message[0])
        print("IsMessagePartOfProtocol")
        if(message[0] == 0 or message[0] == 1 or message[0] == 2):
            print("yes")
            return True
        message = message[1:]
        return False


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS
    def ProcessReceivedProtocolMessage(self, message):
        if(message[0] == 0):
            self.rSender = message[16:]
            self.r = secrets.token_urlsafe(16)
            self.g = 11111111
            self.p = 22222222
            self.mydh = 33333333
            self.protocolState = 1
            response = self.protocolState.to_bytes(1,"big") + \
                self.r.to_bytes(8,"big") +\
                self.EncryptAndProtectMessage(\
                    self.rSender.to_bytes(8,"big") +\
                    self.r.to_bytes(8,"big") +\
                    self.dh.to_bytes(8,"big"), False) +\
                self.g.to_bytes(8,"big") +\
                self.p.to_bytes(8,"big")
                
            return response

        elif(message[0] == 1):
            self.rSender = message[1:18]
            decryptedMessage = self.DecryptAndVerifyMessage(message[18:57])
            if(self.r.to_bytes(8,"big") == decryptedMessage[18:34]):
                print("Ra, the original nonce is verified")
            if(self.rSender.to_bytes(8,"big") == decryptedMessage[34:50]):
                print("Rb, sent is the same... Authenticated!")

            self.g = decryptedMessage[57:65]
            self.p = decryptedMessage[65:73]
            self.theirdh = 33333333 #decryptedMessage[51:60]
            self.mydh = 55555555
            self.commonDH = 88888888
            self.aesCipherSessionKey = AESCipher(self.commonDH)
            return self.EncryptAndProtectMessage(self.rSender.to_bytes(8,"big") + self.mydh.to_bytes(8,"big"), False)
        else:
            # process the message and send a greeting message
            return "HELOOOOO"


    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text, appCall=True):
        if(appCall):
            # print(type(stateThree.to_bytes(1, "big")))
            # print(type(plain_text.encode()))
            # print(stateThree.to_bytes(1, "big") + plain_text.encode())
            cipher_text = stateThree.to_bytes(1, "big") + plain_text.encode()
            cipher_text = cipher_text.decode()
        else:
            cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text, authenticated, sharedKey=False):
        if(authenticated):
            if(sharedKey):
                plain_text = self.aesCipherSharedKey.decrypt(cipher_text)    
            else:
                plain_text = self.aesCipherSessionKey.decrypt(cipher_text)
        else:
            plain_text = cipher_text
        return plain_text

    # For Changing the mode of the protocol
    def SetMode(self, identifier):
        self.identifier = identifier

    # Increments the state of the authentication protocol
    def IncrementState(self):
        # if(self.protocolState == 0):
        #     self.protocolState = 1
        # elif(self.protocolState == 1):
        #     self.protocolState = 2
        # elif(self.protocolState == 2):
        self.protocolState += 1

    def ResetState(self):
        self.protocolState = 0