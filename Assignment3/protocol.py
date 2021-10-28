#define 
from os import curdir
import secrets
from tkinter.constants import W


DEFAULT = 99
AZERO = 0
BZERO = 1
SECURE_PREPEND = 1
NOT_SECURE_PREPEND = 0

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self._key = None
        self.identifier = 999 # TODO make unique identifier should be 15 bytes
        self.protocolState = 0
        self.nonce = None
        self.rSender = None
        self.r = None
        self.g = None
        self.p = None
        self.mydh = None
        self.theirdh = None
        self.commonDH = None
        self.currentState = DEFAULT
        self.authenticate = False


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        # print(self.nonce)
        # print(self.identifier)
        # print(self.nonce + self.identifier)
        self.nonce = secrets.token_urlsafe(16)
        self.currentState = AZERO
        byteMsg = self.stringToBytes(self.nonce) + self.intToBytes(self.identifier)
        return self.prependSecure(byteMsg)


    # ==============================================================================
    # Checking if a received message is part of your protocol (called from app.py)
    # Removes the leading identifier character from the message.
    # ==============================================================================
    def IsMessagePartOfProtocol(self, message):
        flag = message[0]
        message = message[1:]
        return flag

    def prependSecure(self, byteMsg):
        return SECURE_PREPEND.to_bytes(1, "big") + byteMsg

    def prependNotSecure(self, byteMsg):
        return NOT_SECURE_PREPEND.to_bytes(1, "big") + byteMsg

    def stringToBytes(self, str):
        return bytes(str, 'utf-16') 

    def intToBytes(self, num):
        return num.to_bytes(16, "big")

    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS

    #=================================================================================
    # Check the current state by referencing global variables that indicate the 
    # current state of this session. 
    #=================================================================================
    def ProcessReceivedProtocolMessage(self, message):
        if self.currentState == DEFAULT:
            print("Enter Default")
            # TODO process Ra and indentifier
            # TODO create msg to send
            self.currentState = BZERO
            response = self.stringToBytes('fakeresponseDefault')
            # return response
            return self.prependSecure(response)
        if self.currentState == AZERO:
            print("Enter Azero")
            # TODO process variables inside message Ra Rb gpmodp, g, p
            # TODO send response with rb and gpmod kab
            # self.rSender = message[16:]
            # self.r = self.nonce = secrets.token_urlsafe(16)
            # self.g = 11111111
            # self.p = 22222222
            # self.mydh = 33333333
            # self.protocolState = 1
            # message = self.protocolState.to_bytes(1,"big") + \
            #     self.r.to_bytes(8,"big") +\
            #     self.EncryptAndProtectMessage(\
            #         self.rSender.to_bytes(8,"big") +\
            #         self.r.to_bytes(8,"big") +\
            #         self.dh.to_bytes(8,"big"), False) +\
            #     self.g.to_bytes(8,"big") +\
            #     self.p.to_bytes(8,"big")
            self.currentState = DEFAULT
            self.authenticate = True
            self._key = 'DH result'
            response = self.stringToBytes('fakeresponseAzero')
            return self.prependSecure(response)

        elif self.currentState == BZERO:
            print("Enter Bzero")
            # TODO verify Rb 
            # TODO get gamodp and make DH key 
            # TODO set the self.key
            self._key = 'DH result'
            self.authenticate = True
            self.currentState = DEFAULT
            # self.rSender = message[1:18]
            # decryptedMessage = self.DecryptAndVerifyMessage(message[18:57])
            # if(self.r.to_bytes(8,"big") == decryptedMessage[18:34]):
            #     print("Ra, the original nonce is verified")
            # if(self.rSender.to_bytes(8,"big") == decryptedMessage[34:50]):
            #     print("Rb, sent is the same... Authenticated!")

            # self.g = decryptedMessage[57:65]
            # self.p = decryptedMessage[65:73]
            # self.theirdh = 33333333 #decryptedMessage[51:60]
            # self.mydh = 55555555
            # self.commonDH = 88888888
            # return self.EncryptAndProtectMessage(self.rSender.to_bytes(8,"big") + self.mydh.to_bytes(8,"big"), False)
            response = self.stringToBytes('fakeresponseBzero')
            return self.prependSecure(response)
        else:
            print("ELSE HELO")
            return "HELOOOOO"

    def isAuthenticated(self):
        return self.authenticate

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass

    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    # TODO deal with bytes
    # plain_text is a byte string not a normal string
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text
