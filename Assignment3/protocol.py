#define 
from os import curdir
import secrets
from tkinter.constants import W


stateZero = 0
stateOne = 1
stateTwo = 2
authenticate = 3

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self):
        self.SECURE_PREPEND = 1
        self.NOT_SECURE_PREPEND = 0
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
        self.currentState = 0


    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        self.nonce = secrets.token_urlsafe(16)
        self.protocolState = 1
        print(self.SECURE_PREPEND.to_bytes(1, "little") + bytes(self.nonce, 'utf-16') + self.identifier.to_bytes(15, "big"))
        return self.SECURE_PREPEND.to_bytes(1, "little") + bytes(self.nonce, 'utf-16') + self.identifier.to_bytes(15, "big")


    # ==============================================================================
    # Checking if a received message is part of your protocol (called from app.py)
    # Removes the leading identifier character from the message.
    # ==============================================================================
    def IsMessagePartOfProtocol(self, message):
        # print(message)
        # print(message[0])
        # print("IsMessagePartOfProtocol")
        flag = message[0]
        message = message[1:]
        return flag


    # Processing protocol message
    # TODO: IMPLMENET THE LOGIC (CALL SetSessionKey ONCE YOU HAVE THE KEY ESTABLISHED)
    # THROW EXCEPTION IF AUTHENTICATION FAILS

    #=================================================================================
    # Check the current state by referencing global variables that indicate the 
    # current state of this session. 
    #=================================================================================
    def ProcessReceivedProtocolMessage(self, message):
        if self.currentState == 1:
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
                
            return message

        elif(self.currentState == 2):
            pass
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
        elif(self.currentState == 3):
            pass
        else:
            return "HELOOOOO"
    def isAuthenticated():
        return True

    # Setting the key for the current session
    # TODO: MODIFY AS YOU SEEM FIT
    def SetSessionKey(self, key):
        self._key = key
        pass


    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text


    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text
