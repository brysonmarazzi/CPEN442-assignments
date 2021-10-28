from os import curdir
import secrets
from threading import RLock
from tkinter.constants import W

# STATES
DEFAULT = 99
AZERO = 0
BZERO = 1

# PREPEND DEFINiTIONS
SECURE_PREPEND = 1
NOT_SECURE_PREPEND = 0

# VAR LENGTHS
R_LENGTH = 16

class Protocol:
    # Initializer (Called from app.py)
    # TODO: MODIFY ARGUMENTS AND LOGIC AS YOU SEEM FIT
    def __init__(self, sharedKey):
        self._key = sharedKey
        self.identifier = self.intToBytes(999) # TODO make unique identifier should be 15 bytes
        self.rIdentifier = None 
        self.nonce = None
        self.rSender = None
        self.r = None
        self.g = None
        self.p = None
        self.mydh = None
        self.theirdh = None
        self.currentState = DEFAULT
        self.authenticate = False

    # Creating the initial message of your protocol (to be send to the other party to bootstrap the protocol)
    # TODO: IMPLEMENT THE LOGIC (MODIFY THE INPUT ARGUMENTS AS YOU SEEM FIT)
    def GetProtocolInitiationMessage(self):
        self.nonce = self.stringToBytes(secrets.token_urlsafe(16))
        self.currentState = AZERO
        byteMsg = self.nonce + self.identifier
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
        return bytes(str, 'utf-16')  # TODO str.encode()

    def intToBytes(self, num):
        return num.to_bytes(R_LENGTH, "big")

    #=================================================================================
    # Check the current state by referencing global variables that indicate the 
    # current state of this session. 
    # TODO THROW EXCEPTION IF AUTHENTICATION FAILS
    #=================================================================================
    def ProcessReceivedProtocolMessage(self, message):
        if self.currentState == DEFAULT:
            print("Enter Default")
            self.rIdentifier = message[0:R_LENGTH-1] # TODO should we use this value?
            self.rSender = message[R_LENGTH:R_LENGTH*2-1]

            # Build response
            self.mydh = self.getPublicDH()
            messageToEncrypt = self.rSender + self.nonce + self.mydh
            response = self.nonce + self.encryptProtocolMsg(messageToEncrypt)
            self.currentState = BZERO
            return self.prependSecure(response)
        if self.currentState == AZERO:
            print("Enter Azero")
            # Decrypt and process
            self.rSender = message[0:R_LENGTH - 1]
            plainMsg = self.decryptProtocolMsg(message[R_LENGTH:])
            # Verify Ra is correct 
            if plainMsg[0:R_LENGTH - 1] != self.nonce:
                print("FAILED Ra does not have right value")
                return "Fail"
            # Verify Rb is correct 
            if plainMsg[R_LENGTH:R_LENGTH*2-1] != self.rSender:
                print("FAILED Rb does not have right value")
                return "Fail"
            self.theirdh = plainMsg[R_LENGTH*2:]

            # Build response
            self.mydh = self.getPublicDH()
            plainResponse = self.rSender + self.theirdh
            response = self.encryptProtocolMsg(plainResponse)
            self.currentState = DEFAULT
            self.authenticate = True
            self._key = self.calculateDHKey()
            return self.prependSecure(response)

        elif self.currentState == BZERO:
            print("Enter Bzero")
            # Decrypt and Process
            plainMsg = self.decryptProtocolMsg(message)
            if plainMsg[0:R_LENGTH - 1] != self.nonce:
                print("FAILED Rb does not have right value")
                return "Fail"
            self.theirdh = plainMsg[R_LENGTH:]
            key = self.calculateDHKey()
            self.SetSessionKey(key)
            self.authenticate = True
            self.currentState = DEFAULT
            return '' # indicates to app.py code to not send message
        else:
            print("Fail - in detached head state")

    # =====================================
    # TODO implement fully
    # Obtain the public dh key 
    # Return g*modp
    # Return value should be bytes
    # =====================================
    def getPublicDH(self):
        return self.intToBytes(890890809809089)

    # =========================================
    # TODO implement fully
    # Calculates session key using self.theirdh
    # and self.mydh local variables 
    # Return value should be bytes
    # =========================================
    def calculateDHKey(self):
        # return self.theirdh * self.mydh
        return self.intToBytes(834784237429398)

    def isAuthenticated(self):
        return self.authenticate

    # Setting the key for the current session
    def SetSessionKey(self, key):
        self._key = key

    # =========================================
    # TODO implement fully
    # Calls aes function with the self.key 
    # local variable
    # Parameter: msg - bytes to decrypt
    # Return value should be bytes
    # =========================================
    def decryptProtocolMsg(self, msg):
        # self.aes.decrypt(self.key)
        return msg

    # =========================================
    # TODO implement fully
    # Calls aes function with the self.key 
    # local variable
    # Parameter: msg - bytes to encrypt
    # Return value should be bytes
    # =========================================
    def encryptProtocolMsg(self, msg):
        # return self.aes.encrypt(msg, self.key)
        return msg

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
