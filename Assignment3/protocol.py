from aes import AESCipher
import secrets
import pyDH

# STATES
DEFAULT = 0
AZERO = 1
BZERO = 2

# PREPEND DEFINiTIONS
SECURE_PREPEND = 1
NOT_SECURE_PREPEND = 0

# VAR LENGTHS
R_LENGTH = 16

class Protocol:
    # Initializer (Called from app.py)
    def __init__(self, sharedKey):
        self._key = None
        self.SetSessionKey(sharedKey) # The _key starts off with value of sharedKey, but we store the value of the session key later on.
        self.identifier = self.intToBytes(999) # TODO make unique identifier should be 15 bytes.
        self.rIdentifier = None # Unique integer that identifies the other computer.
        self.nonce = None # Random 16 byte value, should be unique each session.
        self.rSender = None # The 'nonce' value generated by the other computer.
        self.dh = pyDH.DiffieHellman() # The pyDH instance 
        self.myDH = None # The DH value for this computer - i.e g*modp.
        self.theirDH = None # The DH value for the other computer - i.e g*modp.
        self.currentState = DEFAULT # Variable that keeps track of the current state.
        self.authenticate = False # Boolean to know if the user has authenticated or not.

    # ---------------------------------------------------------
    # Creating the initial message of your protocol
    # (to be send to the other party to bootstrap the protocol)
    # ---------------------------------------------------------
    def GetProtocolInitiationMessage(self):
        print("Enter Init")
        self.nonce = secrets.token_bytes(R_LENGTH)
        self.currentState = AZERO
        byteMsg = self.nonce
        return self.prependSecure(byteMsg)

    # ------------------------------------------------------------------------------
    # Checking if a received message is part of your protocol (called from app.py)
    # ------------------------------------------------------------------------------
    def IsMessagePartOfProtocol(self, message):
        return message[0]

    # ----------------------------------------------
    # Adds the 'secure' flag to the message in bytes
    # ----------------------------------------------
    def prependSecure(self, byteMsg):
        return SECURE_PREPEND.to_bytes(1, "big") + byteMsg

    # --------------------------------------------------
    # Adds the 'not secure' flag to the message in bytes
    # --------------------------------------------------
    def prependNotSecure(self, byteMsg):
        return NOT_SECURE_PREPEND.to_bytes(1, "big") + byteMsg

    # ---------------------------------------------------
    # Converts integers to a byte array of a fixed length
    # The length is always R_LENGTH
    # num is expected to be an integer
    # ---------------------------------------------------
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
            # Process data in message
            self.nonce = secrets.token_bytes(R_LENGTH)
            self.rSender = message[0:R_LENGTH] 

            # Build response
            self.myDH = self.generateDHKey()
            messageToEncrypt = self.rSender + self.nonce + self.myDH
            response = self.nonce + self.EncryptAndProtectMessage(messageToEncrypt)
            self.currentState = BZERO
            return self.prependSecure(response)

        if self.currentState == AZERO:
            print("Enter Azero")
            # Decrypt and process
            self.rSender = message[0:R_LENGTH]
            plainMsg = self.DecryptAndVerifyMessage(message[R_LENGTH:])
            # Verify Ra is correct 
            if plainMsg[0:R_LENGTH] != self.nonce:
                raise Exception("Auth initiator recieved incorrect \"receiver's nonce\" in response!")
            # Verify Rb is correct 
            if plainMsg[R_LENGTH:R_LENGTH*2] != self.rSender:
                raise Exception("Auth initiator recieved incorrect \"sender's nonce\" in response!")
            # find the index of their DH
            self.theirDH = plainMsg[R_LENGTH*2:]

            # Build response
            self.myDH = self.generateDHKey()
            plainResponse = self.rSender + self.myDH
            response = self.EncryptAndProtectMessage(plainResponse)
            self.currentState = DEFAULT
            self.authenticate = True
            print("A has authenticated!!")
            k = self.calculateDHKey()
            self.SetSessionKey(k)
            return self.prependSecure(response)

        elif self.currentState == BZERO:
            print("Enter Bzero")
            # Decrypt and Process
            plainMsg = self.DecryptAndVerifyMessage(message)
            if plainMsg[0:R_LENGTH] != self.nonce:
                raise Exception("Auth non-initiator recieved incorrect \"reciever's nonce\" in response!")
            self.theirDH = plainMsg[R_LENGTH:]
            self.authenticate = True
            self.currentState = DEFAULT
            print("B has authenticated!!")
            k = self.calculateDHKey()
            self.SetSessionKey(k)
            return None # indicates to caller code to not send message
        else:
            raise Exception("Fail - in detached head state - ENTERED UNKNOWN STATE")

    # =========================================
    # Calculates session key using self.theirdh
    # and self.mydh local variables 
    # Return value should be bytes
    # =========================================
    def calculateDHKey(self):
        toInt = int.from_bytes(self.theirDH, byteorder='big') 
        return self.dh.gen_shared_key(toInt)

    def isAuthenticated(self):
        return self.authenticate

    # Setting the key for the current session
    def SetSessionKey(self, key):
        self._key = key
        self.aesCipher = AESCipher(self._key)

    def generateDHKey(self):
        return self.dh.gen_public_key().to_bytes(1000, "big")
        
    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    # TODO deal with bytes
    # plain_text is a byte string
    def EncryptAndProtectMessage(self, plain_text):
        if self._key == None:
            cipher_text = plain_text
        else:
            cipher_text = self.aesCipher.encrypt(plain_text)
        return cipher_text

    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        if self._key == None:
            plain_text = cipher_text
        else:
            plain_text = self.aesCipher.decrypt(cipher_text)
        return plain_text
