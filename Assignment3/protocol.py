import secrets

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
        self._key = sharedKey # The _key starts off with value of sharedKey, but we store the value of the session key later on.
        self.identifier = self.intToBytes(999) # TODO make unique identifier should be 15 bytes.
        self.rIdentifier = None # Unique integer that identifies the other computer.
        self.nonce = None # Random 16 byte value, should be unique each session.
        self.rSender = None # The 'nonce' value generated by the other computer.
        # self.g = None #TODO We might need these values depending on Kassandra.
        # self.p = None #TODO We might need these values depending on Kassandra.
        self.mydh = None # The DH value for this computer - i.e g*modp.
        self.theirdh = None # The DH value for the other computer - i.e g*modp.
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
        byteMsg = self.identifier + self.nonce
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
            self.rIdentifier = message[0:R_LENGTH] # TODO should we use this value?
            self.rSender = message[R_LENGTH:R_LENGTH*2]

            # Build response
            self.mydh = self.getPublicDH()
            messageToEncrypt = self.rSender + self.nonce + self.mydh
            response = self.nonce + self.encryptProtocolMsg(messageToEncrypt)
            self.currentState = BZERO
            return self.prependSecure(response)

        if self.currentState == AZERO:
            print("Enter Azero")
            # Decrypt and process
            self.rSender = message[0:R_LENGTH]
            plainMsg = self.decryptProtocolMsg(message[R_LENGTH:])
            # Verify Ra is correct 
            if plainMsg[0:R_LENGTH] != self.nonce:
                raise Exception("Auth initiator recieved incorrect \"receiver's nonce\" in response!")
            # Verify Rb is correct 
            if plainMsg[R_LENGTH:R_LENGTH*2] != self.rSender:
                raise Exception("Auth initiator recieved incorrect \"sender's nonce\" in response!")
            self.theirdh = plainMsg[R_LENGTH*2:]

            # Build response
            self.mydh = self.getPublicDH()
            plainResponse = self.rSender + self.theirdh
            response = self.encryptProtocolMsg(plainResponse)
            self.currentState = DEFAULT
            self.authenticate = True
            print("A has authenticated!!")
            self._key = self.calculateDHKey()
            return self.prependSecure(response)

        elif self.currentState == BZERO:
            print("Enter Bzero")
            # Decrypt and Process
            plainMsg = self.decryptProtocolMsg(message)
            if plainMsg[0:R_LENGTH] != self.nonce:
                raise Exception("Auth non-initiator recieved incorrect \"reciever's nonce\" in response!")
            self.theirdh = plainMsg[R_LENGTH:]
            key = self.calculateDHKey()
            self.SetSessionKey(key)
            self.authenticate = True
            self.currentState = DEFAULT
            print("B has authenticated!!")
            return None # indicates to caller code to not send message
        else:
            raise Exception("Fail - in detached head state - ENTERED UNKNOWN STATE")

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
        # return aes.decrypt(self.key, msg)
        return msg

    # =========================================
    # TODO implement fully
    # Calls aes function with the self.key 
    # local variable
    # Parameter: msg - bytes to encrypt
    # Return value should be bytes
    # =========================================
    def encryptProtocolMsg(self, msg):
        # return aes.encrypt(msg, self.key)
        return msg

    # Encrypting messages
    # TODO: IMPLEMENT ENCRYPTION WITH THE SESSION KEY (ALSO INCLUDE ANY NECESSARY INFO IN THE ENCRYPTED MESSAGE FOR INTEGRITY PROTECTION)
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    # TODO deal with bytes
    # plain_text is a byte string
    def EncryptAndProtectMessage(self, plain_text):
        cipher_text = plain_text
        return cipher_text

    # Decrypting and verifying messages
    # TODO: IMPLEMENT DECRYPTION AND INTEGRITY CHECK WITH THE SESSION KEY
    # RETURN AN ERROR MESSAGE IF INTEGRITY VERITIFCATION OR AUTHENTICATION FAILS
    def DecryptAndVerifyMessage(self, cipher_text):
        plain_text = cipher_text
        return plain_text
