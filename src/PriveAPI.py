from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64
import socket
import re
import time
import threading


class AutoKeepAlive(threading.Thread):

    def __init__(self, serverSocket, keepAliveMsg):
        # type: (PriveAPIInstance, str)
        threading.Thread.__init__(self)
        self.serverSock = serverSocket
        self.keepAliveMsg = keepAliveMsg

    def run(self):
        while True:
            try:
                self.serverSock.send(self.keepAliveMsg)
                time.sleep(2)
            except:
                break

class PriveAPIInstance:

    def __init__(self, serverIP, serverPublicKeyFile="serverPublicKey.pk", serverPort=4373, autoKeepAlive=True):
        # type: (str, str, int, bool) -> None
        # Server Socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((serverIP, serverPort))
        self.sessionKeySet = False
        self.loggedInSK = None  # Private Key
        self.loggedInUser = ""  # Active User
        self.loggedIn = False

        serverPublicKeyF = open(serverPublicKeyFile, "r")
        serverPublicKeyStr = serverPublicKeyF.read()
        self.serverPublicKey = RSA.importKey(serverPublicKeyStr)

        self.__sendCreateSessionKeyMessage()

        self.keepAliveMsg = "keepAlive"

        keepAliveEncrypted = self.encryptWithPadding(self.sessionKey, self.keepAliveMsg)
        self.keepAliveMsg = keepAliveEncrypted[1] + "\r\n"

        if autoKeepAlive:
            self.autoKeepAlive = AutoKeepAlive(self.sock, self.keepAliveMsg)
            self.autoKeepAlive.start()

    # Generate Session Key
    def __generateSessionKey(self):
        self.sessionKey = ""
        while not len(self.sessionKey) == 32:
            self.sessionKey = random.long_to_bytes(random.getrandbits(256))

    # Creates a Session Key and sends it
    def __sendCreateSessionKeyMessage(self):
        # Generate Session Key
        self.__generateSessionKey()

        # Encrypt Session Key & Turn to B64
        sessionKeyEncrypted = self.serverPublicKey.encrypt(self.sessionKey, 2)[0]
        sessionKeyB64 = base64.b64encode(sessionKeyEncrypted)

        # Message
        msg = "sessionkey: " + sessionKeyB64 + "\r\n"

        # Send Message & Check For Errors
        if not self.__sendMsg(msg) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        # Receive Message & Check For Errors
        msgReceived = self.__receiveResponse()
        if not msgReceived[0] == 0:
            raise Exception("Error Communicating with Server (Error 0)")
        msgReceived = msgReceived[1]

        msgDataExtracted = self.extractData(msgReceived)
        msgErrorCode = msgDataExtracted[1]
        if msgErrorCode == "":
            raise Exception("Error Parsing Received Message (Error 1)")

        if not msgErrorCode == "successful":
            raise Exception("Error Settting Session Key (Error 2)")

        self.sessionKeySet = True

        return

    def createUser(self, userName, password):
        # type: (str, str) -> str
        """

        Creates User with userName param as name and password param as password

        :param userName: Name for the user that is created
        :param password: Password for the user that is created
        :return: errorMsg
        """
        # Generate RSA Keys
        rsaKeys = RSA.generate(2048)
        privateKey = rsaKeys.exportKey()
        publicKey = base64.b64encode(rsaKeys.publickey().exportKey())

        # Padding Password
        pwdLength = 16 - password.__len__()
        password = password + chr(pwdLength) * pwdLength

        # Validation Token
        vt = random.long_to_bytes(random.getrandbits(1024))
        vtSha = SHA256.new(vt).digest()

        # Encrypt & B64
        privateKeyEncrypted = self.encryptWithPadding(password, privateKey)[1]
        vtEncrypted = self.encryptWithPadding(password, vt)[1]
        vtShaB64 = base64.b64encode(vtSha)

        # Create Message
        message = "newUser;name: " + userName + ";pkB64: " + publicKey + ";skAesB64: "
        message = message + privateKeyEncrypted + ";vtB64: " + vtShaB64 + ";vtAesB64: " + vtEncrypted

        # Send Message
        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        # Receive Message & Check For Errors
        msgReceived = self.__receiveResponse()
        if not msgReceived[0] == 0:
            raise Exception("Error Communicating with Server (Error 0)")
        msgRece = msgReceived[1]

        # Extract Data
        msgDataExtracted = self.extractData(msgRece)
        msgErrorCode = msgDataExtracted[1]
        if msgErrorCode == "":
            raise Exception("Error Parsing Received Message (Error 1)")

        return msgErrorCode

    def __getVT(self, userName, password):
        # Create Message
        vtAesMsg = "getVtAesB64;name: " + userName

        # Send & Check For Errors
        if not self.__sendMsg(vtAesMsg) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        # Receive Message & Check For Errors
        msgReceived = self.__receiveResponse()
        if not msgReceived[0] == 0:
             raise Exception("Error Communicating with Server (Error 0)")
        msgReceived = msgReceived[1]

        # Extract Data
        msgDataExtracted = self.extractData(msgReceived)
        msgErrorCode = msgDataExtracted[1]
        if msgErrorCode == "":
            raise Exception("Error Parsing Received Message (Error 1)")

        # Check Successful
        if not msgErrorCode == "successful":
            return 1, "", msgErrorCode

        # Extract VTEnc
        vtExtracted = re.search(".+;vt: (.+)", msgDataExtracted[0])
        if not vtExtracted:
            raise Exception("Error Parsing Received Message (Error 1)")
        vtEnc = vtExtracted.group(1)

        # Decrypt VT
        vtAesDecrypted = base64.b64encode(self.decryptWithPadding(password, vtEnc)[1])
        return 0, vtAesDecrypted, ""

    def __checkVT(self, userName, password, vtDecrypted):
        # Validation Token
        newvt = random.long_to_bytes(random.getrandbits(1024))
        newvtSha = SHA256.new(newvt).digest()

        # Encrypt & B64
        newvtEncrypted = self.encryptWithPadding(password, newvt)[1]
        newvtShaB64 = base64.b64encode(newvtSha)

        message = "checkVT;name: " + userName + ";vt: " + vtDecrypted + ";newVTSha: " + newvtShaB64 + ";newVTEnc: "
        message = message + newvtEncrypted
        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if not response[0] == 0:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        # Extract Data
        msgDataExtracted = self.extractData(response)
        msgErrorCode = msgDataExtracted[1]
        if msgErrorCode == "":
            raise Exception("Error Parsing Received Message (Error 1)")

        if not msgErrorCode == "successful":
            return 1, msgDataExtracted[0], msgErrorCode

        skExtracted = re.search(".+;sk: (.+)", msgDataExtracted[0])
        if not skExtracted:
            raise Exception("Error Parsing Received Message (Error 1)")
        sk = skExtracted.group(1)
        skDecrypted = self.decryptWithPadding(password, sk)[1]
        return 0, skDecrypted, ""

    def login(self, userName, password):
        # type: (str, str) -> tuple
        """

        Logins as userName param using password param

        :param userName: User to login to
        :param password: Password for user
        :return: errorMsg, timeUntilUnlock
        """

        #Padding passwd
        pwdLength = 16 - password.__len__()
        password = password + chr(pwdLength) * pwdLength

        # Get VT
        vt = self.__getVT(userName, password)
        if vt[0] == 1:
            msgReturned = vt[2]
            if msgReturned == "usrNotFound":
                return "usrNotFound", 0
            else:
                raise Exception("Unhandled Message Returned (Error 2): {0}".format(msgReturned))

        # Get SK
        skDecrypted = self.__checkVT(userName, password, vt[1])
        if skDecrypted[0] == 1:
            msgReturned = skDecrypted[2]
            if msgReturned == "incorrect":
                return "incorrect", 0
            elif msgReturned == "usrNotFound":
                return "usrNotFound2", 0
            elif msgReturned == "accountLocked":
                accountLockedTime = re.search(".+;timeBeforeUnlocking: (.+)", skDecrypted[1])
                if not accountLockedTime:
                    raise Exception("Error Parsing Received Message (Error 1)")
                accountLockedTimeFloat = float(accountLockedTime.group(1))
                return "accountLocked", accountLockedTimeFloat
            else:
                raise Exception("Unhandled Message Returned (Error 2): {0}".format(msgReturned))

        # Import SK
        self.loggedInSK = RSA.importKey(skDecrypted[1])
        if not self.loggedInSK:
            raise Exception("Error Importing RSA Key (Error 3)")
        self.loggedInUser = userName
        self.loggedIn = True
        return "successful", 0

    def deleteUser(self):
        # type: () -> str
        """

        Deletes User if Logged In

        :return: errorMsg
        """
        if not self.loggedIn:
            return "Not logged in"

        textToSign = SHA256.new("delUser;name: " + self.loggedInUser).digest()
        signature = base64.b64encode(random.long_to_bytes(self.loggedInSK.sign(textToSign, 0)[0]))
        message = "delUser;name: " + self.loggedInUser + ";sign: " + signature
        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDataExtracted = self.extractData(response)
        msgErrorCode = msgDataExtracted[1]
        if msgErrorCode == "":
            raise Exception("Error Parsing Received Message (Error 1)")

        if msgErrorCode == "successful":
            self.loggedIn = False
            self.loggedInSK = None
            self.loggedInUser = ""

        return msgErrorCode

    def keepAlive(self):
            self.sock.send(self.keepAliveMsg)

    def __sendMsg(self, msg):
        # type: (str) -> int
        """

        Sends msg parameter and encrypts it if there is a Session Key set.
        Adds \\\\r\\\\n

        ErrorCodes (0 - Successful,
                    1 - Error Sending)

        :param msg:Message To Send
        :return: errorCode
        """
        if self.sessionKeySet == False:
            msgToSend = msg
            if not msgToSend[-2:] == "\r\n":
               msgToSend = msg + "\r\n"
            try:
                self.sock.send(msgToSend)
            except:
                return 1
        elif self.sessionKeySet == True:
            msgToSend = msg
            msgToSend = self.encryptWithPadding(self.sessionKey, msgToSend)[1] + "\r\n"
            try:
                self.sock.send(msgToSend)
            except:
                return 1
        return 0

    def __receiveResponse(self):
        # type: () -> tuple
        """

        Receives and decrypts if there is session key set.
        Removes \\\\r\\\\n


        ErrorCodes (0 - Successful,
                    1 - Error Receiving)

        :return: ErrorCode, Data
        """
        data = ""
        while True:
            try:
                newData = self.sock.recv(4096)
            except:
                return 1, ""
            data = data + newData
            if re.search("\r\n", newData):
                break
        if self.sessionKeySet == False:
            return 0, data[:-2]
        else:
            data = data[:-2]
            data = self.decryptWithPadding(self.sessionKey, data)[1]
            return 0, data

    def close(self):
        """

        Closes the connection to the server

        :return: Nothing
        """
        self.__sendMsg("quit")
        self.sock.close()

    # Get Random String
    @staticmethod
    def getRandString(len):
        # type: (int) -> str
        returnString = ""
        for x in range(0, len):
            returnString += chr(random.getrandbits(8))
        return returnString

    # Encrypt Using AES and Padding
    @staticmethod
    def encryptWithPadding(key, plaintext):
        # type: (str, str) -> tuple
        """

        Encrypts plaintext param with AES using key param as key.
        Also, returns base64-ed output.

        ErrorCodes (True  - Encrypted Correctly,
                    False - Password not padded (ciphertext = \"\")

        :param key: key used to encrypt
        :param plaintext: plaintext to encrypt
        :return: ErrorCode, Ciphertext
        """
        length = (16 - (len(plaintext) % 16)) + 16 * random.randint(0, 14)
        plaintextPadded = plaintext + PriveAPIInstance.getRandString(length - 1) + chr(length)
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, ""
        ciphertext = base64.b64encode(AES.new(key).encrypt(plaintextPadded))
        return True, ciphertext

    # Decrypt Using AES padded message
    @staticmethod
    def decryptWithPadding(key, ciphertext):
        # type: (str, str) -> tuple
        """

        Decrypts ciphertext param using key param as key.

        ErrorCodes (True  - Encrypted Correctly,
                    False - Password not padded (plainText = \"\")

        :param key: key used to decrypt
        :param ciphertext: ciphertext to decrypt
        :return: ErrorCode, Plaintext
        """
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, ""
        ciphertextNotB64 = base64.b64decode(ciphertext)
        plaintextPadded = AES.new(key).decrypt(ciphertextNotB64)
        plaintext = plaintextPadded[:-ord(plaintextPadded[-1])]
        return True, plaintext

    # Extract Data from Prive Message (msgData, errorCode)
    @staticmethod
    def extractData(msg):
        # type: (str) -> tuple
        """

        Extract Data from Prive Message (data;errorCode: eC)

        Returns (\"\", \"\") if it is not a prive message

        :param msg: Message to extract data from
        :return: data, eC
        """

        msgRe = re.search("^(.+);errorCode: (.+)", msg)
        if not msgRe:
            return "", ""

        msgData = msgRe.group(1)
        errorCode = msgRe.group(2)

        return msgData, errorCode