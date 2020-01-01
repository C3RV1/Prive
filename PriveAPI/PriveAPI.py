from Crypto.Random import *
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Sign
import socket
import re
import time
import threading
import utils
import random
import math
import string
import os

alphabet = list(string.ascii_lowercase)
alphabet.extend(str(i) for i in range(0, 10))
alphabet.extend(string.ascii_uppercase)

bytes3ChunksToSend = 65536

class AutoKeepAlive(threading.Thread):

    def __init__(self, serverSocket, keepAliveMsg):
        # type: (PriveAPIInstance, str) -> None
        threading.Thread.__init__(self)
        self.serverSock = serverSocket
        self.keepAliveMsg = keepAliveMsg
        self.event = threading.Event()

    def run(self):
        while True:
            if self.event.is_set():
                time.sleep(0.2)
                continue
            try:
                self.serverSock.send(self.keepAliveMsg)
                time.sleep(0.2)
            except:
                break

class PriveAPIInstance:

    def __init__(self, serverIP, serverPublicKey, serverPort=4373, autoKeepAlive=True,
                 keySize=4096, proofOfWork0es=5, proofOfWorkIterations=2):
        # type: (str, str, int, bool, int, int, int) -> None
        # Server Socket

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            socket.inet_aton(serverIP)
        except:
            try:
                serverIP = socket.gethostbyname(serverIP)
            except:
                raise Exception("Couldn't resolve host")

        try:
            self.sock.connect((serverIP, serverPort))
        except:
            self.sock.close()
            raise Exception("Could connect to server")
        self.sessionKeySet = False
        self.loggedInSK = None  # Private Key
        self.loggedInUser = ""  # Active User
        self.loggedInPassword = ""  # Active User Password
        self.loggedIn = False
        self.keySize = keySize
        self.proofOfWork0es = proofOfWork0es
        self.proofOfWorkIterations = proofOfWorkIterations

        serverPublicKeyStr = serverPublicKey
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
            self.sessionKey = get_random_bytes(32)

    # Creates a Session Key and sends it
    def __sendCreateSessionKeyMessage(self):
        # Generate Session Key
        self.__generateSessionKey()

        # Encrypt Session Key & Turn to B64
        sessionKeyEncrypted = PKCS1_OAEP.new(self.serverPublicKey).encrypt(self.sessionKey)
        sessionKeyB64 = utils.base64_encode(sessionKeyEncrypted)

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

    def solveProofOfWork(self, challenge):
        random.seed(time.time())
        numToAppend = random.randint(0, math.pow(math.floor(time.time()), 2))
        while True:
            testStr = challenge + PriveAPIInstance.numToAlphabet(numToAppend)
            hash = SHA256.new(testStr)
            for i in range(0, self.proofOfWorkIterations-1):
                hash.update(hash.hexdigest())
            if re.search("^" + "0"*self.proofOfWork0es, hash.hexdigest()):
                # Debug
                #print "Check: {}".format(utils.checkProofOfWork(testStr, self.proofOfWork0es,
                #                                                self.proofOfWorkIterations))
                return PriveAPIInstance.numToAlphabet(numToAppend)
            numToAppend += 1

    def requestChallengeAndSolve(self):
        # type: () -> tuple
        message = "requestChallenge"
        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        msgReceived = self.__receiveResponse()
        if not msgReceived[0] == 0:
            raise Exception("Error Communicating with Server (Error 0)")
        msgRece = msgReceived[1]

        # Extract Data
        msgDict = self.extractKeys(msgRece)

        #print "DBG: {}".format(msgDict)

        if msgDict["errorCode"] != "successful":
            return False, ""

        challenge = utils.base64_decode(msgDict["challenge"])
        return True, self.solveProofOfWork(challenge)

    def sendFile(self, filePath, encrypted):
        self.autoKeepAlive.event.set()
        fileHandler = open(filePath, "rb")
        segment = 0

        msgDict = {}

        while True:
            dataToSend = fileHandler.read(3*bytes3ChunksToSend)
            if dataToSend == "":
                break
            if encrypted:
                dataToSend = self.encryptWithPadding(self.loggedInPassword, dataToSend)
            dataToSend = utils.base64_encode(dataToSend)
            segmentMessage = "segment;num: {};data: {}".format(segment, dataToSend)
            if not self.__sendMsg(segmentMessage) == 0:
                Exception("Error Communicating with Server (Error 0)")

            response = self.__receiveResponse()
            if response[0] == 1:
                raise Exception("Error Communicating with Server (Error 0)")
            response = response[1]

            #print "DBG: {}".format(response)

            msgDict = self.extractKeys(response)

            if msgDict["errorCode"] != "successful":
                raise Exception("Error Transfering File (Error 5): {}".format(msgDict))
            segment += 1

        self.autoKeepAlive.event.clear()
        return msgDict

    def createUser(self, userName, password):
        # type: (str, str) -> dict
        """

        Creates User with userName param as name and password param as password

        :param userName: Name for the user that is created
        :param password: Password for the user that is created
        :return: errorMsg
        """
        # Generate RSA Keys
        rsaKeys = RSA.generate(self.keySize)
        privateKey = rsaKeys.exportKey()
        publicKey = utils.base64_encode(rsaKeys.publickey().exportKey())

        # Padding Password
        if len(password) > 16:
            raise
        pwdLength = 16 - password.__len__()
        password = password + chr(pwdLength) * pwdLength

        # Validation Token
        vt = get_random_bytes(128)
        vtSha = SHA256.new(vt).digest()

        # Encrypt & B64
        privateKeyEncrypted = self.encryptWithPadding(password, privateKey)[1]
        vtEncrypted = self.encryptWithPadding(password, vt)[1]
        vtShaB64 = utils.base64_encode(vtSha)

        proofOfWork = self.requestChallengeAndSolve()
        if proofOfWork[0] is False:
            raise Exception("Error Calculation Proof of Work (Error 4)")

        # Create Message
        message = "newUser;name: " + userName + ";pkB64: " + publicKey + ";skAesB64: "
        message = message + privateKeyEncrypted + ";vtB64: " + vtShaB64 + ";vtAesB64: " + vtEncrypted
        message = message + ";pow: " + utils.base64_encode(proofOfWork[1])

        # Send Message
        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        # Receive Message & Check For Errors
        msgReceived = self.__receiveResponse()
        if not msgReceived[0] == 0:
            raise Exception("Error Communicating with Server (Error 0)")
        msgRece = msgReceived[1]

        # Extract Data
        msgDict = self.extractKeys(msgRece)

        return msgDict

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
        msgDict = self.extractKeys(msgReceived)

        return msgDict

    def __checkVT(self, userName, password, vtDecrypted):
        # Validation Token
        newvt = get_random_bytes(128)
        newvtSha = SHA256.new(newvt)

        # Encrypt & B64
        newvtEncrypted = self.encryptWithPadding(password, newvt)[1]
        newvtShaB64 = utils.base64_encode(newvtSha.digest())

        message = "checkVT;name: " + userName + ";vt: " + vtDecrypted + ";newVTSha: " + newvtShaB64 + ";newVTEnc: "
        message = message + newvtEncrypted
        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if not response[0] == 0:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        # Extract Data
        msgDict = self.extractKeys(response)
        return msgDict

    def login(self, userName, password):
        # type: (str, str) -> dict
        """

        Login as <userName> using <password>

        :param userName: User to login to
        :param password: Password for user
        :return: errorMsg, timeUntilUnlock
        """

        #Padding passwd
        pwdLength = 16 - len(password)
        password = password + chr(pwdLength) * pwdLength

        # Get VT
        vt = self.__getVT(userName, password)
        if vt["errorCode"] != "successful":
            return vt

        # Get SK
        skDecrypted = self.__checkVT(userName, password, utils.base64_encode(self.decryptWithPadding(password,
                                                                                                     vt["vt"])[1]))
        if skDecrypted["errorCode"] != "successful":
            return skDecrypted

        # Import SK
        self.loggedInSK = RSA.importKey(self.decryptWithPadding(password, skDecrypted["sk"])[1])
        if not self.loggedInSK:
            raise Exception("Error Importing RSA Key (Error 3)")
        self.loggedInUser = userName
        self.loggedIn = True
        self.loggedInPassword = password
        return skDecrypted

    def deleteUser(self):
        # type: () -> dict
        """

        Deletes User if Logged In

        :return: errorMsg
        """
        if not self.loggedIn:
            raise Exception("Not logged in")

        textToSign = SHA256.new("delUser;name: " + self.loggedInUser)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.loggedInSK).sign(textToSign))
        message = "delUser;name: " + self.loggedInUser + ";signatureB64: " + signature
        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)
        if msgDict["errorCode"] == "successful":
            self.loggedIn = False
            self.loggedInPassword = ""
            self.loggedInSK = None
            self.loggedInUser = ""
        return msgDict

    def updateKeys(self, newPasswd):
        if not self.loggedIn:
            raise Exception("Not logged in")


        pwdLength = 16 - len(newPasswd)
        newPasswd = newPasswd + chr(pwdLength) * pwdLength

        newRSAKey = RSA.generate(self.keySize)
        newPKExported = newRSAKey.publickey().exportKey()
        newPKExportedB64 = utils.base64_encode(newRSAKey.publickey().exportKey())
        newSKExported = newRSAKey.exportKey()

        # Validation Token
        newvt = get_random_bytes(128)
        newvtSha = SHA256.new(newvt)

        # Encrypt & B64
        newvtEncrypted = self.encryptWithPadding(newPasswd, newvt)[1]
        newvtShaB64 = utils.base64_encode(newvtSha.digest())

        # Encrypt & B64
        privateKeyEncrypted = self.encryptWithPadding(newPasswd, newSKExported)[1]

        textToSign = "updateKeys;name: " + self.loggedInUser + ";newPK: " + newPKExported + ";newSKAesB64: "
        textToSign = textToSign + privateKeyEncrypted + ";newVTSha: " + newvtShaB64 + ";newVTEnc: " + newvtEncrypted
        textToSign = SHA256.new(textToSign)

        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.loggedInSK).sign(textToSign))
        message = "updateKeys;name: " + self.loggedInUser + ";signatureB64: " + signature + ";newPKB64: "
        message = message + newPKExportedB64 + ";newSKAesB64: " + privateKeyEncrypted
        message = message + ";newVTSha: " + newvtShaB64 + ";newVTEnc: " + newvtEncrypted
        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)

        if msgDict["errorCode"] == "successful":
            self.loggedInSK = newRSAKey
            self.loggedInPassword = newPasswd

        return msgDict

    def getUserPK(self, user):
        message = "getPK;name: {0}".format(user)
        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if not response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")

        response = response[1]
        msgDict = self.extractKeys(response)

        return msgDict

    def addFile(self, fileName, filePath, visibility="Public"):
        if not self.loggedIn:
            raise Exception("Not logged in")

        if visibility != "Public" and visibility != "Hidden" and visibility != "Private":
            raise Exception("Visibility unknown")

        if not os.path.isfile(filePath):
            raise Exception("File not found")

        fileNameB64 = utils.base64_encode(fileName)

        fileSize = int(math.ceil(os.stat(filePath).st_size/3)*4)

        message = "add" + visibility + "File;name: " + self.loggedInUser + ";fileNameB64: " + fileNameB64 + ";fileB64Size: "
        message = message + str(fileSize)
        #print "BBG " + message
        textToSign = SHA256.new(message)

        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.loggedInSK).sign(textToSign))
        message = message + ";signatureB64: " + signature

        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)

        if msgDict["errorCode"] == "successful":
            msgDict = self.sendFile(filePath, visibility == "Private")

        return msgDict

    def getFiles(self, user=""):
        if user == "" or user == self.loggedInUser:
            return self.__getFiles()
        publicFileListMessage = "getPublicFileList;name: " + user

        if not self.__sendMsg(publicFileListMessage) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)

        if msgDict["errorCode"] != "successful":
            return msgDict

        filesDict = self.extractFiles(msgDict["pufl"], visibility="Public")
        filesDict["errorCode"] = "successful"

        return filesDict

    def __getFiles(self):
        if not self.loggedIn:
            raise Exception("Not logged in")

        publicFileListMessage = "getPublicFileList;name: " + self.loggedInUser

        if not self.__sendMsg(publicFileListMessage) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)

        if msgDict["errorCode"] != "successful":
            return msgDict

        filesDict = self.extractFiles(msgDict["pufl"], visibility="Public")
        filesDict["errorCode"] = "successful"

        hiddenFileListMessage = "getHiddenFileList;name: " + self.loggedInUser
        textToSign = SHA256.new(hiddenFileListMessage)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.loggedInSK).sign(textToSign))
        hiddenFileListMessage = hiddenFileListMessage + ";signatureB64: " + signature

        if not self.__sendMsg(hiddenFileListMessage) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)

        if msgDict["errorCode"] != "successful":
            return msgDict

        filesDict.update(self.extractFiles(msgDict["hfl"], visibility="Hidden"))

        privateFileListMessage = "getPrivateFileList;name: " + self.loggedInUser
        textToSign = SHA256.new(privateFileListMessage)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.loggedInSK).sign(textToSign))
        hiddenFileListMessage = privateFileListMessage + ";signatureB64: " + signature

        if not self.__sendMsg(hiddenFileListMessage) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)

        if msgDict["errorCode"] != "successful":
            return msgDict

        filesDict.update(self.extractFiles(msgDict["prfl"], visibility="Private"))
        filesDict["errorCode"] = "successful"
        return filesDict

    def getFile(self, fileDict, outputPath, user=""):
        if user == "":
            if not self.loggedIn:
                raise Exception("Not logged in")
            user = self.loggedInUser

        if fileDict["visibility"] == "Private":
            return self.__getPrivateFile(user, fileDict, outputPath)

        getFileMessage = "getFile;name: " + user + ";id: " + fileDict["id"]

        if not self.__sendMsg(getFileMessage) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)
        if msgDict["errorCode"] != "successful":
            return msgDict

        self.autoKeepAlive.event.set()

        ouFile = open(outputPath, "wb")
        while True:
            if not self.__sendMsg("segment") == 0:
                raise Exception("Error Communicating with Server (Error 0)")

            response = self.__receiveResponse()
            if response[0] == 1:
                raise Exception("Error Communicating with Server (Error 0)")

            response = response[1]

            msgDict = self.extractKeys(response)
            if msgDict["errorCode"] != "successful" and msgDict["errorCode"] == "allSent":
                msgDict["errorCode"] = "successful"
                break
            ouFile.write(utils.base64_decode(msgDict["data"]))
        ouFile.close()

        self.autoKeepAlive.event.clear()
        return msgDict

    def __getPrivateFile(self, user, fileDict, outputPath):
        getPrivateFileMessage = "getPrivateFile;name: " + user + ";id: " + fileDict["id"]
        textToSign = SHA256.new(getPrivateFileMessage)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.loggedInSK).sign(textToSign))
        getPrivateFileMessage = getPrivateFileMessage + ";signatureB64: " + signature

        if not self.__sendMsg(getPrivateFileMessage) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)
        if msgDict["errorCode"] != "successful":
            return msgDict

        self.autoKeepAlive.event.set()

        ouFile = open(outputPath, "wb")
        while True:
            response = self.__receiveResponse()
            if response[0] == 1:
                raise Exception("Error Communicating with Server (Error 0)")
            response = response[1]

            msgDict = self.extractKeys(response)
            if msgDict["errorCode"] != "segment" and msgDict["errorCode"] == "successful":
                break
            msgDict["data"] = utils.base64_decode(msgDict["data"])
            ouFile.write(self.decryptWithPadding(self.sessionKey, msgDict["data"])[1])
        ouFile.close()

        self.autoKeepAlive.event.clear()
        return msgDict

    def deleteFile(self, fileDict):
        if not self.loggedIn:
            raise Exception("Not logged in")

        deleteFileMessage = "deleteFile;name: " + self.loggedInUser + ";id: " + fileDict["id"]
        textToSign = SHA256.new(deleteFileMessage)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.loggedInSK).sign(textToSign))
        deleteFileMessage = deleteFileMessage + ";signatureB64: " + signature

        if not self.__sendMsg(deleteFileMessage) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)
        return msgDict

    def logout(self):
        self.loggedIn = False
        self.loggedInPassword = ""
        self.loggedInSK = None
        self.loggedInUser = ""

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

    def getLoggedInPasswd(self):
        """

        Returns the password used for login.
        Raises exception if not logged in.

        :return: password
        """
        if not self.loggedIn:
            raise Exception("Password requested while not logged in")
        return self.loggedInPassword[:-ord(self.loggedInPassword[-1])]

    # Get Random String
    @staticmethod
    def getRandString(len):
        # type: (int) -> str
        returnString = ""
        for x in range(0, len):
            returnString += get_random_bytes(1)
        if "\x00" in returnString:
            return PriveAPIInstance.getRandString(len)
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
        ciphertext = utils.base64_encode(AES.new(key, AES.MODE_ECB).encrypt(plaintextPadded))
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
        ciphertextNotB64 = utils.base64_decode(ciphertext)
        plaintextPadded = AES.new(key, AES.MODE_ECB).decrypt(ciphertextNotB64)
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

    @staticmethod
    def extractKeys(msg):
        # type: (str) -> dict
        msgSplit = msg.split(";")
        returnDict = {}
        for key in msgSplit:
            regex = re.search("^(.+): (.+)$", key)
            if regex:
                returnDict[regex.group(1)] = regex.group(2)

        return returnDict

    @staticmethod
    def extractFiles(fileList, visibility):
        fileListSplit = fileList.split(",")[1:-1]
        returnDict = {}
        for i in fileListSplit:
            regex = re.search("fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if regex:
                returnDict[regex.group(2)] = {"name": utils.base64_decode(regex.group(1)),
                                              "visibility": visibility,
                                              "id": regex.group(2),
                                              "size": int((int(regex.group(3))/4.0)*3)}  # Transform b64 size to bytes
        return returnDict

    @staticmethod
    def numToAlphabet(num):
        res = ""
        while num > 0:
            res += alphabet[num % len(alphabet)]
            num = (num - len(alphabet)) / len(alphabet)
        return res
