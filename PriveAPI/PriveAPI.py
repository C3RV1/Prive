from Crypto.Random import *
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Sign
import base64
import socket
import re
import time
import threading
import utils


class AutoKeepAlive(threading.Thread):

    def __init__(self, serverSocket, keepAliveMsg):
        # type: (PriveAPIInstance, str) -> None
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

    def __init__(self, serverIP, serverPublicKeyFile="serverPublicKey.pk", serverPort=4373, autoKeepAlive=True,
                 keySize=4096):
        # type: (str, str, int, bool, int) -> None
        # Server Socket

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((serverIP, serverPort))
        self.sessionKeySet = False
        self.loggedInSK = None  # Private Key
        self.loggedInUser = ""  # Active User
        self.loggedInPassword = ""  # Active User Password
        self.loggedIn = False
        self.keySize = keySize

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
        pwdLength = 16 - password.__len__()
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
        return msgDict

    def updateKeys(self):
        if not self.loggedIn:
            raise Exception("Not logged in")

        newRSAKey = RSA.generate(self.keySize)
        newPKExported = newRSAKey.publickey().exportKey()
        newPKExportedB64 = utils.base64_encode(newRSAKey.publickey().exportKey())
        newSKExported = newRSAKey.exportKey()

        # Encrypt & B64
        privateKeyEncrypted = self.encryptWithPadding(self.loggedInPassword, newSKExported)[1]

        textToSign = "updateKeys;name: " + self.loggedInUser + ";newPK: " + newPKExported + ";newSKAesB64: "
        textToSign = textToSign + privateKeyEncrypted
        textToSign = SHA256.new(textToSign)

        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.loggedInSK).sign(textToSign))
        message = "updateKeys;name: " + self.loggedInUser + ";signatureB64: " + signature + ";newPKB64: "
        message = message + newPKExportedB64 + ";newSKAesB64: " + privateKeyEncrypted
        if not self.__sendMsg(message) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)

        if msgDict["errorCode"] == "successful":
            self.loggedInSK = newRSAKey

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

    def addFile(self, fileName, fileContents, visibility="Public"):
        if not self.loggedIn:
            raise Exception("Not logged in")

        if visibility != "Public" and visibility != "Hidden" and visibility != "Private":
            raise Exception("Visibility unknown")

        fileNameB64 = utils.base64_encode(fileName)
        if visibility == "Private":
            fileContents = self.encryptWithPadding(self.loggedInPassword, fileContents)[1]
        fileContentsB64 = utils.base64_encode(fileContents)

        message = "add" + visibility + "File;name: " + self.loggedInUser + ";fileNameB64: " + fileNameB64 + ";fileB64: "
        message = message + fileContentsB64
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

        return msgDict

    def getFiles(self, user=""):
        if user == "":
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
        return filesDict

    def getFile(self, fileDict, user=""):
        if user == "":
            if not self.loggedIn:
                raise Exception("Not logged in")
            user = self.loggedInUser

        if fileDict["visibility"] == "Private":
            return self.__getPrivateFile(user, fileDict)

        getFileMessage = "getFile;name: " + user + ";id: " + fileDict["id"]

        if not self.__sendMsg(getFileMessage) == 0:
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receiveResponse()
        if response[0] == 1:
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extractKeys(response)
        if msgDict["errorCode"] == "successful":
            msgDict["file"] = utils.base64_decode(msgDict["fileB64"])
        return msgDict

    def __getPrivateFile(self, user, fileDict):
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
        if msgDict["errorCode"] == "successful":
            msgDict["file"] = self.decryptWithPadding(self.loggedInPassword, utils.base64_decode(msgDict["fileB64"]))[1]
        return msgDict

    def deleteFile(self, fileDict):
        if not self.loggedIn:
            raise Exception("Not logged in")

        deleteFileMessage = "deleteFile;name: " + self.loggedInUser + ";id: " + fileDict["id"]
        textToSign = SHA256.new(deleteFileMessage)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.loggedInSK).sign(textToSign))
        deleteFileMessage = deleteFileMessage + "signatureB64: " + signature

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
            regex = re.search("fileName: (.+).id: (.+)", i)
            if regex:
                returnDict[regex.group(2)] = {"name": utils.base64_decode(regex.group(1)),
                                              "visibility": visibility,
                                              "id": regex.group(2)}
        return returnDict
