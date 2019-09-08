from Crypto.Cipher import AES
from Crypto.Random import random
from Crypto.Random import get_random_bytes
import server
import re
import databaseManager
import socket
import threading
import base64
import time
import utils


class Timeout(threading.Thread):
    def __init__(self, clientHandlerMaster, sock, clientAddr, timeoutList, timeout, databaseManager):
        # type: (ClientHandle, socket.socket, tuple, list, int, databaseManager.DatabaseManager) -> None
        self.databaseManager = databaseManager
        self.clientAddr = clientAddr
        self.log("Starting Timeout Thread on Client " + clientAddr[0] + " " + str(clientAddr[1]))
        threading.Thread.__init__(self)
        self.socket = sock
        self.timeoutList = timeoutList
        self.timeout = timeout
        self.clientHandlerMaster = clientHandlerMaster

    def log(self, msg, printOnScreen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.databaseManager.logger.log("ClientTimeout:" + self.clientAddr[0] + ":" + str(self.clientAddr[1]),
                                        msg, printToScreen=printOnScreen, debug=debug)

    def run(self):
        while True and not self.timeoutList[1]:
            if self.timeoutList[0] > self.timeout:
                self.log("Client " + self.clientAddr[0] + " " + str(self.clientAddr[1]) + " has reached the timeout")
                self.socket.close()
                self.clientHandlerMaster.closeAll()
                break
            time.sleep(1)
            self.timeoutList[0] += 1
        self.log("Exiting Timeout")


class ClientHandle(threading.Thread):

    def __init__(self, clientSocket, clientAddress, databaseManager, serverMaster, timeout):
        #type: (ClientHandle, socket.socket, tuple, databaseManager.DatabaseManager, server.Server, int) -> None
        threading.Thread.__init__(self)
        self.clientSocket = clientSocket
        self.clientAddress = clientAddress
        self.databaseManager = databaseManager
        self.serverMaster = serverMaster
        self.timeoutList = [0, False]  # Because all instances share the same object
        self.timeOutController = Timeout(self, self.clientSocket, self.clientAddress, self.timeoutList, timeout, databaseManager)
        self.timeOutController.start()

    def run(self):
        while True:
            #try:
            if True:
                data = ""
                while True:
                    newData = self.clientSocket.recv(4096)
                    data = data + newData
                    if re.search("\r\n", newData):
                        break
                if self.handleMessage(data):
                    break
                if not self.serverMaster.running.returnRunning():
                    self.send("quit")
                    break
            """except Exception as e:
                self.log("Error:" + e, error=True)"""
        self.closeAll()

    def closeAll(self):
        self.databaseManager.deleteSessionKey(self.clientAddress[0], self.clientAddress[1])
        self.log("Closing")
        try:
            self.clientSocket.close()
        except Exception:
            self.log("Client Already Closed")
        self.log("Removing Timeout")
        self.timeOutController = None
        self.log("Removing Self")
        self.serverMaster.deleteClientThread(self)
        self.timeoutList[1] = True

    def log(self, msg, printOnScreen=True, debug=False, error=False, saveToFile=True):
        # type: (str, bool, bool, bool, bool) -> None
        self.databaseManager.logger.log("Client:" + self.clientAddress[0] + ":" + str(self.clientAddress[1]),
                                        msg, printToScreen=printOnScreen, debug=debug, error=error, saveToFile=saveToFile)
        pass

    def send(self, msg, encrypted=False, key=""):
        #type: (str, bool, str) -> None
        self.log("Sending [{}]".format(msg), printOnScreen=False)
        self.log("Sending {}".format(msg.split(';')[0]), saveToFile=False)
        if encrypted:
            msg = self.encryptWithPadding(key, msg)[1] + "\r\n"
        else:
            msg += "\r\n"
        self.clientSocket.send(msg)
        pass

    def handleMessage(self, data):
        self.timeoutList[0] = 0
        data = data[:-2]
        if re.search("^quit$", data):
            return True
        sessionKeyRe = re.search("^sessionkey: (.*)$", data)
        sessionKey = self.databaseManager.getSessionKey(self.clientAddress[0], self.clientAddress[1])
        if sessionKeyRe:
            self.log("Received session key")
            if not sessionKey[0]:
                validSEK = self.databaseManager.newSessionKey(self.clientAddress[0], self.clientAddress[1],
                                                                    sessionKeyRe.group(1))
                if not validSEK:
                    self.send("Invalid Session Key;errorCode: invalid")
                else:
                    self.send("Session Key Updated;errorCode: successful")
                return False
            else:
                self.send("Already Session Key;errorCode: already")
                return False

        if not sessionKey[0]:
            self.send("No Session Key")
            return False

        sessionKey = sessionKey[1]

        decryptedMessage = self.decryptWithPadding(sessionKey, data)[1]
        self.log("Received: " + decryptedMessage, printOnScreen=False)
        showTxt = ""
        for i in range(0, len(decryptedMessage)):
            if decryptedMessage[i] == ';':
                break
            showTxt += decryptedMessage[i]
        self.log("Received: " + showTxt, saveToFile=False)

        if re.search("^quit$", decryptedMessage):
            return True
        if re.search("^keepAlive$", decryptedMessage):
            return False

        newUser = re.search("^newUser;name: (.+);pkB64: (.+);skAesB64: (.+);vtB64: (.+);vtAesB64: (.+)$",
                            decryptedMessage)
        if newUser:
            msg = ""
            l_name = newUser.group(1)
            l_pkB64 = base64.b64decode(newUser.group(2))
            l_skAesB64 = newUser.group(3)
            l_vtShaB64 = newUser.group(4)
            l_vtAesB64 = newUser.group(5)

            # l_databaseQueryErrorCode = self.databaseManager.newUser(l_name, l_pkB64, l_skAesB64, l_vtShaB64, l_vtAesB64)
            l_databaseQueryErrorCode = self.databaseManager.executeFunction("newUser", (l_name,
                                                                                        l_pkB64,
                                                                                        l_skAesB64,
                                                                                        l_vtShaB64,
                                                                                        l_vtAesB64))

            if l_databaseQueryErrorCode == 0:
                msg = "New User Registered!;errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Already Exists;errorCode: usrAlreadyExists"
            elif l_databaseQueryErrorCode == 2:
                msg = "Invalid Name Characters;errorCode: invalidName"
            elif l_databaseQueryErrorCode == 3:
                msg = "Invalid Private Key Characters;errorCode: invalidSK"
            elif l_databaseQueryErrorCode == 4:
                msg = "Invalid Public Key Characters;errorCode: invalidPK"
            elif l_databaseQueryErrorCode == 5:
                msg = "Invalid Validation Token Characters;errorCode: invalidVT"
            elif l_databaseQueryErrorCode == 6:
                msg = "Invalid Encrypted Validation Token Characters;errorCode: invalidVTEnc"
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"
            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getVtAesB64 = re.search("^getVtAesB64;name: (.+)$", decryptedMessage)

        if getVtAesB64:
            l_name = getVtAesB64.group(1)
            # l_databaseQueryResult = self.databaseManager.getVtAesB64(l_name)

            l_databaseQueryResult = self.databaseManager.executeFunction("getVTAesB64", (l_name,))

            l_databaseQueryErrorCode = l_databaseQueryResult[0]
            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "vtAesB64;vt: " + l_databaseQueryResult[1] + ";errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "User Without VtAESB64;errorCode: wtfHappenedToTheVTEnc"
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        checkVT = re.search("^checkVT;name: (.+);vt: (.+);newVTSha: (.+);newVTEnc: (.+)$", decryptedMessage)

        if checkVT:
            l_name = checkVT.group(1)
            l_vtB64 = checkVT.group(2)
            l_newVTSha = checkVT.group(3)
            l_newVTEnc = checkVT.group(4)

            l_databaseQueryResult = self.databaseManager.executeFunction("checkVT", (l_name, l_vtB64,
                                                                                     self.clientAddress[0],
                                                                                     l_newVTSha, l_newVTEnc))

            l_databaseQueryErrorCode = l_databaseQueryResult[0]
            msg = ""

            if l_databaseQueryErrorCode == 0:
                l_skAesB64 = self.databaseManager.executeFunction("getSK", (l_name,))
                l_skAesB64ErrorCode = l_skAesB64[0]
                if l_skAesB64ErrorCode == 0:
                    msg = "VT Correct!;sk: " + l_skAesB64[1] + ";errorCode: successful"
                elif l_skAesB64ErrorCode == 1:
                    msg = "User Without SK;errorCode: wtfHappenedToTheSK"
                elif l_skAesB64ErrorCode == 2:
                    msg = "Impossible Exception;errorCode: somethingIsWrong"
            elif l_databaseQueryErrorCode == 1:
                msg = "Incorrect VT;errorCode: incorrect"
            elif l_databaseQueryErrorCode == 2:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 3:
                msg = "User Without VT;errorCode: wtfHappenedToTheVTSha"
            elif l_databaseQueryErrorCode == 4:
                msg = "Invalid Validation Token Characters;errorCode: invalidVT"
            elif l_databaseQueryErrorCode == 5:
                msg = "Account Locked;timeBeforeUnlocking: " + str(l_databaseQueryResult[1]) + ";errorCode: accountLocked"
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getPk = re.search("^getPK;name: (.+)$", decryptedMessage)

        if getPk:
            l_name = getPk.group(1)

            l_databaseQueryResult = self.databaseManager.executeFunction("getPK", (l_name,))

            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "pk;pk: " + l_databaseQueryResult[1] + ";errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "User Without PK;errorCode: wtfHappenedToThePK"
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        delUser = re.search("^delUser;name: (.+);signatureB64: (.+)$",decryptedMessage)

        if delUser:
            l_name = delUser.group(1)
            l_signatureB64 = delUser.group(2)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("delUser", (l_name, l_signatureB64))

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "User Deleted Successfully;errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "User Without PK;errorCode: wtfHappenedToThePK"
            elif l_databaseQueryErrorCode == 3:
                msg = "Invalid Signature Characters;errorCode: invalidSignCh"
            elif l_databaseQueryErrorCode == 4:
                msg = "Faulty Signature;errorCode: invalidSign"
            elif l_databaseQueryErrorCode == 5:
                msg = "Error Importing User PK;errorCode: faultyPK"
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        updateKeys = re.search("^updateKeys;name: (.+);signatureB64: (.+);newPKB64: (.+);newSKAesB64: (.+)$",
                               decryptedMessage)

        if updateKeys:
            l_name = updateKeys.group(1)
            l_signatureB64 = updateKeys.group(2)
            l_newPK = updateKeys.group(3)
            l_newSKAesB64 = updateKeys.group(4)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("updateKeys", (l_name,
                                                                                           l_signatureB64,
                                                                                           l_newPK,
                                                                                           l_newSKAesB64))

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "Keys Updated;errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "Invalid Signature Characters;errorCode: invalidSignCh"
            elif l_databaseQueryErrorCode == 3:
                msg = "Invalid newSKAesB64 Characters;errorCode: invalidNewSKAesB64"
            elif l_databaseQueryErrorCode == 4:
                msg = "Invalid newPK Format or Characters;errorCode: invalidNewPK"
            elif l_databaseQueryErrorCode == 5:
                msg = "Strange Error Where User Doesn't Have PK;errorCode: wtfHappenedToThePK"
            elif l_databaseQueryErrorCode == 6:
                msg = "Error Importing User PK;errorCode: faultyPK"
            elif l_databaseQueryErrorCode == 7:
                msg = "Faulty Signature;errorCode: invalidSign"
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        addPublicFile = re.search("^addPublicFile;name: (.+);fileNameB64: (.+);fileB64: (.+);signatureB64: (.+)$",
                                  decryptedMessage)

        if addPublicFile and False:
            l_name = addPublicFile.group(1)
            l_fileNameB64 = addPublicFile.group(2)
            l_fileB64 = addPublicFile.group(3)
            l_signatureB64 = addPublicFile.group(4)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("addPublicFile", (l_name, l_fileNameB64,
                                                                                              l_fileB64,
                                                                                              l_signatureB64))

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "File Added;errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "Invalid Filename Characters;errorCode: invalidFilename"
            elif l_databaseQueryErrorCode == 3:
                msg = "Invalid File Characters;errorCode: invalidFileCharacters"
            elif l_databaseQueryErrorCode == 4:
                msg = "Invalid Signature Characters;errorCode: invalidSignCh"
            elif l_databaseQueryErrorCode == 5:
                msg = "Strange Error Where User Doesn't Have PK;errorCode: wtfHappenedToThePK"
            elif l_databaseQueryErrorCode == 6:
                msg = "Error Importing User PK;errorCode: faultyPK"
            elif l_databaseQueryErrorCode == 7:
                msg = "Faulty Signature;errorCode: invalidSign"
            elif l_databaseQueryErrorCode == 8:
                msg = "Missing Public File List;errorCode: missingPUFL"
            elif l_databaseQueryErrorCode == 9:
                msg = "File exceeds max file size of {0} bytes;maxSize: {0};errorCode: fileTooBig".format(
                    self.databaseManager.maxFileSize)
            elif l_databaseQueryErrorCode == 10:
                msg = "Reached max files: {0};maxFiles: {0};errorCode: maxFilesReached".format(self.databaseManager.maxFiles)
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        addHiddenFile = re.search("^addHiddenFile;name: (.+);fileNameB64: (.+);fileB64: (.+);signatureB64: (.+)$",
                                  decryptedMessage)

        if addHiddenFile and False:
            l_name = addHiddenFile.group(1)
            l_fileNameB64 = addHiddenFile.group(2)
            l_fileB64 = addHiddenFile.group(3)
            l_signatureB64 = addHiddenFile.group(4)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("addHiddenFile", (l_name, l_fileNameB64,
                                                                                              l_fileB64,
                                                                                              l_signatureB64))

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "File Added;errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "Invalid Filename Characters;errorCode: invalidFilename"
            elif l_databaseQueryErrorCode == 3:
                msg = "Invalid File Characters;errorCode: invalidFileCharacters"
            elif l_databaseQueryErrorCode == 4:
                msg = "Invalid Signature Characters;errorCode: invalidSignCh"
            elif l_databaseQueryErrorCode == 5:
                msg = "Strange Error Where User Doesn't Have PK;errorCode: wtfHappenedToThePK"
            elif l_databaseQueryErrorCode == 6:
                msg = "Error Importing User PK;errorCode: faultyPK"
            elif l_databaseQueryErrorCode == 7:
                msg = "Faulty Signature;errorCode: invalidSign"
            elif l_databaseQueryErrorCode == 8:
                msg = "Missing Public File List;errorCode: missingPUFL"
            elif l_databaseQueryErrorCode == 9:
                msg = "File exceeds max file size of {0} bytes;maxSize: {0};errorCode: fileTooBig".format(
                    self.databaseManager.maxFileSize)
            elif l_databaseQueryErrorCode == 10:
                msg = "Reached max files: {0};maxFiles: {0};errorCode: maxFilesReached".format(self.databaseManager.maxFiles)
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        addPrivateFile = re.search("^addPrivateFile;name: (.+);fileNameB64: (.+);fileB64: (.+);signatureB64: (.+)$",
                                   decryptedMessage)

        if addPrivateFile and False:
            l_name = addPrivateFile.group(1)
            l_fileNameB64 = addPrivateFile.group(2)
            l_fileB64 = addPrivateFile.group(3)
            l_signatureB64 = addPrivateFile.group(4)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("addPrivateFile", (l_name, l_fileNameB64,
                                                                                               l_fileB64,
                                                                                               l_signatureB64))

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "File Added;errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "Invalid Filename Characters;errorCode: invalidFilename"
            elif l_databaseQueryErrorCode == 3:
                msg = "Invalid File Characters;errorCode: invalidFileCharacters"
            elif l_databaseQueryErrorCode == 4:
                msg = "Invalid Signature Characters;errorCode: invalidSignCh"
            elif l_databaseQueryErrorCode == 5:
                msg = "Strange Error Where User Doesn't Have PK;errorCode: wtfHappenedToThePK"
            elif l_databaseQueryErrorCode == 6:
                msg = "Error Importing User PK;errorCode: faultyPK"
            elif l_databaseQueryErrorCode == 7:
                msg = "Faulty Signature;errorCode: invalidSign"
            elif l_databaseQueryErrorCode == 8:
                msg = "Missing Public File List;errorCode: missingPUFL"
            elif l_databaseQueryErrorCode == 9:
                msg = "File exceeds max file size of {0} bytes;maxSize: {0};errorCode: fileTooBig".format(
                    self.databaseManager.maxFileSize)
            elif l_databaseQueryErrorCode == 10:
                msg = "Reached max files: {0};maxFiles: {0};errorCode: maxFilesReached".format(self.databaseManager.maxFiles)
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

                self.send(msg, encrypted=True, key=sessionKey)
                return False

        getPublicFileList = re.search("^getPublicFileList;name: (.+)$", decryptedMessage)

        if getPublicFileList and False:
            l_name = getPublicFileList.group(1)

            l_databaseQueryResult = self.databaseManager.executeFunction("getPublicFileList", (l_name,))
            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "Returning PUFL;pufl: " + l_databaseQueryResult[1] + ";errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "Missing Public File List;errorCode: missingPUFL"
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getHiddenFileList = re.search("^getHiddenFileList;name: (.+);signatureB64: (.+)$", decryptedMessage)

        if getHiddenFileList and False:
            l_name = getHiddenFileList.group(1)
            l_signatureB64 = getHiddenFileList.group(2)

            l_databaseQueryResult = self.databaseManager.executeFunction("getHiddenFileList", (l_name,
                                                                                               l_signatureB64))
            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "Returning HFL;hfl: " + l_databaseQueryResult[1] + ";errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "Missing Hidden File List;errorCode: missingHFL"
            elif l_databaseQueryErrorCode == 3:
                msg = "Invalid Signature Characters;errorCode: invalidSignCh"
            elif l_databaseQueryErrorCode == 4:
                msg = "Strange Error Where User Doesn't Have PK;errorCode: wtfHappenedToThePK"
            elif l_databaseQueryErrorCode == 5:
                msg = "Error Importing User PK;errorCode: faultyPK"
            elif l_databaseQueryErrorCode == 6:
                msg = "Faulty Signature;errorCode: invalidSign"
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getPrivateFileList = re.search("^getPrivateFileList;name: (.+);signatureB64: (.+)$", decryptedMessage)

        if getPrivateFileList and False:
            l_name = getPrivateFileList.group(1)
            l_signatureB64 = getPrivateFileList.group(2)

            l_databaseQueryResult = self.databaseManager.executeFunction("getPrivateFileList", (l_name,
                                                                                                l_signatureB64))
            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "Returning PRFL;prfl: " + l_databaseQueryResult[1] + ";errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "Missing Private File List;errorCode: missingPRFL"
            elif l_databaseQueryErrorCode == 3:
                msg = "Invalid Signature Characters;errorCode: invalidSignCh"
            elif l_databaseQueryErrorCode == 4:
                msg = "Strange Error Where User Doesn't Have PK;errorCode: wtfHappenedToThePK"
            elif l_databaseQueryErrorCode == 5:
                msg = "Error Importing User PK;errorCode: faultyPK"
            elif l_databaseQueryErrorCode == 6:
                msg = "Faulty Signature;errorCode: invalidSign"
            elif l_databaseQueryErrorCode == -1:
                msg = "Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getFile = re.search("^getFile;name: (.+);id: (.+)$", decryptedMessage)

        if getFile and False:
            l_name = getFile.group(1)
            l_id = getFile.group(2)

            l_databaseQueryResult = self.databaseManager.executeFunction("getFile", (l_name, l_id))
            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            msg = ""

            if l_databaseQueryErrorCode == 0:
                pass
            elif l_databaseQueryErrorCode == 1:
                pass
            elif l_databaseQueryErrorCode == 2:
                pass
            elif l_databaseQueryErrorCode == 3:
                pass
            elif l_databaseQueryErrorCode == 4:
                pass
            elif l_databaseQueryErrorCode == 5:
                pass
            elif l_databaseQueryErrorCode == 6:
                pass
            elif l_databaseQueryErrorCode == -1:
                pass

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getPrivateFile = re.search("^getPrivateFile;name: (.+);id: (.+);signatureB64: (.+)$", decryptedMessage)

        if getPrivateFile and False:
            l_name = getPrivateFile.group(1)
            l_id = getPrivateFile.group(2)
            l_signatureB64 = getPrivateFile.group(3)

            l_databaseQueryResult = self.databaseManager.executeFunction("getPrivateFile", (l_name, l_id,
                                                                                            l_signatureB64))
            l_databaseQueryErrorCode = l_databaseQueryResult[0]


        msg = "Invalid Request;errorCode: invalidReq"
        msg = self.encryptWithPadding(sessionKey, msg)[1] + "\r\n"
        self.clientSocket.send(msg)
        return False

    @staticmethod
    def encryptWithPadding(key, plaintext):
        # type: (str, str) -> tuple
        length = (16 - (len(plaintext) % 16)) + 16 * random.randint(0,14)
        plaintextPadded = plaintext + utils.getRandString(length-1) + chr(length)
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, ""
        ciphertext = base64.b64encode(AES.new(key, AES.MODE_ECB).encrypt(plaintextPadded))
        return True, ciphertext

    @staticmethod
    def decryptWithPadding(key, ciphertext):
        # type: (str, str) -> tuple
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, ""
        ciphertextNotB64 = base64.b64decode(ciphertext)
        plaintextPadded = AES.new(key, AES.MODE_ECB).decrypt(ciphertextNotB64)
        plaintext = plaintextPadded[:-ord(plaintextPadded[-1])]
        return True, plaintext

# Code NOT USED
        #createChatReToSearchFor = "^createChat;creatorName: (.+);chatName: (.+);"
        #createChatReToSearchFor += "keys: (.+);firstMsg: (.+);sign: (.+);msgValidationSha: (.+)$"

        #createChat = re.search(createChatReToSearchFor, decryptedMessage)

        #if createChat:
        #    l_creatorName = createChat.group(1)
        #    l_chatName = createChat.group(2)
        #    l_keys = createChat.group(3)
        #    l_firstMsg = createChat.group(4)
        #    l_signature = createChat.group(5)
        #    l_msgValidationSha = createChat.group(6)
        #    l_databaseQueryErrorCode = self.databaseManager.createChat(l_creatorName, l_chatName, l_keys, l_firstMsg,
        #                                                               l_signature, l_msgValidationSha)

        #    msg = ""

        #    if l_databaseQueryErrorCode == 0:
        #        msg = "Chat Created Successfully;errorCode: successful"
        #    elif l_databaseQueryErrorCode == 1:
        #        msg = "Creator Doesn't Exist;errorCode: usrNotFound"
        #    elif l_databaseQueryErrorCode == 2:
        #        msg = "User Without chats;errorCode: wtfHappenedToTheChats"
        #    elif l_databaseQueryErrorCode == 3:
        #        msg = "Invalid Chat Name Characters;errorCode: invalidChatName"
        #    elif l_databaseQueryErrorCode == 4:
        #        msg = "Chat Already Exist;errorCode: chatAlreadyExists"
        #    elif l_databaseQueryErrorCode == 5:
        #        msg = "User Without PK;errorCode: wtfHappenedToThePK"
        #    elif l_databaseQueryErrorCode == 6:
        #        msg = "Invalid Keys Characters;errorCode: invalidKeys"
        #    elif l_databaseQueryErrorCode == 7:
        #        msg = "Faulty Signature;errorCode: invalidSign"
        #    elif l_databaseQueryErrorCode == 8:
        #        msg = "Invalid Number Of Keys;errorCode: invalidKeysNum"
        #    elif l_databaseQueryErrorCode == 9:
        #        msg = "Invalid First Message Characters;errorCode: invalidFirstMsg"
        #    elif l_databaseQueryErrorCode == 10:
        #        msg = "Invalid Message Validation Sha Characters;errorCode: invalidMsgVS"

        #    msg = self.encryptWithPadding(sessionKey, msg)[1] + "\r\n"
        #    self.clientSocket.send(msg)
        #    return False
