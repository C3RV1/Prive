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
            try:
            #if True:
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
            except Exception as e:
                self.log("Error:" + e, error=True)
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

    def send(self, msg, encrypted=False, key=""):
        #type: (str, bool, str) -> None
        self.log("Sending [{}]".format(msg), printOnScreen=False)
        self.log("Sending {}".format(msg.split(';')[0]), saveToFile=False)
        if encrypted:
            msg = self.encryptWithPadding(key, msg)[1] + "\r\n"
        else:
            msg += "\r\n"
        self.clientSocket.send(msg)

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
        showTxt = ""
        for i in range(0, len(decryptedMessage)):
            if decryptedMessage[i] == ';':
                break
            showTxt += decryptedMessage[i]
        self.log("Received: [" + showTxt + "]", saveToFile=False)
        if showTxt != "keepAlive":
            self.log("Received: [" + decryptedMessage + "]", printOnScreen=False)

        if re.search("^quit$", decryptedMessage):
            return True
        if re.search("^keepAlive$", decryptedMessage):
            return False

        newUser = re.search("^newUser;name: (.+);pkB64: (.+);skAesB64: (.+);vtB64: (.+);vtAesB64: (.+)$",
                            decryptedMessage)
        if newUser:
            l_name = newUser.group(1)
            l_pkB64 = utils.base64_decode(newUser.group(2))
            l_skAesB64 = newUser.group(3)
            l_vtShaB64 = newUser.group(4)
            l_vtAesB64 = newUser.group(5)

            # l_databaseQueryErrorCode = self.databaseManager.newUser(l_name, l_pkB64, l_skAesB64, l_vtShaB64, l_vtAesB64)
            l_databaseQueryErrorCode = self.databaseManager.executeFunction("newUser", (l_name,
                                                                                        l_pkB64,
                                                                                        l_skAesB64,
                                                                                        l_vtShaB64,
                                                                                        l_vtAesB64))

            responseDict = {0: "msg: New User Registered!;errorCode: successful",
                            1: "msg: User Already Exists;errorCode: usrAlreadyExists",
                            2: "msg: Invalid Name Characters;errorCode: invalidName",
                            3: "msg: Invalid Private Key Characters;errorCode: invalidSK",
                            4: "msg: Invalid Public Key Characters;errorCode: invalidPK",
                            5: "msg: Invalid Validation Token Characters;errorCode: invalidVT",
                            6: "msg: Invalid Encrypted Validation Token Characters;errorCode: invalidVTEnc",
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getVtAesB64 = re.search("^getVtAesB64;name: (.+)$", decryptedMessage)

        if getVtAesB64:
            l_name = getVtAesB64.group(1)
            # l_databaseQueryResult = self.databaseManager.getVtAesB64(l_name)

            l_databaseQueryResult = self.databaseManager.executeFunction("getVTAesB64", (l_name,))

            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            responseDict = {0: "msg: Returning vtAesB64;vt: " + l_databaseQueryResult[1] + ";errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: User Without VtAesB64;errorCode: userWithoutVtEnc",
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

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

            if l_databaseQueryErrorCode == 0:
                l_skAesB64 = self.databaseManager.executeFunction("getSK", (l_name,))
                l_skAesB64ErrorCode = l_skAesB64[0]

                responseDict = {0: "msg: VT Correct!;sk: " + l_skAesB64[1] + ";errorCode: successful",
                                1: "msg: User Without SK;errorCode: userWithoutSK",
                                2: "msg: User Deleted Before getSK execution;errorCode: userDeletedBeforeExecution",
                                -1: "msg: Server Panic 2!;errorCode: serverPanic2"}

                msg = responseDict.get(l_skAesB64ErrorCode, "msg: Bad Error Code 2;errorCode: badErrorCode2")
            else:
                responseDict = {1: "msg: Incorrect VT;errorCode: incorrect",
                                2: "msg: User Doesn't Exist;errorCode: usrNotFound",
                                3: "msg: User Without VT;errorCode: userWithoutVt",
                                4: "msg: Invalid Validation Token Characters;errorCode: invalidVT",
                                5: "msg: Account Locked;timeBeforeUnlocking: " + str(l_databaseQueryResult[1]) + ";errorCode: accountLocked",
                                -1: "msg: Server Panic!;errorCode: serverPanic"}

                msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getPk = re.search("^getPK;name: (.+)$", decryptedMessage)

        if getPk:
            l_name = getPk.group(1)

            l_databaseQueryResult = self.databaseManager.executeFunction("getPK", (l_name,))

            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            responseDict = {0: "msg: Returning pk;pk: " + l_databaseQueryResult[1] + ";errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: User Without PK;errorCode: userWithoutPK"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        delUser = re.search("^delUser;name: (.+);signatureB64: (.+)$",decryptedMessage)

        if delUser:
            l_name = delUser.group(1)
            l_signatureB64 = delUser.group(2)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("delUser", (l_name, l_signatureB64))

            responseDict = {0: "msg: User Deleted Successfully;errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: User Without PK;errorCode: userWithoutPK",
                            3: "msg: Invalid Signature Characters;errorCode: invalidSignCh",
                            4: "msg: Faulty Signature;errorCode: invalidSign",
                            5: "msg: Error Importing User PK;errorCode: faultyPK",
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        updateKeys = re.search("^updateKeys;name: (.+);signatureB64: (.+);newPKB64: (.+);newSKAesB64: (.+);newVTSha: " +
                               "(.+);newVTEnc: (.+)$",
                               decryptedMessage)

        if updateKeys:
            l_name = updateKeys.group(1)
            l_signatureB64 = updateKeys.group(2)
            l_newPK = updateKeys.group(3)
            l_newSKAesB64 = updateKeys.group(4)
            l_newVTSha = updateKeys.group(5)
            l_newVTEnc = updateKeys.group(6)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("updateKeys", (l_name,
                                                                                           l_signatureB64,
                                                                                           l_newPK,
                                                                                           l_newSKAesB64,
                                                                                           l_newVTSha,
                                                                                           l_newVTEnc))

            responseDict = {0: "msg: Keys Updated;errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: Invalid Signature Characters;errorCode: invalidSignCh",
                            3: "msg: Invalid newSKAesB64 Characters;errorCode: invalidNewSKAesB64",
                            4: "msg: Invalid newPK Format or Characters;errorCode: invalidNewPK",
                            5: "msg: Invalid Validation Token Sha Characters;errorCode: invalidVTSha",
                            6: "msg: Invalid Validation Token Encrypted Characters;errorCode: invalidVTEnc",
                            7: "msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                            8: "msg: Error Importing User PK;errorCode: faultyPK",
                            9: "msg: Faulty Signature;errorCode: invalidSign",
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        addPublicFile = re.search("^addPublicFile;name: (.+);fileNameB64: (.+);fileB64: (.+);signatureB64: (.+)$",
                                  decryptedMessage)

        if addPublicFile:
            l_name = addPublicFile.group(1)
            l_fileNameB64 = addPublicFile.group(2)
            l_fileB64 = addPublicFile.group(3)
            l_signatureB64 = addPublicFile.group(4)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("addPublicFile", (l_name, l_fileNameB64,
                                                                                              l_fileB64,
                                                                                              l_signatureB64))

            responseDict = {0: "msg: File Added;errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: Invalid Filename Characters;errorCode: invalidFilename",
                            3: "msg: Invalid File Characters;errorCode: invalidFileCharacters",
                            4: "msg: Invalid Signature Characters;errorCode: invalidSignCh",
                            5: "msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                            6: "msg: Error Importing User PK;errorCode: faultyPK",
                            7: "msg: Faulty Signature;errorCode: invalidSign",
                            8: "msg: Missing Public File List;errorCode: missingPUFL",
                            9: "msg: File exceeds max file size of {0} bytes;maxSize: {0};errorCode: fileTooBig".format(
                                self.databaseManager.maxFileSize),
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        addHiddenFile = re.search("^addHiddenFile;name: (.+);fileNameB64: (.+);fileB64: (.+);signatureB64: (.+)$",
                                  decryptedMessage)

        if addHiddenFile:
            l_name = addHiddenFile.group(1)
            l_fileNameB64 = addHiddenFile.group(2)
            l_fileB64 = addHiddenFile.group(3)
            l_signatureB64 = addHiddenFile.group(4)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("addHiddenFile", (l_name, l_fileNameB64,
                                                                                              l_fileB64,
                                                                                              l_signatureB64))

            responseDict = {0: "msg: File Added;errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: Invalid Filename Characters;errorCode: invalidFilename",
                            3: "msg: Invalid File Characters;errorCode: invalidFileCharacters",
                            4: "msg: Invalid Signature Characters;errorCode: invalidSignCh",
                            5: "msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                            6: "msg: Error Importing User PK;errorCode: faultyPK",
                            7: "msg: Faulty Signature;errorCode: invalidSign",
                            8: "msg: Missing Hidden File List;errorCode: missingHFL",
                            9: "msg: File exceeds max file size of {0} bytes;maxSize: {0};errorCode: fileTooBig".format(
                                self.databaseManager.maxFileSize),
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        addPrivateFile = re.search("^addPrivateFile;name: (.+);fileNameB64: (.+);fileB64: (.+);signatureB64: (.+)$",
                                   decryptedMessage)

        if addPrivateFile:
            l_name = addPrivateFile.group(1)
            l_fileNameB64 = addPrivateFile.group(2)
            l_fileB64 = addPrivateFile.group(3)
            l_signatureB64 = addPrivateFile.group(4)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("addPrivateFile", (l_name, l_fileNameB64,
                                                                                               l_fileB64,
                                                                                               l_signatureB64))

            responseDict = {0: "msg: File Added;errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: Invalid Filename Characters;errorCode: invalidFilename",
                            3: "msg: Invalid File Characters;errorCode: invalidFileCharacters",
                            4: "msg: Invalid Signature Characters;errorCode: invalidSignCh",
                            5: "msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                            6: "msg: Error Importing User PK;errorCode: faultyPK",
                            7: "msg: Faulty Signature;errorCode: invalidSign",
                            8: "msg: Missing Private File List;errorCode: missingPRFL",
                            9: "msg: File exceeds max file size of {0} bytes;maxSize: {0};errorCode: fileTooBig".format(
                                self.databaseManager.maxFileSize),
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getPublicFileList = re.search("^getPublicFileList;name: (.+)$", decryptedMessage)

        if getPublicFileList:
            l_name = getPublicFileList.group(1)

            l_databaseQueryResult = self.databaseManager.executeFunction("getPublicFileList", (l_name,))
            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            responseDict = {0: "msg: Returning PUFL;pufl: " + l_databaseQueryResult[1] + ";errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: Missing Public File List;errorCode: missingHFL",
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getHiddenFileList = re.search("^getHiddenFileList;name: (.+);signatureB64: (.+)$", decryptedMessage)

        if getHiddenFileList:
            l_name = getHiddenFileList.group(1)
            l_signatureB64 = getHiddenFileList.group(2)

            l_databaseQueryResult = self.databaseManager.executeFunction("getHiddenFileList", (l_name,
                                                                                               l_signatureB64))
            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            responseDict = {0: "msg: Returning HFL;hfl: " + l_databaseQueryResult[1] + ";errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: Missing Hidden File List;errorCode: missingHFL",
                            3: "msg: Invalid Signature Characters;errorCode: invalidSignCh",
                            4: "msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                            5: "msg: Error Importing User PK;errorCode: faultyPK",
                            6: "msg: Faulty Signature;errorCode: invalidSign",
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getPrivateFileList = re.search("^getPrivateFileList;name: (.+);signatureB64: (.+)$", decryptedMessage)

        if getPrivateFileList:
            l_name = getPrivateFileList.group(1)
            l_signatureB64 = getPrivateFileList.group(2)

            l_databaseQueryResult = self.databaseManager.executeFunction("getPrivateFileList", (l_name,
                                                                                                l_signatureB64))
            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            responseDict = {0: "msg: Returning PRFL;prfl: " + l_databaseQueryResult[1] + ";errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: Missing Private File List;errorCode: missingPRFL",
                            3: "msg: Invalid Signature Characters;errorCode: invalidSignCh",
                            4: "msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                            5: "msg: Error Importing User PK;errorCode: faultyPK",
                            6: "msg: Faulty Signature;errorCode: invalidSign",
                            -1: "msg: Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getFile = re.search("^getFile;name: (.+);id: (.+)$", decryptedMessage)

        if getFile:
            l_name = getFile.group(1)
            l_id = getFile.group(2)

            l_databaseQueryResult = self.databaseManager.executeFunction("getFile", (l_name, l_id))
            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            responseDict = {0: "msg: Returning fileB64;fileB64: " + l_databaseQueryResult[1] + ";errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: Missing Public File List;errorCode: missingPUFL",
                            3: "msg: Missing Hidden File List;errorCode: missingHFL",
                            4: "msg: Invalid Id Characters;errorCode: invalidIdCh",
                            5: "msg: File in a list but nonexistent;errorCode: fileInListButNonexistent",
                            6: "msg: File not found;errorCode: fileNotFound",
                            -1: "msg: Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        getPrivateFile = re.search("^getPrivateFile;name: (.+);id: (.+);signatureB64: (.+)$", decryptedMessage)

        if getPrivateFile:
            l_name = getPrivateFile.group(1)
            l_id = getPrivateFile.group(2)
            l_signatureB64 = getPrivateFile.group(3)

            l_databaseQueryResult = self.databaseManager.executeFunction("getPrivateFile", (l_name, l_id,
                                                                                            l_signatureB64))
            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            responseDict = {0: "msg: Returning fileB64;fileB64: " + l_databaseQueryResult[1] + ";errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: Strange Error Where User Doesn't Have PK;errorCode: wtfHappenedToThePK",
                            3: "msg: Invalid Signature Characters;errorCode: invalidSignCh",
                            4: "msg: Invalid Id Characters;errorCode: invalidIdCh",
                            5: "msg: Missing Private File List;errorCode: missingPRFL",
                            6: "msg: Error Importing User PK;errorCode: faultyPK",
                            7: "msg: Faulty Signature;errorCode: invalidSign",
                            8: "msg: File not found;errorCode: fileNotFound",
                            9: "msg: File in a list but nonexistent;errorCode: fileInListButNonexistent",
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        deleteFile = re.search("^deleteFile;name: (.+);id: (.+);signatureB64: (.+)$", decryptedMessage)

        if deleteFile:
            l_name = deleteFile.group(1)
            l_id = deleteFile.group(2)
            l_signatureB64 = deleteFile.group(3)

            l_databaseQueryErrorCode = self.databaseManager.executeFunction("deleteFile", (l_name, l_id,
                                                                                           l_signatureB64))

            self.log("l_databaseQueryErrorCode on deleteFile: {}".format(l_databaseQueryErrorCode),debug=True)

            responseDict = {0: "msg: File Deleted;errorCode: successful",
                            1: "msg: User Doesn't Exist;errorCode: usrNotFound",
                            2: "msg: Invalid Signature Characters;errorCode: invalidSignCh",
                            3: "msg: Invalid Id Characters;errorCode: invalidIdCh",
                            4: "msg: Missing Public File List;errorCode: missingPUFL",
                            5: "msg: Missing Hidden File List;errorCode: missingHFL",
                            6: "msg: Missing Private File List;errorCode: missingPRFL",
                            7: "msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                            8: "msg: Error Importing User PK;errorCode: faultyPK",
                            9: "msg: Faulty Signature;errorCode: invalidSign",
                            10: "msg: File not found;errorCode: fileNotFound",
                            11: "msg: File in a list but nonexistent;errorCode: fileInListButNonexistent",
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(l_databaseQueryErrorCode, "msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=sessionKey)
            return False

        msg = "msg: Invalid Request;errorCode: invalidReq"
        self.send(msg, encrypted=True, key=sessionKey)
        return False

    @staticmethod
    def encryptWithPadding(key, plaintext):
        # type: (str, str) -> tuple
        length = (16 - (len(plaintext) % 16)) + 16 * random.randint(0,14)
        plaintextPadded = plaintext + utils.getRandString(length-1) + chr(length)
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, ""
        ciphertext = utils.base64_encode(AES.new(key, AES.MODE_ECB).encrypt(plaintextPadded))
        return True, ciphertext

    @staticmethod
    def decryptWithPadding(key, ciphertext):
        # type: (str, str) -> tuple
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, ""
        ciphertextNotB64 = utils.base64_decode(ciphertext)
        plaintextPadded = AES.new(key, AES.MODE_ECB).decrypt(ciphertextNotB64)
        plaintext = plaintextPadded[:-ord(plaintextPadded[-1])]
        return True, plaintext
