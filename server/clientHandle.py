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


class Timeout(threading.Thread):
    def __init__(self, sock, clientAddr, timeoutList, timeout, databaseManager):
        # type: (socket.socket, tuple, list, int, databaseManager.DatabaseManager) -> None
        self.databaseManager = databaseManager
        self.clientAddr = clientAddr
        self.log("Starting Timeout Thread on Client " + clientAddr[0] + " " + str(clientAddr[1]))
        threading.Thread.__init__(self)
        self.socket = sock
        self.timeoutList = timeoutList
        self.timeout = timeout

    def log(self, msg, printOnScreen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.databaseManager.logger.log("[ClientHandlerTimeout:" + self.clientAddr[0] + ":" + str(self.clientAddr[1]) +
                                        "] " + msg, printToScreen=printOnScreen, debug=debug)

    def run(self):
        while True and not self.timeoutList[1]:
            if self.timeoutList[0] > self.timeout:
                self.log("Client " + self.clientAddr[0] + " " + str(self.clientAddr[1]) + " has reached the timeout")
                self.socket.close()
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
        self.timeOutController = Timeout(self.clientSocket, self.clientAddress, self.timeoutList, timeout, databaseManager)
        self.timeOutController.start()

    def run(self):
        while True:
            try:
                data = ""
                while True:
                    newData = self.clientSocket.recv(4096)
                    data = data + newData
                    if re.search("\r\n", newData):
                        break
                if self.handleMessage(data):
                    break
                if not self.serverMaster.running.returnRunning():
                    self.clientSocket.send("quit\r\n")
                    break
            except Exception as e:
                self.log("Error Receiving Client: " + str(self.clientAddress[0]) + " " + str(self.clientAddress[1]))
                if type(e.message) == str:
                    self.log("Error Msg: " + e.message)
                else:
                    self.log("Error Msg not String")
                break
        self.databaseManager.deleteSessionKey(self.clientAddress[0], self.clientAddress[1])
        self.log("Closing Client: " + str(self.clientAddress[0]) + " " + str(self.clientAddress[1]))
        try:
            self.clientSocket.close()
        except Exception:
            self.log("Client Already Closed")
        self.log("Removing Timeout")
        self.timeOutController = None
        self.log("Removing Self")
        self.serverMaster.deleteClientThread(self)
        self.timeoutList[1] = True

    def log(self, msg, printOnScreen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.databaseManager.logger.log("[ClientHandler:" + self.clientAddress[0] + ":" + str(self.clientAddress[1]) +
                                        "] " + msg, printToScreen=printOnScreen, debug=debug)
        pass

    def handleMessage(self, data):
        self.timeoutList[0] = 0
        data = data[:-2]
        self.log("Received from client " + self.clientAddress[0] + " " + str(self.clientAddress[1]) + " : " + repr(data))
        if re.search("^quit$", data):
            return True
        sessionKeyRe = re.search("^sessionkey: (.*)$", data)
        sessionKey = self.databaseManager.getSessionKey(self.clientAddress[0], self.clientAddress[1])
        if sessionKeyRe:
            if not sessionKey[0]:
                validSEK = self.databaseManager.newSessionKey(self.clientAddress[0], self.clientAddress[1],
                                                                    sessionKeyRe.group(1))
                if not validSEK:
                    self.clientSocket.send("Invalid Session Key;errorCode: invalid\r\n")
                else:
                    self.clientSocket.send("Session Key Updated;errorCode: successful\r\n")
                return False
            else:
                self.clientSocket.send("Already Session Key;errorCode: already\r\n")
                return False

        if not sessionKey[0]:
            self.clientSocket.send("No Session Key\r\n")
            return False

        sessionKey = sessionKey[1]

        decryptedMessage = self.decryptWithPadding(sessionKey, data)[1]
        self.log("Client Message Decrypted: " + decryptedMessage)

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
            l_databaseQueryResult = self.databaseManager.newUser(l_name, l_pkB64, l_skAesB64, l_vtShaB64, l_vtAesB64)
            if l_databaseQueryResult == 0:
                msg = "New User Registered!;errorCode: successful"
            elif l_databaseQueryResult == 1:
                msg = "User Already Exists;errorCode: usrAlreadyExists"
            elif l_databaseQueryResult == 2:
                msg = "Invalid Name Characters;errorCode: invalidName"
            elif l_databaseQueryResult == 3:
                msg = "Invalid Private Key Characters;errorCode: invalidSK"
            elif l_databaseQueryResult == 4:
                msg = "Invalid Public Key Characters;errorCode: invalidPK"
            elif l_databaseQueryResult == 5:
                msg = "Invalid Validation Token Characters;errorCode: invalidVT"
            elif l_databaseQueryResult == 6:
                msg = "Invalid Encrypted Validation Token Characters;errorCode: invalidVTEnc"
            msg = self.encryptWithPadding(sessionKey, msg)[1] + "\r\n"
            self.clientSocket.send(msg)
            return False

        getVtAesB64 = re.search("^getVtAesB64;name: (.+)$", decryptedMessage)

        if getVtAesB64:
            l_name = getVtAesB64.group(1)
            l_databaseQueryResult = self.databaseManager.getVtAesB64(l_name)
            l_databaseQueryErrorCode = l_databaseQueryResult[0]
            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "vtAesB64;vt: " + l_databaseQueryResult[1] + ";errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "User Without VtAESB64;errorCode: wtfHappenedToTheVTEnc"

            msg = self.encryptWithPadding(sessionKey, msg)[1] + "\r\n"
            self.clientSocket.send(msg)
            return False

        checkVT = re.search("^checkVT;name: (.+);vt: (.+);newVTSha: (.+);newVTEnc: (.+)$", decryptedMessage)

        if checkVT:
            l_name = checkVT.group(1)
            l_vtB64 = checkVT.group(2)
            l_newVTSha = checkVT.group(3)
            l_newVTEnc = checkVT.group(4)
            l_databaseQueryResult = self.databaseManager.checkVt(l_name, l_vtB64, self.clientAddress[0],
                                                                 l_newVTSha, l_newVTEnc)
            l_databaseQueryErrorCode = l_databaseQueryResult[0]
            msg = ""

            if l_databaseQueryErrorCode == 0:
                l_skAesB64 = self.databaseManager.getSk_(l_name)
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

            msg = self.encryptWithPadding(sessionKey, msg)[1] + "\r\n"
            self.clientSocket.send(msg)
            return False

        getPk = re.search("^getPK;name: (.+)$", decryptedMessage)

        if getPk:
            l_name = getPk.group(1)
            l_databaseQueryResult = self.databaseManager.getPk(l_name)
            l_databaseQueryErrorCode = l_databaseQueryResult[0]

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "pk;pk: " + l_databaseQueryResult[1] + ";errorCode: successful"
            elif l_databaseQueryErrorCode == 1:
                msg = "User Doesn't Exist;errorCode: usrNotFound"
            elif l_databaseQueryErrorCode == 2:
                msg = "User Without PK;errorCode: wtfHappenedToThePK"

            msg = self.encryptWithPadding(sessionKey, msg)[1] + "\r\n"
            self.clientSocket.send(msg)
            return False

        delUser = re.search("^delUser;name: (.+);sign: (.+)$",decryptedMessage)

        if delUser:
            l_name = delUser.group(1)
            l_signature = delUser.group(2)
            l_databaseQueryErrorCode = self.databaseManager.delUser(l_name, l_signature)

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "User Deleted Successful;errorCode: successful"
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

            msg = self.encryptWithPadding(sessionKey, msg)[1] + "\r\n"
            self.clientSocket.send(msg)
            return False

        updateKeys = re.search("^updateKeys;name: (.+);signatureB64: (.+);newPKB64: (.+);newSKAesB64: (.+)$",
                               decryptedMessage)

        if updateKeys:
            l_name = updateKeys.group(1)
            l_signatureB64 = updateKeys.group(2)
            l_newPK = updateKeys.group(3)
            l_newSKAesB64 = updateKeys.group(4)

            l_databaseQueryErrorCode = self.databaseManager.updateKeys(l_name, l_signatureB64, l_newPK, l_newSKAesB64)

            msg = ""

            if l_databaseQueryErrorCode == 0:
                msg = "Keys Updated!;errorCode: successful"
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

            msg = self.encryptWithPadding(sessionKey, msg)[1] + "\r\n"
            self.clientSocket.send(msg)
            return False

        msg = "Invalid Request;errorCode: invalidReq"
        msg = self.encryptWithPadding(sessionKey, msg)[1] + "\r\n"
        self.clientSocket.send(msg)
        return False

    @staticmethod
    def encryptWithPadding(key, plaintext):
        # type: (str, str) -> tuple
        length = (16 - (len(plaintext) % 16)) + 16 * random.randint(0,14)
        plaintextPadded = plaintext + ClientHandle.getRandString(length-1) + chr(length)
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, ""
        ciphertext = base64.b64encode(AES.new(key, AES.MODE_CFB).encrypt(plaintextPadded))
        return True, ciphertext

    @staticmethod
    def decryptWithPadding(key, ciphertext):
        # type: (str, str) -> tuple
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, ""
        ciphertextNotB64 = base64.b64decode(ciphertext)
        plaintextPadded = AES.new(key, AES.MODE_CFB).decrypt(ciphertextNotB64)
        plaintext = plaintextPadded[:-ord(plaintextPadded[-1])]
        return True, plaintext

    @staticmethod
    def getRandString(len):
        # type: (int) -> str
        returnString = ""
        for x in range(0, len):
            returnString += get_random_bytes(1)
        return returnString

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
