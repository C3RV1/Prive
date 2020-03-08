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
import os
import shutil
import clientHandle
from config import Config


class Timeout(threading.Thread):
    def __init__(self, clientHandlerMaster, sock, clientAddr, timeout, databaseManager):
        # type: (FileSend, socket.socket, tuple, int, databaseManager.DatabaseManager) -> None
        self.databaseManager = databaseManager
        self.clientAddr = clientAddr
        self.log("Starting Timeout Thread on ClientFT " + clientAddr[0] + " " + str(clientAddr[1]), printOnScreen=False)
        threading.Thread.__init__(self)
        self.socket = sock
        self.startTimeout = time.time()
        self.timeoutEvent = threading.Event()
        self.timeout = timeout
        self.clientHandlerMaster = clientHandlerMaster

    def log(self, msg, printOnScreen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.databaseManager.logger.log("Client.FS.Timeout:" + self.clientAddr[0] + ":" + str(self.clientAddr[1]),
                                        msg, printToScreen=printOnScreen, debug=debug)

    def stop(self):
        self.timeoutEvent.set()

    def resetTime(self):
        self.startTimeout = time.time()

    def run(self):
        while not self.timeoutEvent.is_set():
            if time.time() - self.startTimeout >= self.timeout:
                self.log("ClientFS " + self.clientAddr[0] + " " + str(self.clientAddr[1]) + " has reached the timeout",
                         printOnScreen=False)
                self.clientHandlerMaster.clientHandle.closeAll()
                self.clientHandlerMaster.endTransmission()
                break
            time.sleep(1)
        self.log("Exiting Timeout", printOnScreen=False)


class FileSend(threading.Thread):

    def __init__(self, clientHandler, path):
        # type: (clientHandle.ClientHandle, str) -> None
        threading.Thread.__init__(self)
        self.clientSocket = clientHandler.clientSocket
        self.clientAddress = clientHandler.clientAddress
        self.databaseManager = clientHandler.databaseManager
        self.serverMaster = clientHandler.serverMaster
        self.timeoutList = [0, False]  # Because all instances share the same object
        self.timeOutController = Timeout(self, self.clientSocket, self.clientAddress,
                                         clientHandler.timeOutController.timeout, self.databaseManager)
        self.timeOutController.start()
        self.runningEvent = threading.Event()

        self.clientHandle = clientHandler
        self.clientHandle.recvEvent.set()

        self.path = path
        self.segment = 0

    def run(self):
        self.log("Starting file sending", printOnScreen=False)
        while not self.runningEvent.is_set():
            try:
                data = ""
                while True:
                    newData = self.clientSocket.recv(4096)
                    data = data + newData
                    if re.search("\r\n", newData):
                        break

                    # ANTI MEMORY LEAK
                    if len(data) > len("keepAlive\r\n"):
                        break
                if self.runningEvent.is_set():
                    break
                if self.handleMessage(data):
                    break
                if not self.serverMaster.running.returnRunning():
                    self.send("quit")
                    self.clientHandle.closeAll()
                    break
            except Exception as e:
                self.log("Error:" + str(e), error=True)
                self.clientHandle.closeAll()
                return self.endTransmission()
        return self.endTransmission()

    def endTransmission(self):
        if self.runningEvent.is_set():
            return
        self.runningEvent.set()
        self.log("Ending transmission", printOnScreen=False)
        self.log("Removing Timeout", printOnScreen=False)
        self.timeOutController.stop()
        try:
            self.timeOutController.join()
        except:
            pass
        self.timeOutController = None
        self.clientHandle.recvEvent.clear()
        return None

    def log(self, msg, printOnScreen=True, debug=False, error=False, saveToFile=True):
        # type: (str, bool, bool, bool, bool) -> None
        self.databaseManager.logger.log(
            "ClientFileSend:" + self.clientAddress[0] + ":" + str(self.clientAddress[1]),
            msg, printToScreen=printOnScreen, debug=debug, error=error, saveToFile=saveToFile)

    def send(self, msg, encrypted=False, key=""):
        # type: (str, bool, str) -> None
        showTxt = msg.split(';')[0]
        #if showTxt != "msg: Sending Segment":
        #    self.log("Sending {}".format(showTxt), saveToFile=False)
        if encrypted:
            msg = self.encryptWithPadding(key, msg)[1] + "\r\n"
        else:
            msg += "\r\n"
        self.clientSocket.send(msg)

    def handleMessage(self, data):
        # Reset timeout time
        self.timeOutController.resetTime()

        # Remove \r\n from message
        data = data[:-2]

        if re.search("^quit$", data):
            return True

        # Get session key if exists
        sessionKey = self.databaseManager.getSessionKey(self.clientAddress[0], self.clientAddress[1])

        sessionKey = sessionKey[1]

        decryptedMessage = self.decryptWithPadding(sessionKey, data)[1]
        showTxt = ""
        for i in range(0, len(decryptedMessage)):
            if decryptedMessage[i] == ';':
                break
            showTxt += decryptedMessage[i]
        if showTxt != "keepAlive" and showTxt != "segment":
            self.log("Received: [" + decryptedMessage + "]", printOnScreen=False)

        if re.search("^quit$", decryptedMessage):
            return True
        if re.search("^keepAlive$", decryptedMessage):
            return False

        segment = re.search("^segment$", decryptedMessage)

        if segment:
            result = self.handleSegment()
            errorCode = result[1]

            responseDict = {0: "msg: Sending Segment;segment: {};data: {};errorCode: successful".format(result[3],
                                                                                                        result[2]),
                            1: "msg: All Segments Sent;errorCode: allSent",
                            2: "msg: File May Have Been Deleted While Reading;errorCode: fileError",
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(errorCode, "msg: Bad Error Code;errorCode: badErrorCode")
            self.send(msg, encrypted=True, key=sessionKey)
            return result[0]

        msg = "msg: Invalid Request;errorCode: invalidReq"
        self.send(msg, encrypted=True, key=sessionKey)
        return False

    @staticmethod
    def encryptWithPadding(key, plaintext):
        # type: (str, str) -> tuple
        length = (16 - (len(plaintext) % 16)) + 16 * random.randint(0, 14)
        plaintextPadded = plaintext + utils.getRandString(length - 1) + chr(length)
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

    def handleSegment(self):
        try:
            f = open(self.path, "rb")
            f.seek(self.segment*Config.FILE_SEND_CHUNKS*4)
            fileData = f.read(Config.FILE_SEND_CHUNKS*4)
            self.segment += 1
            f.close()
            if fileData == "":
                return True, 1, fileData, self.segment
            else:
                return False, 0, fileData, self.segment
        except:
            return True, 2, "", self.segment
