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
    def __init__(self, clientHandlerMaster, sock, clientAddr, databaseManager):
        # type: (FileTransfer, socket.socket, tuple, databaseManager.DatabaseManager) -> None
        self.databaseManager = databaseManager
        self.clientAddr = clientAddr
        self.log("Starting Timeout Thread on ClientFT " + clientAddr[0] + " " + str(clientAddr[1]), printOnScreen=False)
        threading.Thread.__init__(self)
        self.socket = sock
        self.startTimeout = time.time()
        self.timeoutEvent = threading.Event()
        self.timeout = Config.CLIENT_TIMEOUT
        self.clientHandlerMaster = clientHandlerMaster

    def log(self, msg, printOnScreen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.databaseManager.logger.log("Client.FT.Timeout:" + self.clientAddr[0] + ":" + str(self.clientAddr[1]),
                                        msg, printToScreen=printOnScreen, debug=debug)

    def stop(self):
        self.timeoutEvent.set()

    def resetTime(self):
        self.startTimeout = time.time()

    def run(self):
        while not self.timeoutEvent.is_set():
            if time.time() - self.startTimeout >= self.timeout:
                self.log("ClientFT " + self.clientAddr[0] + " " + str(self.clientAddr[1]) + " has reached the timeout",
                         printOnScreen=False)
                self.clientHandlerMaster.clientHandle.closeAll()
                self.clientHandlerMaster.endTransmission()
                break
            time.sleep(1)
        self.log("Exiting Timeout", printOnScreen=False)


class FileTransfer(threading.Thread):

    def __init__(self, clientSocket, clientAddress, databaseManager, serverMaster, tmpFolder, recvSize, endFilePath,
                 clientHandle, listPath, listData):
        #type: (socket.socket, tuple, databaseManager.DatabaseManager, server.Server, str, int, str, clientHandle.ClientHandle, str, str) -> None
        threading.Thread.__init__(self)
        self.clientSocket = clientSocket
        self.clientAddress = clientAddress
        self.databaseManager = databaseManager
        self.serverMaster = serverMaster
        self.timeoutList = [0, False]  # Because all instances share the same object
        self.timeOutController = Timeout(self, self.clientSocket, self.clientAddress, databaseManager)
        self.timeOutController.start()
        self.runningEvent = threading.Event()

        self.clientHandle = clientHandle
        self.clientHandle.recvEvent.set()

        self.currentlyReceived = 0
        self.tmpFolder = tmpFolder
        self.recvSize = recvSize
        self.endFilePath = endFilePath
        self.transmissionCompleted = False

        self.listPath = listPath
        self.listData = listData

    def run(self):
        self.log("Starting file transmission", printOnScreen=False)
        while not self.runningEvent.is_set():
            try:
                data = ""
                while True:
                    newData = self.clientSocket.recv(4096)
                    data = data + newData
                    if re.search("\r\n", newData):
                        #self.log("Normal data read", debug=True)
                        break

                    # ANTI MEMORY LEAK
                    if len(data) > utils.fromByteToB64Length(Config.FILE_SEND_CHUNKS * 4 + len("segment;num: ;data: ") + len("00000000")):
                        #self.log("Maximum reached (Length {}, Max: {})".format(len(data),
                        #                                                       utils.fromByteToB64Length(Config.FILE_SEND_CHUNKS * 4 + len("segment;num: ;data: ") + len("00000000"))),
                        #         debug=True)
                        break
                if self.runningEvent.is_set():
                    break
                if self.handleMessage(data):
                    if not self.transmissionCompleted:
                        self.clientHandle.closeAll()
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
        try:
            shutil.rmtree(self.tmpFolder[:-1])
        except:
            pass
        self.timeOutController.stop()
        try:
            self.timeOutController.join()
        except:
            pass
        self.timeOutController = None
        self.clientHandle.recvEvent.clear()
        return self.transmissionCompleted

    def log(self, msg, printOnScreen=True, debug=False, error=False, saveToFile=True):
        # type: (str, bool, bool, bool, bool) -> None
        self.databaseManager.logger.log("ClientFileTransfer:" + self.clientAddress[0] + ":" + str(self.clientAddress[1]),
                                        msg, printToScreen=printOnScreen, debug=debug, error=error, saveToFile=saveToFile)

    def send(self, msg, encrypted=False, key=""):
        #type: (str, bool, str) -> None
        showTxt = msg.split(';')[0]
        #if showTxt != "msg: Segment Received Correctly":
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

        # Check if session key message
        sessionKeyRe = re.search("^sessionkey: (.*)$", data)

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

        segment = re.search("^segment;num: ([0-9]+);data: (.+)$", decryptedMessage)

        if segment:
            segmentNum = segment.group(1)
            data = segment.group(2)

            result = self.handleSegment(segmentNum, data)
            errorCode = result[1]

            if errorCode == 4:
                self.completeTransmission()

            responseDict = {0: "msg: Segment Received Correctly;errorCode: successful",
                            1: "msg: Segment Already Exists;errorCode: segmentAlreadyExists",
                            2: "msg: Invalid Data Characters;errorCode: invalidDataCh",
                            3: "msg: Invalid Data Chunk;errorCode: invalidDataCk",
                            4: "msg: Data Transmission Finished;errorCode: successful",
                            -1: "msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(errorCode, "msg: Bad Error Code;errorCode: badErrorCode")
            self.send(msg, encrypted=True, key=sessionKey)
            return result[0]

        msg = "msg: Invalid Request;errorCode: invalidReq"
        self.send(msg, encrypted=True, key=sessionKey)
        return True

    @staticmethod
    def encryptWithPadding(key, plaintext):
        # type: (str, str) -> tuple
        length = (16 - (len(plaintext) % 16)) + 16 * random.randint(0,14)
        plaintextPadded = plaintext + utils.getRandString(length-1) + chr(length)
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, ""
        try:
            ciphertext = utils.base64_encode(AES.new(key, AES.MODE_ECB).encrypt(plaintextPadded))
        except:
            return False, ""
        return True, ciphertext

    @staticmethod
    def decryptWithPadding(key, ciphertext):
        # type: (str, str) -> tuple
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, ""
        if not utils.isBase64(ciphertext):
            return False, ""
        ciphertextNotB64 = utils.base64_decode(ciphertext)
        try:
            plaintextPadded = AES.new(key, AES.MODE_ECB).decrypt(ciphertextNotB64)
        except:
            return False, ""
        plaintext = plaintextPadded[:-ord(plaintextPadded[-1])]
        return True, plaintext

    def handleSegment(self, segmentNum, data):
        if os.path.isfile("{}tmp-{}.tfd".format(self.tmpFolder, segmentNum)):
            return False, 1

        if not utils.isBase64(data):
            return True, 2

        if re.search("=$", data) and self.currentlyReceived + len(data) < self.recvSize:
            return True, 3

        self.currentlyReceived += len(data)

        tmpFile = open("{}tmp-{}.tfd".format(self.tmpFolder, segmentNum), "wb")
        tmpFile.write(data)
        tmpFile.close()

        if self.currentlyReceived >= self.recvSize:
            return True, 4

        return False, 0

    def completeTransmission(self):
        self.log("Transmission is being completed", printOnScreen=False)
        self.databaseManager.databaseLock.acquire()
        listOfSegments = os.listdir(self.tmpFolder)
        listOfSegmentsNum = []
        for segment in listOfSegments:
            group = re.search("^tmp-([0-9]+).tfd$", segment)
            if group:
                listOfSegmentsNum.append(int(group.group(1)))
        listOfSegmentsNum.sort()

        outputFile = open(self.endFilePath, "wb")
        for segmentNum in listOfSegmentsNum:
            openSegmentFile = open("{}tmp-{}.tfd".format(self.tmpFolder, segmentNum), "rb")
            outputFile.write(openSegmentFile.read())
            openSegmentFile.close()
        outputFile.close()

        self.transmissionCompleted = True

        fileList = open(self.listPath, "ab")
        fileList.write(self.listData)
        fileList.close()
        
        self.databaseManager.databaseLock.release()
