from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Sig
import base64
import os
import re
import logger
import time
import shutil
import generateKeys
import utils
import math
import threading
import server

# ALL file management is done in this file and in generateKeys.py

class DatabaseManager(threading.Thread):

    def __init__(self, databaseDirectory, logFile, unacceptedNameCharacters, keySize, maxFileSize, serverMaster):
        #type: (str, str, str, int, int, server.Server) -> None
        threading.Thread.__init__(self)
        self.databaseDirectory = databaseDirectory
        self.unacceptedNameCharacters = unacceptedNameCharacters

        if not os.path.isdir(self.databaseDirectory):
            os.mkdir(self.databaseDirectory)
        if not os.path.isdir(self.databaseDirectory + "/Profiles"):
            os.mkdir(self.databaseDirectory + "/Profiles")
        if not os.path.isdir(self.databaseDirectory + "/SessionKeys"):
            os.mkdir(self.databaseDirectory + "/SessionKeys")
        #if not os.path.isdir(self.databaseDirectory + "\\Chats"):
        #    os.mkdir(self.databaseDirectory + "\\Chats")

        privateKeyPath = self.databaseDirectory + "/privateKey.skm"  # Private Key Master

        if not os.path.isfile(privateKeyPath):
            print "Private key not found"
            print "Creating private key"
            genKeyObj = generateKeys.GenerateKeys(self.databaseDirectory, keySize)
            genKeyObj.generate()

        privateKeyFile = open(privateKeyPath, "r")
        privateKeyStr = privateKeyFile.read()
        self.privateKey = RSA.importKey(privateKeyStr)

        self.databaseLock = threading.Lock()
        self.logger = logger.Logger(logFile)
        self.maxFileSize = maxFileSize
        self.serverMaster = serverMaster

        self.availableFunctions = ["newUser", "getVTAesB64", "checkVT", "getSK", "getPK",
                                   "delUser", "updateKeys", "addPublicFile",
                                   "addHiddenFile", "addPrivateFile",
                                   "getPublicFileList", "getHiddenFileList",
                                   "getPrivateFileList", "getFile",
                                   "getPrivateFile", "deleteFile"]

        self.functionParametersLength = {"newUser": 5,
                                         "getVTAesB64": 1,
                                         "checkVT": 5,
                                         "getSK": 1,
                                         "getPK": 1,
                                         "delUser": 2,
                                         "updateKeys": 4,
                                         "addPublicFile": 4,
                                         "addHiddenFile": 4,
                                         "addPrivateFile": 4,
                                         "getPublicFileList": 1,
                                         "getHiddenFileList": 2,
                                         "getPrivateFileList": 3,
                                         "getFile": 2,
                                         "getPrivateFile": 3,
                                         "deleteFile": 3}

        self.functionNameToFunc = {"newUser": self.newUser,
                                   "getVTAesB64": self.getVtAesB64,
                                   "checkVT": self.checkVt,
                                   "getSK": self.getSk_,
                                   "getPK": self.getPk,
                                   "delUser": self.delUser,
                                   "updateKeys": self.updateKeys,
                                   "addPublicFile": self.addPublicFile,
                                   "addHiddenFile": self.addHiddenFile,
                                   "addPrivateFile": self.addPrivateFile,
                                   "getPublicFileList": self.getPublicFileList,
                                   "getHiddenFileList": self.getHiddenFileList,
                                   "getPrivateFileList": self.getPrivateFile,
                                   "getFile": self.getFile,
                                   "getPrivateFile": self.getPrivateFile,
                                   "deleteFile": self.deleteFile}

        self.databaseQueue = []
        self.idQueueDictionary = {}
        self.resultsDictionary = {}

    def log(self, msg, printOnScreen=True, debug=False, error=False):
        # type: (str, bool, bool, bool) -> None
        self.logger.log("DatabaseManager", msg, printToScreen=printOnScreen, debug=debug, error=error)

    # Queue Functions

    def run(self):
        while self.serverMaster.running.returnRunning():
            while len(self.databaseQueue) > 0:
                self.databaseLock.acquire()
                actionToDo = self.databaseQueue.pop(0)
                self.doAction(actionToDo)
                self.databaseLock.release()
            time.sleep(0.05)

    def doAction(self, id):
        if id not in self.idQueueDictionary:
            self.log("Id {} not in queue dictionary but in databaseQueue".format(id), error=True)
            return
        actionData = self.idQueueDictionary[id]
        if "function" not in actionData:
            self.log("Id {} in queue dictionary hasn't got a function key".format(id), error=True)
            return
        if "params" not in actionData:
            self.log("Id {} in queue dictionary hasn't got a params key".format(id), error=True)
            return

        function = actionData["function"]
        params = actionData["params"]

        if function not in self.availableFunctions:
            self.log("Id {} in queue dictionary function {} not found".format(id, function), error=True)
            return

        if function not in self.functionParametersLength:
            self.log("Id {} in queue dictionary function {} not in functionParameters".format(id, function), error=True)
            return

        if not len(params) == self.functionParametersLength[function]:
            self.log("Id {} in queue dictionary function {} wrong arguments length: {}".format(id, function,
                                                                                               len(params)),
                     error=True)
            return

        if function not in self.functionNameToFunc:
            self.log("Id {} in queue dictionary function {} not in functionNameToFunc".format(id, function),
                     error=True)
            return

        result = self.functionNameToFunc[function](*params)
        self.resultsDictionary[id] = result

    def addToQueue(self, function, params):
        # type: (str, tuple) -> str
        # self.log("Adding to queue {}".format(function), debug=True)
        if function not in self.availableFunctions:
            self.log("Function {} not in availableFunctions", error=True)
            return ""
        while True:
            newId = base64.b64encode(utils.get_random_bytes(48))
            if newId not in self.databaseQueue:
                break
        self.databaseLock.acquire()
        self.databaseQueue.append(newId)
        self.idQueueDictionary[newId] = {"function": function, "params": params}
        self.databaseLock.release()
        return newId

    def executeFunction(self, function, params):
        id = self.addToQueue(function, params)
        if id == "":
            return -1
        while id not in self.resultsDictionary:
            time.sleep(0.02)
        result = self.resultsDictionary[id]
        del self.resultsDictionary[id]
        return result

    # Prive Methods

    def newSessionKey(self, host, port, sessionKey):
        #type: (str, int, str) -> bool
        self.databaseLock.acquire()
        try:
            return self.__newSessionKey(host, port, sessionKey)
        except:
            self.log("Error newSessionKey", debug=False, error=True)
            return False
        finally:
            self.databaseLock.release()

    def __newSessionKey(self, host, port, sessionKey):
        #type: (str, int, str) -> bool
        sessionKeyb64decoded = base64.b64decode(sessionKey)
        sessionKeyDecrypted = PKCS1_OAEP.new(self.privateKey).decrypt(sessionKeyb64decoded)
        if len(sessionKeyDecrypted) != 16 and len(sessionKeyDecrypted) != 32 and len(sessionKeyDecrypted) != 24:
            return False
        sessionKeyDecryptedB64 = base64.b64encode(sessionKeyDecrypted)
        fileToWrite = open(self.databaseDirectory + "/SessionKeys/" + host + "_" + str(port) + ".sessionkey", "w")
        fileToWrite.write(sessionKeyDecryptedB64)
        return True

    def deleteSessionKey(self, host, port):
        #type: (str, int) -> None
        self.databaseLock.acquire()
        retValue = False
        try:
            retValue = self.__deleteSessionKey(host, port)
        except:
            self.log("Error deleteSessionKey", error=True)
        finally:
            self.databaseLock.release()
        return retValue

    def __deleteSessionKey(self, host, port):
        #type: (str, int) -> None
        #fileToWrite = open(self.databaseDirectory + "\\SessionKeys\\" + host + "_" + str(port) + ".sessionkey", "w")
        #fileToWrite.write("None")
        filePath = self.databaseDirectory + "/SessionKeys/" + host + "_" + str(port) + ".sessionkey"
        if not os.path.isfile(filePath):
            return
        os.remove(self.databaseDirectory + "/SessionKeys/" + host + "_" + str(port) + ".sessionkey")

    def getSessionKey(self, host, port):
        #type: (str, int) -> tuple
        self.databaseLock.acquire()
        retValue = (-1, "")
        try:
            retValue = self.__getSessionKey(host, port)
        except:
            self.log("Error getSessionKey", error=True)
        finally:
            self.databaseLock.release()
        return retValue

    def __getSessionKey(self, host, port):
        #type: (str, int) -> tuple
        filePath = self.databaseDirectory + "/SessionKeys/" + host + "_" + str(port) + ".sessionkey"
        if not os.path.isfile(filePath):
            return False, ""
        fileToRead = open(filePath, "r")
        sessionKey = fileToRead.read()
        if sessionKey == "None":
            return False, ""
        return True, base64.b64decode(sessionKey)

    def newUser(self, name, pk, skAesB64, vtB64, vtAesB64):
        #type: (str, str, str, str, str) -> int
        retValue = -1
        try:
            retValue = self.__newUser(name, pk, skAesB64, vtB64, vtAesB64)
        except:
            self.log("Error newUser", error=True)
        return retValue

    def __newUser(self, name, pk, skAesB64, vtB64, vtAesB64):
        #type: (str, str, str, str, str) -> int
        # Returns errorNumber (0 - All Correct,
        #                      1 - AlreadyExists,
        #                      2 - Bad Characters Name,
        #                      3 - " " Private Key,
        #                      4 - " " Public Key,
        #                      5 - " " Validation Token,
        #                      6 - " " Validation Token Encrypted)

        if re.search(".*[" + self.unacceptedNameCharacters + "].*", name):
            return 2

        if os.path.isdir(self.databaseDirectory + "/Profiles/" + name):
            return 1

        if not utils.isBase64(skAesB64):
            return 3

        if not re.search("^-----BEGIN PUBLIC KEY-----\n[a-zA-Z0-9+/=\n]+-----END PUBLIC KEY-----$", pk):
            return 4

        if not utils.isBase64(vtB64):
            return 5

        if not utils.isBase64(vtAesB64):
            return 6

        os.mkdir(self.databaseDirectory + "/Profiles/" + name)

        nameFile = open(self.databaseDirectory + "/Profiles/" + name + "/name.username", "w")
        nameFile.write(name)
        nameFile.close()

        pkFile = open(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk", "w")  # Public Key
        pkFile.write(pk)
        pkFile.close()

        skFile = open(self.databaseDirectory + "/Profiles/" + name + "/privatekey.skaesb64", "w")  # Secret Key Aes
        skFile.write(skAesB64)
        skFile.close()

        vtFile = open(self.databaseDirectory + "/Profiles/" + name + "/validation.vtb64", "w")  # Validation Token
        vtFile.write(vtB64)
        vtFile.close()

        vtAesFile = open(self.databaseDirectory + "/Profiles/" + name + "/validationEnc.vtaesb64",
                         "w")  # Validation Token Aes
        vtAesFile.write(vtAesB64)
        vtAesFile.close()

        os.mkdir(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs")

        publicFileList = open(self.databaseDirectory + "/Profiles/" + name + "/publicFileList.pufl", "w")
        publicFileList.close()

        hiddenFileList = open(self.databaseDirectory + "/Profiles/" + name + "/hiddenFileList.hfl", "w")
        hiddenFileList.close()

        privateFileList = open(self.databaseDirectory + "/Profiles/" + name + "/privateFileList.prfl", "w")
        privateFileList.close()

        #chatsFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\chats.chts", "w")
        #chatsFile.close()

        return 0

    def getVtAesB64(self, name):
        #type: (str) -> tuple
        retValue = (-1, "")
        try:
            retValue = self.__getVtAesB64(name)
        except:
            self.log("Error getVtAesB64", error=True)
        return retValue

    def __getVtAesB64(self, name):
        #type: (str) -> tuple
        # Returns (errorCode, vtAesB64)
        # Error Codes (0 - All Correct,
        #              1 - User doesn't exist,
        #              2 - Strange Error where there isn't vtaesb64)
        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + name):
            return 1, ""

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/validationEnc.vtaesb64"):
            return 2, ""

        vtAesFile = open(self.databaseDirectory + "/Profiles/" + name + "/validationEnc.vtaesb64",
                         "r")  # Validation Token Aes
        vtAes = vtAesFile.read()

        return 0, vtAes

    def checkVt(self, name, vtB64, ip, newVtSha, newVtEnc):
        #type: (str, str, str, str, str) -> tuple
        retValue = (-1, "")
        try:
            retValue = self.__checkVt(name, vtB64, ip, newVtSha, newVtEnc)
        except:
            self.log("Error checkVt", error=True)
        return retValue

    def __checkVt(self, name, vtB64, ip, newVTSha, newVTEnc):
        #type: (str, str, str, str, str) -> tuple
        # Returns (errorCode, timeUntilUnlock)
        # Error Codes (0 - Correct,
        #              1 - Incorrect,
        #              2 - User doesn't exist,
        #              3 - Strange Error where there isn't validation token,
        #              4 - Invalid Validation Token Characters,
        #              5 - Locked Account)

        if os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs/" + ip):
            triesFile = open(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs/" + ip, "r")
            triesNotRe = triesFile.read()
            triesNotRe = triesNotRe.split("\n")[:-1]
            triesNotReLast = triesNotRe[-1]
            triesRe = re.search("^Ltest: (.+)$", triesNotReLast)
            if triesRe:
                triesNum = triesNotRe.__len__()
                if float(triesRe.group(1)) + pow(2,triesNum)*0.5 > time.time():
                    waitingTime = (float(triesRe.group(1)) + pow(2,triesNum)*0.5) - time.time()
                    return 5, waitingTime
            triesFile.close()

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + name):
            return 2, 0

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/validation.vtb64"):
            return 3, 0

        if not utils.isBase64(vtB64):
            return 4, 0

        vtFile = open(self.databaseDirectory + "/Profiles/" + name + "/validation.vtb64", "r")
        vtB64Correct = vtFile.read()

        vtShaB64 = base64.b64encode(SHA256.new(base64.b64decode(vtB64)).digest())

        if vtShaB64 == vtB64Correct:
            # Empty Ip Tries File
            if os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs/" + ip):
                os.remove(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs/" + ip)
            vtFile = open(self.databaseDirectory + "/Profiles/" + name + "/validation.vtb64", "w")
            vtFile.write(newVTSha)
            vtFile.close()
            vtEncFile = open(self.databaseDirectory + "/Profiles/" + name + "/validationEnc.vtaesb64", "w")
            vtEncFile.write(newVTEnc)
            vtEncFile.close()
            return 0, 0

        ipFile = open(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs/" + ip, "a")
        ipFile.write("Ltest: " + str(time.time()) + "\n")
        return 1, 0

    def getSk_(self, name):
        #type: (str) -> tuple
        retValue = (-1, "")
        try:
            retValue = self.__getSk_(name)
        except:
            self.log("Error getSk_", error=True)
        return retValue

    def __getSk_(self, name):
        #type: (str) -> tuple
        # Returns errorCode, skb64
        # Error Codes (0 - All Correct,
        #              1 - Strange Error where there isn't private key,
        #              2 - User Doesn't Exist)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + name):
            return 2, ""

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/privatekey.skaesb64"):
            return 1, ""

        skFile = open(self.databaseDirectory + "/Profiles/" + name + "/privatekey.skaesb64", "r")
        sk = skFile.read()

        return 0, sk

    def getPk(self, name):
        #type: (str) -> tuple
        retValue = (-1, "")
        try:
            retValue = self.__getPk(name)
        except:
            self.log("Error getPk", error=True)
        return retValue

    def __getPk(self, name):
        # type: (str) -> tuple
        # Returns errorCode, pkb64
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Strange Error Where there isn't Public Key)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + name):
            return 1, ""

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk"):
            return 2, ""

        pkFile = open(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk", "r")
        pk = pkFile.read()

        return 0, pk

    def delUser(self, name, signatureB64):
        # type: (str, str) -> int
        retValue = -1
        try:
            retValue = self.__delUser(name, signatureB64)
        except:
            self.log("Error delUser", error=True)
        return retValue

    def __delUser(self, name, signatureB64):
        # type: (str, str) -> int
        # Returns errorCode
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Strange Error Where The User Doesn't Have PK,
        #              3 - Signature not B64,
        #              4 - Faulty Signature,
        #              5 - Error Importing User PK)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + name):
            return 1

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk"):
            return 2

        if not utils.isBase64(signatureB64):
            return 3

        pkFile = open(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 5

        signature = base64.b64decode(signatureB64)
        signToVerify = SHA256.new()
        signToVerify.update("delUser;name: " + name)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signToVerify, signature)
            validSignature = True
        except ValueError:
            validSignature = False

        if validSignature is True:
            #print 2
            #for file in os.listdir(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs"):
            #    os.remove(file)
            #os.remove(self.databaseDirectory + "\\Profiles\\" + name + "\\name.username")
            #os.remove(self.databaseDirectory + "\\Profiles\\" + name + "\\privatekey.skaesb64")
            #os.remove(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk")
            #os.remove(self.databaseDirectory + "\\Profiles\\" + name + "\\validation.vtb64")
            #os.remove(self.databaseDirectory + "\\Profiles\\" + name + "\\validationEnc.vtaesb64")
            #os.rmdir(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs")
            shutil.rmtree(self.databaseDirectory + "/Profiles/" + name)
            return 0

        return 4

    def updateKeys(self, name, signatureB64, newPKB64, newSKAesB64):
        # type: (str, str, str, str) -> int
        retValue = -1
        try:
            retValue = self.__updateKeys(name, signatureB64, newPKB64, newSKAesB64)
        except:
            self.log("Error updateKeys", error=True)
        return retValue

    def __updateKeys(self, name, signatureB64, newPKB64, newSKAesB64):
        # type: (str, str, str, str) -> int
        # Returns errorCode
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Invalid Signature Characters,
        #              3 - Invalid newSKAesB64 Character,
        #              4 - Invalid newPK,
        #              5 - Strange Error Where User Doesn't have PK,
        #              6 - Error Importing User PK,
        #              7 - Faulty Signature)

        newPK = base64.b64decode(newPKB64)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + name):
            return 1

        if not utils.isBase64(signatureB64):
            return 2

        if not utils.isBase64(newSKAesB64):
            return 3

        if not re.search("^-----BEGIN PUBLIC KEY-----\n[a-zA-Z0-9+/=\n]+-----END PUBLIC KEY-----$", newPK):
            return 4

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk"):
            return 5

        pkFile = open(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 6

        signatureToVerify = SHA256.new()
        signatureToVerify.update("updateKeys;name: " + name + ";newPK: " + newPK + ";newSKAesB64: " + newSKAesB64)
        signature = base64.b64decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature is True:
            pkFile = open(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk", "w")
            pkFile.write(newPK)
            pkFile.close()

            skFile = open(self.databaseDirectory + "/Profiles/" + name + "/privatekey.skaesb64", "w")
            skFile.write(newSKAesB64)
            skFile.close()

            return 0

        return 7

    # File secction

    def addPublicFile(self, user, fileNameB64, fileB64, signatureB64):
        retValue = -1
        try:
            retValue = self.__addPublicFile(user, fileNameB64, fileB64, signatureB64)
        except:
            self.log("Error addPublicFile", error=True)
        return  retValue

    def __addPublicFile(self, user, fileNameB64, fileB64, signatureB64):
        #type: (str, str, str, str) -> int
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Invalid FileNameB64 Characters,
        #              3 - Invalid FileB64 Characters
        #              4 - Invalid Signature Characters,
        #              5 - Strange Error Where User Doesn't have PK,
        #              6 - Error Importing User PK,
        #              7 - Faulty Signature,
        #              8 - Missing Public File List (PUFL))
        #              9 - Exceeds max file size (4*ceil(bytes/3))

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + user):
            return 1

        if not utils.isBase64(fileNameB64):
            return 2

        if not utils.isBase64(fileB64):
            return 3

        if not utils.isBase64(signatureB64):
            return 4

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk"):
            return 5

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl"):
            return 8

        if len(fileB64) > 4*math.ceil(self.maxFileSize/3.0):
            return 9

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 6

        signatureToVerify = SHA256.new()
        signatureToVerify.update("addPublicFile;name: " + user + ";fileNameB64: " + fileNameB64 + ";fileB64: " + fileB64)
        signature = base64.b64decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature is True:

            randomIdB64 = ""

            while True:
                randomIdB64 = base64.b64encode(utils.get_random_bytes(48))
                if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd"):
                    break
                self.log("1 in a 2^384 possibilities. AMAZINGGGGGG", debug=True)

            publicFileList = open(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl", "a")  # Stands for Public File List (PUFL)
            publicFileList.write("fileName: {0};id: {1},".format(fileNameB64, randomIdB64))
            publicFileList.close()

            fileFile = open(self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd", "w")  #Stands for File Data (FD). Also fileFile is funny.
            fileFile.write(fileB64)
            fileFile.close()

            return 0

        return 7

    def addHiddenFile(self, user, fileNameB64, fileB64, signatureB64):
        retValue = -1
        try:
            retValue = self.__addHiddenFile(user, fileNameB64, fileB64, signatureB64)
        except:
            self.log("Error addHiddenFile", error=True)
        return  retValue

    def __addHiddenFile(self, user, fileNameB64, fileB64, signatureB64):
        #type: (str, str, str, str) -> int
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Invalid FileNameB64 Characters,
        #              3 - Invalid FileB64 Characters
        #              4 - Invalid Signature Characters,
        #              5 - Strange Error Where User Doesn't have PK,
        #              6 - Error Importing User PK,
        #              7 - Faulty Signature,
        #              8 - Missing Hidden File List (HFL))
        #              9 - Exceeds max file size (4*ceil(bytes/3))

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + user):
            return 1

        if not utils.isBase64(fileNameB64):
            return 2

        if not utils.isBase64(fileB64):
            return 3

        if not utils.isBase64(signatureB64):
            return 4

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk"):
            return 5

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl"):
            return 8

        if len(fileB64) > 4*math.ceil(self.maxFileSize/3.0):
            return 9

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 6

        signatureToVerify = SHA256.new()
        signatureToVerify.update("addHiddenFile;name: " + user + ";fileNameB64: " + fileNameB64 + ";fileB64: " + fileB64)
        signature = base64.b64decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature is True:

            randomIdB64 = ""

            while True:
                randomIdB64 = base64.b64encode(utils.get_random_bytes(48))
                if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd"):
                    break
                self.log("1 in a 2^384 possibilities. AMAZINGGGGGG", debug=True)

            hiddenFileList = open(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl",
                                  "a")  # Stands for Hidden File List (HFL)
            hiddenFileList.write("fileName: {0};id: {1},".format(fileNameB64, randomIdB64))
            hiddenFileList.close()

            fileFile = open(self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd",
                            "w")  #Stands for File Data (FD). Also fileFile is funny.
            fileFile.write(fileB64)
            fileFile.close()

            return 0

        return 7

    def addPrivateFile(self, user, fileNameB64, fileB64, signatureB64):
        retValue = -1
        try:
            retValue = self.__addPublicFile(user, fileNameB64, fileB64, signatureB64)
        except:
            self.log("Error addPrivateFile", error=True)
        return  retValue

    def __addPrivateFile(self, user, fileNameB64, fileB64, signatureB64):
        #type: (str, str, str, str) -> int
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Invalid FileNameB64 Characters,
        #              3 - Invalid FileB64 Characters
        #              4 - Invalid Signature Characters,
        #              5 - Strange Error Where User Doesn't have PK,
        #              6 - Error Importing User PK,
        #              7 - Faulty Signature,
        #              8 - Missing Private File List (PRFL))
        #              9 - Exceeds max file size (4*ceil(bytes/3))

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + user):
            return 1

        if not utils.isBase64(fileNameB64):
            return 2

        if not utils.isBase64(fileB64):
            return 3

        if not utils.isBase64(signatureB64):
            return 4

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk"):
            return 5

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl"):
            return 8

        if len(fileB64) > 4 * math.ceil(self.maxFileSize / 3.0):
            return 9

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 6

        signatureToVerify = SHA256.new()
        signatureToVerify.update(
            "addPrivateFile;name: " + user + ";fileNameB64: " + fileNameB64 + ";fileB64: " + fileB64)
        signature = base64.b64decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature is True:

            randomIdB64 = ""

            while True:
                randomIdB64 = base64.b64encode(utils.get_random_bytes(48))
                if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd"):
                    break
                self.log("1 in a 2^384 possibilities. AMAZINGGGGGG", debug=True)

            privateFileList = open(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl",
                                   "a")  # Stands for Hidden File List (HFL)
            privateFileList.write("fileName: {0};id: {1},".format(fileNameB64, randomIdB64))
            privateFileList.close()

            fileFile = open(self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd",
                            "w")  # Stands for File Data (FD). Also fileFile is funny.
            fileFile.write(fileB64)
            fileFile.close()

            return 0

        return 7

    def getPublicFileList(self, user):
        # type: (str) -> list
        retValue = [-1, ""]
        try:
            retValue = self.__getPublicFileList(user)
        except:
            self.log("Error getPublicFileList", error=True)
        return retValue
        pass

    def __getPublicFileList(self, user):
        # type: (str) -> list
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Missing Public File List (PUFL))

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + user):
            return [1, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl"):
            return [2, ""]

        publicFileList = open(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl", "r")  # Stands for Public File List (PUFL)
        publicFileListContents = publicFileList.read()
        publicFileList.close()
        return [0, publicFileListContents]

    def getHiddenFileList(self, user, signatureB64):
        # type: (str, str) -> list
        retValue = [-1, ""]
        try:
            retValue = self.__getHiddenFileList(user, signatureB64)
        except:
            self.log("Error getHiddenFileList", error=True)
        return retValue
        pass

    def __getHiddenFileList(self, user, signatureB64):
        # type: (str, str) -> list
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Missing Hidden File List (HFL),
        #              3 - Wrong SignatureB64 characters,
        #              4 - Strange Error Where User Doesn't have PK,
        #              5 - Error Importing User PK,
        #              6 - Faulty Signature)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + user):
            return [1, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl"):
            return [2, ""]

        if not utils.isBase64(signatureB64):
            return [3, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk"):
            return [4, ""]

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return [5, ""]

        signatureToVerify = SHA256.new()
        signatureToVerify.update("getHiddenFileList;name: " + user)
        signature = base64.b64decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature:
            publicFileList = open(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl",
                                  "r")  # Stands for Hidden File List (HFL)
            publicFileListContents = publicFileList.read()
            publicFileList.close()
            return [0, publicFileListContents]

        return [6, ""]

    def getPrivateFileList(self, user, signatureB64):
        # type: (str, str) -> list
        retValue = [-1, ""]
        try:
            retValue = self.__getPrivateFileList(user, signatureB64)
        except:
            self.log("Error getPrivateFileList", error=True)
        return retValue
        pass

    def __getPrivateFileList(self, user, signatureB64):
        # type: (str, str) -> list
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Missing Private File List (PRFL),
        #              3 - Wrong SignatureB64 characters,
        #              4 - Strange Error Where User Doesn't have PK,
        #              5 - Error Importing User PK,
        #              6 - Faulty Signature)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + user):
            return [1, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl"):
            return [2, ""]

        if not utils.isBase64(signatureB64):
            return [3, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk"):
            return [4, ""]

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return [5, ""]

        signatureToVerify = SHA256.new()
        signatureToVerify.update("getPrivateFileList;name: " + user)
        signature = base64.b64decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature:
            publicFileList = open(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl",
                                  "r")  # Stands for Hidden File List (HFL)
            publicFileListContents = publicFileList.read()
            publicFileList.close()
            return [0, publicFileListContents]

        return [6, ""]
        pass

    def getFile(self, user, id):  # Works for both Public & Hidden Files
        # type: (str, str) -> tuple
        pass

    def __getFile(self, user, id):
        # type: (str, str) -> tuple
        pass

    def getPrivateFile(self, user, id, signatureB64):
        # type: (str, str, str) -> tuple
        pass

    def __getPrivateFile(self, user, id, signatureB64):
        # type: (str, str, str) -> tuple
        pass

    def deleteFile(self, user, id, signatureB64):
        pass

    def __deleteFile(self, user, id, signatureB64):
        pass

    # Not Used
    """def __createChat(self, creatorName, chatName, keys, firstMessage, signature, messageValidationSha):
        # type: (str, str, str, str, str, str) -> int
        # Returns errorCode
        # Error Codes (0  - All Correct,
        #              1  - Creator User Doesn't Exist,
        #              2  - Strange Error Where User Doesn't Have Chats Folder,
        #              3  - Invalid Chat Name Characters,
        #              4  - Chat Already Exists,
        #              5  - Strange Error Where User Doesn't Have PK,
        #              6  - Invalid Keys Characters,
        #              7  - Faulty Signature,
        #              8  - Incorrect Number Of Keys,
        #              9  - Invalid First Message Characters,
        #              10 - Invalid Key Characters)

        self.databaseLock.acquire()

        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + creatorName):
            self.databaseLock.release()
            return 1

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + creatorName + "\\chats.chts"):
            self.databaseLock.release()
            return 2

        if re.search(".*[\r\n/\\\\:\"?*<>|.].*", chatName):
            self.databaseLock.release()
            return 3

        if re.search(".*\r\n.*", firstMessage):
            self.databaseLock.release()
            return 9

        if os.path.isdir(self.databaseDirectory + "\\Chats\\" + chatName):
            return 4

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + creatorName + "\\publickey.pk"):
            self.databaseLock.release()
            return 5

        if not re.search("^[a-zA-Z0-9+/;=\n]+$", keys):
            self.databaseLock.release()
            return 6

        if not re.search("^[a-zA-Z0-9+/;=\n]+$", messageValidationSha):
            self.databaseLock.release()
            return 10

        if not keys.split("\n")[:-1].__len__() == 1:
            self.databaseLock.release()
            return 8

        signToVerifyStr = "newChat;creatorName: " + creatorName + ";chatName: " + chatName + ";keys: " + keys
        signToVerifyStr = signToVerifyStr + ";firstMessage: " + firstMessage

        pkFile = open(self.databaseDirectory + "\\Profiles\\" + creatorName + "\\publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()
        pkKey = RSA.importKey(pk)

        signature = base64.b64decode(signature)

        signToVerify = SHA256.new()
        signToVerify.update(signToVerifyStr)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if not validSignature:
            self.databaseLock.release()
            return 7

        os.mkdir(self.databaseDirectory + "\\Chats\\" + chatName)

        chatFile = open(self.databaseDirectory + "\\Chats\\" + chatName + "\\chat.ch", "a")
        chatFile.write(creatorName + ": " + firstMessage + "\r\n")
        chatFile.close()

        keysFile = open(self.databaseDirectory + "\\Chats\\" + chatName + "\\keys.ks", "w")
        keysFile.write(keys)
        keysFile.close()

        memberFile = open(self.databaseDirectory + "\\Chats\\" + chatName + "\\Members.ms", "a")
        memberFile.write(creatorName + ";")
        memberFile.close()

        profileMemberFile = open(self.databaseDirectory + "\\Profiles\\" + creatorName + "\\chats.chts", "a")
        profileMemberFile.write(chatName + ";")
        profileMemberFile.close()

        adminFile = open(self.databaseDirectory + "\\Chats\\" + chatName + "\\admin.an", "w")
        adminFile.write(chatName)
        adminFile.close()

        msgValidationShaFile = open(self.databaseDirectory + "\\Chats\\" + chatName + "\\msgVS.msgvsha", "w")
        msgValidationShaFile.write(messageValidationSha)
        msgValidationShaFile.close()

        self.databaseLock.release()

        return 0"""
