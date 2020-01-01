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
from config import Config
import fileTransfer
import clientHandle

# ALL file management is done in this file and in generateKeys.py

class DatabaseManager(threading.Thread):

    def __init__(self, databaseDirectory, logFile, unacceptedNameCharacters, keySize, maxFileSize,
                 serverMaster):
        #type: (DatabaseManager, str, str, str, int, int, server.Server) -> None
        threading.Thread.__init__(self)
        self.databaseDirectory = databaseDirectory
        self.unacceptedNameCharacters = unacceptedNameCharacters

        if not os.path.isdir(self.databaseDirectory):
            os.mkdir(self.databaseDirectory)
        if not os.path.isdir(self.databaseDirectory + "/Profiles"):
            os.mkdir(self.databaseDirectory + "/Profiles")
        if not os.path.isdir(self.databaseDirectory + "/SessionKeys"):
            os.mkdir(self.databaseDirectory + "/SessionKeys")
        if not os.path.isdir(self.databaseDirectory + "/Challenges"):
            os.mkdir(self.databaseDirectory + "/Challenges")
        if not os.path.isdir(self.databaseDirectory + "/FileSegments"):
            os.mkdir(self.databaseDirectory + "/FileSegments")
        #if not os.path.isdir(self.databaseDirectory + "\\Chats"):
        #    os.mkdir(self.databaseDirectory + "\\Chats")

        privateKeyPath = self.databaseDirectory + "/privateKey.skm"  # Private Key Master

        if not os.path.isfile(privateKeyPath):
            print "Private key not found"
            print "Creating private key"
            genKeyObj = generateKeys.GenerateKeys(self.databaseDirectory, keySize)
            genKeyObj.generate()

        privateKeyFile = open(privateKeyPath, "rb")
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
                                   "getPrivateFile", "deleteFile", "requestChallenge"]

        self.functionParametersLength = {"newUser": 7,
                                         "getVTAesB64": 1,
                                         "checkVT": 5,
                                         "getSK": 1,
                                         "getPK": 1,
                                         "delUser": 2,
                                         "updateKeys": 6,
                                         "addPublicFile": 5,
                                         "addHiddenFile": 5,
                                         "addPrivateFile": 5,
                                         "getPublicFileList": 1,
                                         "getHiddenFileList": 2,
                                         "getPrivateFileList": 2,
                                         "getFile": 2,
                                         "getPrivateFile": 3,
                                         "deleteFile": 3,
                                         "requestChallenge": 1}

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
                                   "getPrivateFileList": self.getPrivateFileList,
                                   "getFile": self.getFile,
                                   "getPrivateFile": self.getPrivateFile,
                                   "deleteFile": self.deleteFile,
                                   "requestChallenge": self.requestChallenge}

        self.databaseQueueLock = threading.Lock()
        self.databaseQueue = []

        self.idQueueDictionaryLock = threading.Lock()
        self.idQueueDictionary = {}

        self.resultsDictionaryLock = threading.Lock()
        self.resultsDictionary = {}

    def log(self, msg, printOnScreen=True, debug=False, error=False):
        # type: (str, bool, bool, bool) -> None
        self.logger.log("DatabaseManager", msg, printToScreen=printOnScreen, debug=debug, error=error)

    # Queue Functions

    def run(self):
        while self.serverMaster.running.returnRunning():
            while len(self.databaseQueue) > 0:
                self.databaseLock.acquire()

                self.databaseQueueLock.acquire()
                actionToDo = self.databaseQueue.pop(0)
                self.databaseQueueLock.release()

                self.doAction(actionToDo)

                self.databaseLock.release()
            time.sleep(0.05)

    def doAction(self, id):
        if id not in self.idQueueDictionary:
            self.log("Id {} not in queue dictionary but in databaseQueue".format(id), error=True)
            return

        self.idQueueDictionaryLock.acquire()
        actionData = self.idQueueDictionary[id]
        self.idQueueDictionaryLock.release()

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

        self.resultsDictionaryLock.acquire()
        self.resultsDictionary[id] = result
        self.resultsDictionaryLock.release()

    def addToQueue(self, function, params):
        # type: (str, tuple) -> str
        # self.log("Adding to queue {}".format(function), debug=True)
        if function not in self.availableFunctions:
            self.log("Function {} not in availableFunctions", error=True)
            return ""
        while True:
            newId = utils.base64_encode(utils.get_random_bytes(48))
            if newId not in self.databaseQueue:
                break

        self.databaseQueueLock.acquire()
        self.databaseQueue.append(newId)
        self.databaseQueueLock.release()

        self.idQueueDictionaryLock.acquire()
        self.idQueueDictionary[newId] = {"function": function, "params": params}
        self.idQueueDictionaryLock.release()

        return newId

    def executeFunction(self, function, params):
        id = self.addToQueue(function, params)

        if id == "":
            return -1

        while id not in self.resultsDictionary:
            time.sleep(0.02)

        self.resultsDictionaryLock.acquire()
        result = self.resultsDictionary[id]
        del self.resultsDictionary[id]
        self.resultsDictionaryLock.release()

        return result

    # Security section

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
        sessionKeyb64decoded = utils.base64_decode(sessionKey)
        sessionKeyDecrypted = PKCS1_OAEP.new(self.privateKey).decrypt(sessionKeyb64decoded)
        if len(sessionKeyDecrypted) != 16 and len(sessionKeyDecrypted) != 32 and len(sessionKeyDecrypted) != 24:
            return False
        sessionKeyDecryptedB64 = utils.base64_encode(sessionKeyDecrypted)
        fileToWrite = open(self.databaseDirectory + "/SessionKeys/" + host + "_" + str(port) + ".sessionkey", "wb")
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
        fileToRead = open(filePath, "rb")
        sessionKey = fileToRead.read()
        if sessionKey == "None":
            return False, ""
        return True, utils.base64_decode(sessionKey)

    def requestChallenge(self, ip):
        # type: (str) -> tuple
        retValue = (-1, "")
        try:
            retValue = self.__requestChallenge(ip)
        except:
            self.log("Error requestChallenge", error=True)
        return retValue

    def __requestChallenge(self, ip):
        # type: (str) -> tuple
        if not os.path.isfile(self.databaseDirectory + "/Challenges/" + ip + ".chll"):
            randomChallenge = utils.base64_encode(utils.get_random_bytes(48))

            chlFile = open(self.databaseDirectory + "/Challenges/" + ip + ".chll", "wb")
            chlFile.write(randomChallenge)
            chlFile.close()

        chlFile = open(self.databaseDirectory + "/Challenges/" + ip + ".chll", "rb")
        challenge = chlFile.read()
        chlFile.close()
        return 0, challenge

    def checkPOW_(self, proofOfWork, ip):
        # type: (str, str) -> int
        if not os.path.isfile(self.databaseDirectory + "/Challenges/" + ip + ".chll"):
            return 1

        challengeFile = open(self.databaseDirectory + "/Challenges/" + ip + ".chll", "rb")
        challenge = challengeFile.read()

        try:
            challenge = utils.base64_decode(challenge)
        except Exception as e:
            self.log("Proof of work error decoding base64. Error: {}".format(e), error=True)
            try:
                os.remove(self.databaseDirectory + "/Challenges/" + ip + ".chll")
            except:
                pass
            return 1

        challengeSolved = challenge + proofOfWork

        check = utils.checkProofOfWork(challengeSolved, Config.POW_NUM_OF_0, Config.POW_ITERATIONS)

        if check:
            return 0
        else:
            return 2

    # User section

    def newUser(self, name, pk, skAesB64, vtB64, vtAesB64, proofOfWork, ip):
        #type: (str, str, str, str, str, str, str) -> int
        retValue = -1
        try:
            retValue = self.__newUser(name, pk, skAesB64, vtB64, vtAesB64, proofOfWork, ip)
        except:
            self.log("Error newUser", error=True)
        return retValue

    def __newUser(self, name, pk, skAesB64, vtB64, vtAesB64, proofOfWork, ip):
        #type: (str, str, str, str, str, str, str) -> int
        # Returns errorNumber (0 - All Correct,
        #                      1 - AlreadyExists,
        #                      2 - Bad Characters Name,
        #                      3 - " " Private Key,
        #                      4 - " " Public Key,
        #                      5 - " " Validation Token,
        #                      6 - " " Validation Token Encrypted,
        #                      7 - " " Proof of Work,
        #                      8/9 - Proof of work errors (checkPOW_))

        if not re.search(self.unacceptedNameCharacters, name):
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

        if not utils.isBase64(proofOfWork):
            return 7

        proofOfWork = utils.base64_decode(proofOfWork)

        powVerification = self.checkPOW_(proofOfWork, ip)
        if powVerification != 0:
            return powVerification+7

        os.mkdir(self.databaseDirectory + "/Profiles/" + name)

        pkFile = open(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk", "wb")  # Public Key
        pkFile.write(pk)
        pkFile.close()

        skFile = open(self.databaseDirectory + "/Profiles/" + name + "/privatekey.skaesb64", "wb")  # Secret Key Aes
        skFile.write(skAesB64)
        skFile.close()

        vtFile = open(self.databaseDirectory + "/Profiles/" + name + "/validation.vtb64", "wb")  # Validation Token
        vtFile.write(vtB64)
        vtFile.close()

        vtAesFile = open(self.databaseDirectory + "/Profiles/" + name + "/validationEnc.vtaesb64",
                         "wb")  # Validation Token Aes
        vtAesFile.write(vtAesB64)
        vtAesFile.close()

        os.mkdir(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs")

        publicFileList = open(self.databaseDirectory + "/Profiles/" + name + "/publicFileList.pufl", "wb")
        publicFileList.write(",")
        publicFileList.close()

        hiddenFileList = open(self.databaseDirectory + "/Profiles/" + name + "/hiddenFileList.hfl", "wb")
        hiddenFileList.write(",")
        hiddenFileList.close()

        privateFileList = open(self.databaseDirectory + "/Profiles/" + name + "/privateFileList.prfl", "wb")
        privateFileList.write(",")
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
                         "rb")  # Validation Token Aes
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
            triesFile = open(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs/" + ip, "rb")
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

        vtFile = open(self.databaseDirectory + "/Profiles/" + name + "/validation.vtb64", "rb")
        vtB64Correct = vtFile.read()
        vtFile.close()

        vtShaB64 = utils.base64_encode(SHA256.new(utils.base64_decode(vtB64)).digest())

        if vtShaB64 == vtB64Correct:
            # Empty Ip Tries File
            if os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs/" + ip):
                os.remove(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs/" + ip)
            vtFile = open(self.databaseDirectory + "/Profiles/" + name + "/validation.vtb64", "wb")
            vtFile.write(newVTSha)
            vtFile.close()
            vtEncFile = open(self.databaseDirectory + "/Profiles/" + name + "/validationEnc.vtaesb64", "wb")
            vtEncFile.write(newVTEnc)
            vtEncFile.close()
            return 0, 0

        ipFile = open(self.databaseDirectory + "/Profiles/" + name + "/triesByIPs/" + ip, "ab")
        ipFile.write("Ltest: " + str(time.time()) + "\n")
        return 1, 0

    def getSk_(self, name):
        #type: (str) -> list
        retValue = [-1, ""]
        try:
            retValue = self.__getSk_(name)
        except:
            self.log("Error getSk_", error=True)
        return retValue

    def __getSk_(self, name):
        #type: (str) -> list
        # Returns errorCode, skb64
        # Error Codes (0 - All Correct,
        #              1 - Strange Error where there isn't private key,
        #              2 - User Doesn't Exist)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + name):
            return [2, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/privatekey.skaesb64"):
            return [1, ""]

        skFile = open(self.databaseDirectory + "/Profiles/" + name + "/privatekey.skaesb64", "rb")
        sk = skFile.read()

        return [0, sk]

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

        pkFile = open(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk", "rb")
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

        pkFile = open(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk", "rb")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 5

        signature = utils.base64_decode(signatureB64)
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

    def updateKeys(self, name, signatureB64, newPKB64, newSKAesB64, newVTSha, newVTEnc):
        # type: (str, str, str, str, str, str) -> int
        retValue = -1
        try:
            retValue = self.__updateKeys(name, signatureB64, newPKB64, newSKAesB64, newVTSha, newVTEnc)
        except:
            self.log("Error updateKeys", error=True)
        return retValue

    def __updateKeys(self, name, signatureB64, newPKB64, newSKAesB64, newVTSha, newVTEnc):
        # type: (str, str, str, str, str, str) -> int
        # Returns errorCode
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Invalid Signature Characters,
        #              3 - Invalid newSKAesB64 Characters,
        #              4 - Invalid newPK,
        #              5 - Invalid newVtSha Characters,
        #              6 - Invalid newVtEnc Characters,
        #              7 - Strange Error Where User Doesn't have PK,
        #              8 - Error Importing User PK,
        #              9 - Faulty Signature)

        newPK = utils.base64_decode(newPKB64)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + name):
            return 1

        if not utils.isBase64(signatureB64):
            return 2

        if not utils.isBase64(newSKAesB64):
            return 3

        if not re.search("^-----BEGIN PUBLIC KEY-----\n[a-zA-Z0-9+/=\n]+-----END PUBLIC KEY-----$", newPK):
            return 4

        if not utils.isBase64(newVTSha):
            return 5

        if not utils.isBase64(newVTEnc):
            return 6

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk"):
            return 7

        pkFile = open(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk", "rb")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 8

        signatureToVerify = SHA256.new()
        signatureToVerify.update("updateKeys;name: " + name + ";newPK: " + newPK + ";newSKAesB64: " + newSKAesB64 +
                                 ";newVtSha: " + newVTSha + ";newVtEnc: " + newVTEnc)
        signature = utils.base64_decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature is True:
            pkFile = open(self.databaseDirectory + "/Profiles/" + name + "/publickey.pk", "wb")
            pkFile.write(newPK)
            pkFile.close()

            skFile = open(self.databaseDirectory + "/Profiles/" + name + "/privatekey.skaesb64", "wb")
            skFile.write(newSKAesB64)
            skFile.close()

            vtFile = open(self.databaseDirectory + "/Profiles/" + name + "/validation.vtb64", "wb")
            vtFile.write(newVTSha)
            vtFile.close()

            vtEncFile = open(self.databaseDirectory + "/Profiles/" + name + "/validationEnc.vtaesb64", "wb")
            vtEncFile.write(newVTEnc)
            vtEncFile.close()

            return 0

        return 9

    # File secction

    def addPublicFile(self, user, fileNameB64, fileB64Size, signatureB64, clientHandler):
        # type: (str, str, str, str, clientHandle.ClientHandle) -> int
        retValue = -1
        try:
            retValue = self.__addPublicFile(user, fileNameB64, fileB64Size, signatureB64, clientHandler)
        except Exception as e:
            self.log("Error addPublicFile: {0}".format(e.message), error=True)
        return retValue

    def __addPublicFile(self, user, fileNameB64, fileB64Size, signatureB64, clientHandler):
        #type: (str, str, str, str, clientHandle.ClientHandle) -> int
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

        if not utils.isInt(fileB64Size):
            return 3

        fileB64Size = int(fileB64Size)

        if not utils.isBase64(signatureB64):
            return 4

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk"):
            return 5

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl"):
            return 8

        publicFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl", "rb")
        publicFileListFilesSplit = publicFileListFile.read().split(",")[1:-1]
        publicFileListSizes = [0]
        for i in publicFileListFilesSplit:
            publicFileListRe = re.search("fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if publicFileListRe:
                publicFileListSizes.append(int(publicFileListRe.group(3)))
        publicFileListFile.close()

        #self.log("Total size: {}".format(str(sum(publicFileListSizes))), debug=True)

        if fileB64Size > (4*math.ceil(self.maxFileSize/3.0)) - sum(publicFileListSizes):
            return 9

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "rb")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 6

        signatureToVerify = SHA256.new()
        signatureToVerify.update(
            "addPublicFile;name: " + user + ";fileNameB64: " + fileNameB64 + ";fileB64Size: " + str(fileB64Size))
        signature = utils.base64_decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature is True:

            randomIdB64 = ""

            while True:
                randomIdB64 = utils.base64_encode(utils.get_random_bytes(48))
                if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd"):
                    if not os.path.isdir(self.databaseDirectory + "/FileSegments/" + randomIdB64):
                        break
                self.log("1 in a 2^384 possibilities. AMAZINGGGGGG", debug=True)

            os.mkdir(self.databaseDirectory + "/FileSegments/" + randomIdB64)

            fileTrans = fileTransfer.FileTransfer(clientHandler.clientSocket, clientHandler.clientAddress,
                                                  self, self.serverMaster, clientHandler.timeOutController.timeout,
                                                  self.databaseDirectory + "/FileSegments/" + randomIdB64 + "/",
                                                  fileB64Size,
                                                  self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd",
                                                  clientHandler, self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl",
                                                  "fileName:{0}.id:{1}.size:{2},".format(fileNameB64, randomIdB64, str(fileB64Size)))
            fileTrans.start()

            return 0

        return 7

    def addHiddenFile(self, user, fileNameB64, fileB64Size, signatureB64, clientHandler):
        # type: (str, str, str, str, clientHandle.ClientHandle) -> int
        retValue = -1
        try:
            retValue = self.__addHiddenFile(user, fileNameB64, fileB64Size, signatureB64, clientHandler)
        except:
            self.log("Error addHiddenFile", error=True)
        return retValue

    def __addHiddenFile(self, user, fileNameB64, fileB64Size, signatureB64, clientHandler):
        #type: (str, str, str, str, clientHandle.ClientHandle) -> int
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

        if not utils.isInt(fileB64Size):
            return 3

        fileB64Size = int(fileB64Size)

        if not utils.isBase64(signatureB64):
            return 4

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk"):
            return 5

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl"):
            return 8

        hiddenFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl", "rb")
        hiddenFileListFilesSplit = hiddenFileListFile.read().split(",")[1:-1]
        hiddenFileListSizes = [0]
        for i in hiddenFileListFilesSplit:
            hiddenFileListRe = re.search("fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if hiddenFileListRe:
                hiddenFileListSizes.append(int(hiddenFileListRe.group(3)))
        hiddenFileListFile.close()

        if fileB64Size > (4*math.ceil(self.maxFileSize/3.0)) - sum(hiddenFileListSizes):
            return 9

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "rb")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 6

        signatureToVerify = SHA256.new()
        signatureToVerify.update(
            "addHiddenFile;name: " + user + ";fileNameB64: " + fileNameB64 + ";fileB64Size: " + str(fileB64Size))
        signature = utils.base64_decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature is True:

            randomIdB64 = ""

            while True:
                randomIdB64 = utils.base64_encode(utils.get_random_bytes(48))
                if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd"):
                    if not os.path.isdir(self.databaseDirectory + "/FileSegments/" + randomIdB64):
                        break
                self.log("1 in a 2^384 possibilities. AMAZINGGGGGG", debug=True)

            os.mkdir(self.databaseDirectory + "/FileSegments/" + randomIdB64)

            fileTrans = fileTransfer.FileTransfer(clientHandler.clientSocket, clientHandler.clientAddress,
                                                  self, self.serverMaster, clientHandler.timeOutController.timeout,
                                                  self.databaseDirectory + "/FileSegments/" + randomIdB64 + "/",
                                                  fileB64Size,
                                                  self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd",
                                                  clientHandler,
                                                  self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.pufl",
                                                  "fileName:{0}.id:{1}.size:{2},".format(fileNameB64, randomIdB64,
                                                                                         str(fileB64Size)))
            fileTrans.start()

            return 0

        return 7

    def addPrivateFile(self, user, fileNameB64, fileB64Size, signatureB64, clientHandler):
        # type: (str, str, str, str, clientHandle.ClientHandle)
        retValue = -1
        try:
            retValue = self.__addPrivateFile(user, fileNameB64, fileB64Size, signatureB64, clientHandler)
        except:
            self.log("Error addPrivateFile", error=True)
        return retValue

    def __addPrivateFile(self, user, fileNameB64, fileB64Size, signatureB64, clientHandler):
        #type: (str, str, str, str, clientHandle.ClientHandle) -> int
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

        if not utils.isInt(fileB64Size):
            return 3

        fileB64Size = int(fileB64Size)

        if not utils.isBase64(signatureB64):
            return 4

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk"):
            return 5

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl"):
            return 8

        privateFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl", "rb")
        privateFileListFilesSplit = privateFileListFile.read().split(",")[1:-1]
        privateFileSizes = [0]
        for i in privateFileListFilesSplit:
            privateFileListRe = re.search("fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if privateFileListRe:
                privateFileSizes.append(int(privateFileListRe.group(3)))
        privateFileListFile.close()

        if fileB64Size > (4 * math.ceil(self.maxFileSize / 3.0)) - sum(privateFileSizes):
            return 9

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "rb")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 6

        signatureToVerify = SHA256.new()
        signatureToVerify.update(
            "addPrivateFile;name: " + user + ";fileNameB64: " + fileNameB64 + ";fileB64Size: " + str(fileB64Size))
        signature = utils.base64_decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature is True:

            randomIdB64 = ""

            while True:
                randomIdB64 = utils.base64_encode(utils.get_random_bytes(48))
                if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd"):
                    break
                self.log("1 in a 2^384 possibilities. AMAZINGGGGGG", debug=True)


            os.mkdir(self.databaseDirectory + "/FileSegments/" + randomIdB64)

            fileTrans = fileTransfer.FileTransfer(clientHandler.clientSocket, clientHandler.clientAddress,
                                                  self, self.serverMaster, clientHandler.timeOutController.timeout,
                                                  self.databaseDirectory + "/FileSegments/" + randomIdB64 + "/",
                                                  fileB64Size,
                                                  self.databaseDirectory + "/Profiles/" + user + "/" + randomIdB64 + ".fd",
                                                  clientHandler,
                                                  self.databaseDirectory + "/Profiles/" + user + "/privateFileList.pufl",
                                                  "fileName:{0}.id:{1}.size:{2},".format(fileNameB64, randomIdB64,
                                                                                         str(fileB64Size)))

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

    def __getPublicFileList(self, user):
        # type: (str) -> list
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Missing Public File List (PUFL))

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + user):
            return [1, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl"):
            return [2, ""]

        publicFileList = open(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl", "rb")  # Stands for Public File List (PUFL)
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

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "rb")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return [5, ""]

        signatureToVerify = SHA256.new()
        signatureToVerify.update("getHiddenFileList;name: " + user)
        signature = utils.base64_decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature:
            hiddenFileList = open(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl",
                                  "rb")  # Stands for Hidden File List (HFL)
            hiddenFileListContents = hiddenFileList.read()
            hiddenFileList.close()
            return [0, hiddenFileListContents]

        return [6, ""]

    def getPrivateFileList(self, user, signatureB64):
        # type: (str, str) -> list
        retValue = [-1, ""]
        try:
            retValue = self.__getPrivateFileList(user, signatureB64)
        except:
            self.log("Error getPrivateFileList", error=True)
        return retValue

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

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "rb")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return [5, ""]

        signatureToVerify = SHA256.new()
        signatureToVerify.update("getPrivateFileList;name: " + user)
        signature = utils.base64_decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature:
            privateFileList = open(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl",
                                   "rb")  # Stands for Hidden File List (HFL)
            privateFileListContents = privateFileList.read()
            privateFileList.close()
            return [0, privateFileListContents]

        return [6, ""]

    def getFile(self, user, fileIdB64):  # Works for both Public & Hidden Files
        # type: (str, str) -> list
        retValue = [-1, ""]
        try:
            retValue = self.__getFile(user, fileIdB64)
        except:
            self.log("Error getFile", error=True)
        return retValue

    def __getFile(self, user, fileIdB64):
        # type: (str, str) -> list
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Missing Public File List (PUFL),
        #              3 - Missing Hidden File List (HFL),
        #              4 - Invalid File Id Characters,
        #              5 - File In A File List but Nonexistent,
        #              6 - File Not Found)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + user):
            return [1, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl"):
            return [2, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl"):
            return [3, ""]

        if not utils.isBase64(fileIdB64):
            return [4, ""]

        publicFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl", "rb")
        hiddenFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl", "rb")

        publicFileListContents = publicFileListFile.read()
        hiddenFileListContents = hiddenFileListFile.read()

        publicFileListFile.close()
        hiddenFileListFile.close()

        publicFileListContentsSplit = publicFileListContents.split(",")
        publicFileListContentsSplit = publicFileListContentsSplit[1:-1]

        hiddenFileListContentsSplit = hiddenFileListContents.split(",")
        hiddenFileListContentsSplit = hiddenFileListContentsSplit[1:-1]

        allIds = []
        for i in publicFileListContentsSplit:
            idRe = re.search("fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if idRe:
                allIds.append(idRe.group(2))
        for i in hiddenFileListContentsSplit:
            idRe = re.search("fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if idRe:
                allIds.append(idRe.group(2))

        #self.log("Allids: {}".format(str(allIds)), debug=True)
        #self.log("FileIDB64: {}".format(fileIdB64),debug=True)

        if fileIdB64 in allIds:
            if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/" + fileIdB64 + ".fd"):
                return [5, ""]
            fileB64File = open(self.databaseDirectory + "/Profiles/" + user + "/" + fileIdB64 + ".fd", "rb")
            fileB64 = fileB64File.read()
            fileB64File.close()
            return [0, fileB64]
        else:
            return [6, ""]

    def getPrivateFile(self, user, fileIdB64, signatureB64):
        # type: (str, str, str) -> list
        retValue = [-1, ""]
        try:
            retValue = self.__getPrivateFile(user, fileIdB64, signatureB64)
        except:
            self.log("Error getPrivateFile", error=True)
        return retValue

    def __getPrivateFile(self, user, fileIdB64, signatureB64):
        # type: (str, str, str) -> list
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Strange Error Where User Doesn't Have PK,
        #              3 - Invalid Signature Characters,
        #              4 - Invalid Id Characters,
        #              5 - Missing Private File List (PRFL),
        #              6 - Error Importing User PK,
        #              7 - Faulty Signature,
        #              8 - File Not Found,
        #              9 - File In A File List but Nonexistent)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + user):
            return [1, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk"):
            return [2, ""]

        if not utils.isBase64(signatureB64):
            return [3, ""]

        if not utils.isBase64(fileIdB64):
            return [4, ""]

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl"):
            return [5, ""]

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "rb")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return [6, ""]

        signatureToVerify = SHA256.new()
        signatureToVerify.update("getPrivateFile;name: " + user + ";id: " + fileIdB64)
        signature = utils.base64_decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature:
            privateFileList = open(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl",
                                   "rb")
            privateFileListSplit = privateFileList.read().split(",")
            privateFileListSplit = privateFileListSplit[1:-1]
            privateFileList.close()

            allIds = []
            for i in privateFileListSplit:
                idRe = re.search("fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
                if idRe:
                    allIds.append(idRe.group(2))

            if fileIdB64 in allIds:
                if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/" + fileIdB64 + ".fd"):
                    return [9, ""]
                fileFile = open(self.databaseDirectory + "/Profiles/" + user + "/" + fileIdB64 + ".fd", "rb")
                fileContents = fileFile.read()
                fileFile.close()
                return [0, fileContents]
            else:
                return [8, ""]

        return [7, ""]

    def deleteFile(self, user, fileIdB64, signatureB64):
        #type: (str, str, str) -> int
        retValue = -1
        try:
            retValue = self.__deleteFile(user, fileIdB64, signatureB64)
        except:
            self.log("Error deleteFile", error=True)
        return retValue

    def __deleteFile(self, user, fileIdB64, signatureB64):
        #type: (str, str, str) -> int
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Invalid Signature Characters,
        #              3 - Invalid Id Characters,
        #              4 - Missing Public File List (PUFL),
        #              5 - Missing Hidden File List (HFL),
        #              6 - Missing Private File List (PRFL),
        #              7 - Strange Error Where User Doesn't Have PK,
        #              8 - Error Importing User PK,
        #              9 - Faulty Signature,
        #              10 - File not found,
        #              11 - File In A File List but Nonexistent)

        if not os.path.isdir(self.databaseDirectory + "/Profiles/" + user):
            return 1

        if not utils.isBase64(signatureB64):
            return 2

        if not utils.isBase64(fileIdB64):
            return 3

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl"):
            return 4

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl"):
            return 5

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl"):
            return 6

        if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk"):
            return 7

        pkFile = open(self.databaseDirectory + "/Profiles/" + user + "/publickey.pk", "rb")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 8

        signatureToVerify = SHA256.new()
        signatureToVerify.update("deleteFile;name: " + user + ";id: " + fileIdB64)
        signature = utils.base64_decode(signatureB64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signatureToVerify, signature)
            validSignature = True
        except:
            validSignature = False

        if validSignature:
            publicFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl", "rb")
            hiddenFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl", "rb")
            privateFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl", "rb")

            publicFileListSplitComma = publicFileListFile.read().split(",")[1:-1]
            hiddenFileListSplitComma = hiddenFileListFile.read().split(",")[1:-1]
            privateFileListSplitComma = privateFileListFile.read().split(",")[1:-1]

            found = False
            index = 0

            for i in range(0, len(publicFileListSplitComma)):
                if "id:" + fileIdB64 in publicFileListSplitComma[i]:
                    found = True
                    index = i
                    break

            if found:
                publicFileListSplitComma.pop(index)
            else:
                for i in range(0, len(hiddenFileListSplitComma)):
                    if "id:" + fileIdB64 in hiddenFileListSplitComma[i]:
                        found = True
                        index = i
                        break
                if found:
                    hiddenFileListSplitComma.pop(index)
                else:
                    for i in range(0, len(privateFileListSplitComma)):
                        if "id:" + fileIdB64 in privateFileListSplitComma[i]:
                            found = True
                            index = i
                            break
                    if found:
                        privateFileListSplitComma.pop(index)
                    else:
                        return 10

            fileToDelete = fileIdB64 + ".fd"
            if not os.path.isfile(self.databaseDirectory + "/Profiles/" + user + "/" + fileToDelete):
                return 11

            # Could potentially be exploited to remove any file, but we have sanitized the input to be Base64
            os.remove(self.databaseDirectory + "/Profiles/" + user + "/" + fileToDelete)

            publicFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/publicFileList.pufl", "wb")
            hiddenFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/hiddenFileList.hfl", "wb")
            privateFileListFile = open(self.databaseDirectory + "/Profiles/" + user + "/privateFileList.prfl", "wb")

            result = ","

            for i in publicFileListSplitComma:
                result += i + ","

            publicFileListFile.write(result)
            publicFileListFile.close()

            result = ","

            for i in hiddenFileListSplitComma:
                result += i + ","

            hiddenFileListFile.write(result)
            hiddenFileListFile.close()

            result = ","

            for i in privateFileListSplitComma:
                result += i + ","

            privateFileListFile.write(result)
            privateFileListFile.close()

            return 0
        else:
            return 9
