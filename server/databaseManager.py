from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Sig
import base64
import threading
import os
import re
import logger
import time
import shutil
import generateKeys
import lineno


class DatabaseManager:

    def __init__(self, databaseDirectory, logFile, unacceptedNameCharacters, keySize):
        #type: (str, str, str, int) -> None
        self.databaseDirectory = databaseDirectory
        self.unacceptedNameCharacters = unacceptedNameCharacters

        if not os.path.isdir(self.databaseDirectory):
            os.mkdir(self.databaseDirectory)
        if not os.path.isdir(self.databaseDirectory + "\\Profiles"):
            os.mkdir(self.databaseDirectory + "\\Profiles")
        if not os.path.isdir(self.databaseDirectory + "\\SessionKeys"):
            os.mkdir(self.databaseDirectory + "\\SessionKeys")
        #if not os.path.isdir(self.databaseDirectory + "\\Chats"):
        #    os.mkdir(self.databaseDirectory + "\\Chats")

        privateKeyPath = self.databaseDirectory + "\\privateKey.skm"  # Private Key Master

        if not os.path.isfile(privateKeyPath):
            print "Private key not found"
            print "Creating private key"
            genKeyObj = generateKeys.GenerateKeys(self.databaseDirectory, keySize)

        privateKeyFile = open(privateKeyPath, "r")
        privateKeyStr = privateKeyFile.read()
        self.privateKey = RSA.importKey(privateKeyStr)

        self.databaseLock = threading.Lock()
        self.logger = logger.Logger(logFile)

    def log(self, msg, printOnScreen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.logger.log("[DatabaseManager]: " + msg, printToScreen=printOnScreen, debug=debug)

    def newSessionKey(self, host, port, sessionKey):
        self.databaseLock.acquire()
        try:
            return self.__newSessionKey(host, port, sessionKey)
        except:
            self.log("Error newSessionKey")
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
        fileToWrite = open(self.databaseDirectory + "\\SessionKeys\\" + host + "_" + str(port) + ".sessionkey", "w")
        fileToWrite.write(sessionKeyDecryptedB64)
        return True

    def deleteSessionKey(self, host, port):
        self.databaseLock.acquire()
        retValue = False
        try:
            retValue = self.__deleteSessionKey(host, port)
        except:
            self.log("Error deleteSessionKey", debug=True)
        finally:
            self.databaseLock.release()
        return retValue

    def __deleteSessionKey(self, host, port):
        #type: (str, int) -> None
        self.databaseLock.acquire()
        #fileToWrite = open(self.databaseDirectory + "\\SessionKeys\\" + host + "_" + str(port) + ".sessionkey", "w")
        #fileToWrite.write("None")
        filePath = self.databaseDirectory + "\\SessionKeys\\" + host + "_" + str(port) + ".sessionkey"
        if not os.path.isfile(filePath):
            self.databaseLock.release()
            return
        os.remove(self.databaseDirectory + "\\SessionKeys\\" + host + "_" + str(port) + ".sessionkey")
        self.databaseLock.release()

    def getSessionKey(self, host, port):
        self.databaseLock.acquire()
        retValue = ()
        try:
            retValue = self.__getSessionKey(host, port)
        except:
            self.log("Error getSessionKey", debug=True)
        finally:
            self.databaseLock.release()
        return retValue

    def __getSessionKey(self, host, port):
        #type: (str, int) -> tuple
        filePath = self.databaseDirectory + "\\SessionKeys\\" + host + "_" + str(port) + ".sessionkey"
        if not os.path.isfile(filePath):
            return False, ""
        fileToRead = open(filePath, "r")
        sessionKey = fileToRead.read()
        if sessionKey == "None":
            return False, ""
        return True, base64.b64decode(sessionKey)

    def newUser(self, name, pk, skAesB64, vtB64, vtAesB64):
        self.databaseLock.acquire()
        retValue = -1
        try:
            retValue = self.__newUser(name, pk, skAesB64, vtB64, vtAesB64)
        except:
            self.log("Error newUser", debug=True)
        finally:
            self.databaseLock.release()
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

        if os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            return 1

        if not re.search("^[a-zA-Z0-9+/=]+$", skAesB64):
            return 3

        if not re.search("^-----BEGIN PUBLIC KEY-----\n[a-zA-Z0-9+/=\n]+-----END PUBLIC KEY-----$", pk):
            return 4

        if not re.search("^[a-zA-Z0-9+/=]+$", vtB64):
            return 5

        if not re.search("^[a-zA-Z0-9+/=]+$", vtAesB64):
            return 6

        os.mkdir(self.databaseDirectory + "\\Profiles\\" + name)

        nameFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\name.username", "w")
        nameFile.write(name)

        pkFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk", "w")  # Public Key
        pkFile.write(pk)

        skFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\privatekey.skaesb64", "w")  # Secret Key Aes
        skFile.write(skAesB64)

        vtFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\validation.vtb64", "w")  # Validation Token
        vtFile.write(vtB64)

        vtAesFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\validationEnc.vtaesb64",
                         "w")  # Validation Token Aes
        vtAesFile.write(vtAesB64)

        os.mkdir(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs")

        #chatsFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\chats.chts", "w")
        #chatsFile.close()

        return 0

    def getVtAesB64(self, name):
        self.databaseLock.acquire()
        retValue = ()
        try:
            retValue = self.__getVtAesB64(name)
        except:
            self.log("Error getVtAesB64")
        finally:
            self.databaseLock.release()
        return retValue

    def __getVtAesB64(self, name):
        #type: (str) -> tuple
        # Returns (errorCode, vtAesB64)
        # Error Codes (0 - All Correct,
        #              1 - User doesn't exist,
        #              2 - Strange Error where there isn't vtaesb64)
        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            return 1, ""

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\validationEnc.vtaesb64"):
            return 2, ""

        vtAesFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\validationEnc.vtaesb64",
                         "r")  # Validation Token Aes
        vtAes = vtAesFile.read()

        return 0, vtAes

    def checkVt(self, name, vtB64, ip, newVtSha, newVtEnc):
        self.databaseLock.acquire()
        retValue = ()
        try:
            retValue = self.__checkVt(name, vtB64, ip, newVtSha, newVtEnc)
        except:
            self.log("Error checkVt")
        finally:
            self.databaseLock.release()
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

        if os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs\\" + ip):
            triesFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs\\" + ip, "r")
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

        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            return 2, 0

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\validation.vtb64"):
            return 3, 0

        if not re.search("^[a-zA-Z0-9+/=]+$", vtB64):
            return 4, 0

        vtFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\validation.vtb64", "r")
        vtB64Correct = vtFile.read()

        vtShaB64 = base64.b64encode(SHA256.new(base64.b64decode(vtB64)).digest())

        if vtShaB64 == vtB64Correct:
            # Empty Ip Tries File
            if os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs\\" + ip):
                os.remove(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs\\" + ip)
            vtFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\validation.vtb64", "w")
            vtFile.write(newVTSha)
            vtFile.close()
            vtEncFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\validationEnc.vtaesb64", "w")
            vtEncFile.write(newVTEnc)
            vtEncFile.close()
            return 0, 0

        ipFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs\\" + ip, "a")
        ipFile.write("Ltest: " + str(time.time()) + "\n")
        return 1, 0

    def getSk_(self, name):
        self.databaseLock.acquire()
        retValue = ()
        try:
            retValue = self.__getSk_(name)
        except:
            self.log("Error getSk_")
        finally:
            self.databaseLock.release()
        return retValue

    def __getSk_(self, name):
        #type: (str) -> tuple
        # Returns errorCode, skb64
        # Error Codes (0 - All Correct,
        #              1 - Strange Error where there isn't private key,
        #              2 - User Doesn't Exist)

        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            return 2, ""

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\privatekey.skaesb64"):
            return 1, ""

        skFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\privatekey.skaesb64", "r")
        sk = skFile.read()

        return 0, sk

    def getPk(self, name):
        self.databaseLock.acquire()
        retValue = ()
        try:
            retValue = self.__getPk(name)
        except:
            self.log("Error getPk")
        finally:
            self.databaseLock.release()
        return retValue

    def __getPk(self, name):
        # type: (str) -> tuple
        # Returns errorCode, pkb64
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Strange Error Where there isn't Public Key)

        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            return 1, ""

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk"):
            return 2, ""

        pkFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk", "r")
        pk = pkFile.read()

        return 0, pk

    def delUser(self, name, signatureB64):
        self.databaseLock.acquire()
        retValue = -1
        try:
            retValue = self.__delUser(name, signatureB64)
        except:
            self.log("Error delUser")
        finally:
            self.databaseLock.release()
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

        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            return 1

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk"):
            return 2

        if not re.search("^[a-zA-Z0-9+/;=\n]+$", signatureB64):
            return 3

        pkFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk", "r")
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
            shutil.rmtree(self.databaseDirectory + "\\Profiles\\" + name)
            return 0

        return 4

    def updateKeys(self, name, signatureB64, newPKB64, newSKAesB64):
        self.databaseLock.acquire()
        retValue = -1
        try:
            retValue = self.__updateKeys(name, signatureB64, newPKB64, newSKAesB64)
        except:
            self.log("Error updateKeys")
        finally:
            self.databaseLock.release()
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

        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            return 1

        if not re.search("^[a-zA-Z0-9+/;=\n]+$", signatureB64):
            return 2

        if not re.search("^[a-zA-Z0-9+/;=\n]+$", newSKAesB64):
            return 3

        if not re.search("^-----BEGIN PUBLIC KEY-----\n[a-zA-Z0-9+/=\n]+-----END PUBLIC KEY-----$", newPK):
            return 4

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk"):
            return 5

        pkFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk", "r")
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
            pkFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk", "w")
            pkFile.write(newPK)
            pkFile.close()

            skFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\privatekey.skaesb64", "w")
            skFile.write(newSKAesB64)
            skFile.close()

            return 0

        return 7

    def addPublicFile(self, user, fileName, fileB64, signatureB64):
        self.databaseLock.acquire()
        retValue = -1
        try:
            retValue = self.__addPublicFile(user, fileName, fileB64, signatureB64)
        except:
            self.log("Error addPublicFile")
        finally:
            self.databaseLock.release()
        return  retValue

    def __addPublicFile(self, user, fileName, fileB64, signatureB64):
        #type: (str, str, str, str) -> int
        return 0

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
