from Crypto.Random import random
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64
import threading
import os
import re
import logger
import time
import shutil


class DatabaseManager:

    def __init__(self, databaseDirectory, logFile, unacceptedNameCharacters):
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
            raise Exception("DatabaseManager: Private Key File doesn't exist: {0}".format(privateKeyPath))

        privateKeyFile = open(privateKeyPath, "r")
        privateKeyStr = privateKeyFile.read()
        self.privateKey = RSA.importKey(privateKeyStr)

        self.databaseLock = threading.Lock()
        self.logger = logger.Logger(logFile)

    def newSessionKey(self, host, port, sessionKey):
        #type: (str, int, str) -> bool
        self.databaseLock.acquire()
        sessionKeyb64decoded = base64.b64decode(sessionKey)
        sessionKeyDecrypted = self.privateKey.decrypt(sessionKeyb64decoded)
        if len(sessionKeyDecrypted) != 16 and len(sessionKeyDecrypted) != 32 and len(sessionKeyDecrypted) != 24:
            self.databaseLock.release()
            return False
        sessionKeyDecryptedB64 = base64.b64encode(sessionKeyDecrypted)
        fileToWrite = open(self.databaseDirectory + "\\SessionKeys\\" + host + "_" + str(port) + ".sessionkey", "w")
        fileToWrite.write(sessionKeyDecryptedB64)
        self.databaseLock.release()
        return True

    def deleteSessionKey(self, host, port):
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
        #type: (str, int) -> tuple
        self.databaseLock.acquire()
        filePath = self.databaseDirectory + "\\SessionKeys\\" + host + "_" + str(port) + ".sessionkey"
        if not os.path.isfile(filePath):
            self.databaseLock.release()
            return False, ""
        fileToRead = open(filePath, "r")
        sessionKey = fileToRead.read()
        if sessionKey == "None":
            self.databaseLock.release()
            return False, ""
        self.databaseLock.release()
        return True, base64.b64decode(sessionKey)

    def newUser(self, name, pk, skAesB64, vtB64, vtAesB64):
        #type: (str, str, str, str, str) -> int
        # Returns errorNumber (0 - All Correct,
        #                      1 - AlreadyExists,
        #                      2 - Bad Characters Name,
        #                      3 - " " Private Key,
        #                      4 - " " Public Key,
        #                      5 - " " Validation Token,
        #                      6 - " " Validation Token Encrypted)

        self.databaseLock.acquire()

        if re.search(".*[" + self.unacceptedNameCharacters + "].*", name):
            self.databaseLock.release()
            return 2

        if os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            self.databaseLock.release()
            return 1

        if not re.search("^[a-zA-Z0-9+/=]+$", skAesB64):
            self.databaseLock.release()
            return 3

        if not re.search("^-----BEGIN PUBLIC KEY-----\n[a-zA-Z0-9+/=\n]+-----END PUBLIC KEY-----$", pk):
            self.databaseLock.release()
            return 4

        if not re.search("^[a-zA-Z0-9+/=]+$", vtB64):
            self.databaseLock.release()
            return 5

        if not re.search("^[a-zA-Z0-9+/=]+$", vtAesB64):
            self.databaseLock.release()
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

        self.databaseLock.release()
        return 0

    def getVtAesB64(self, name):
        #type: (str) -> tuple
        # Returns (errorCode, vtAesB64)
        # Error Codes (0 - All Correct,
        #              1 - User doesn't exist,
        #              2 - Strange Error where there isn't vtaesb64)
        self.databaseLock.acquire()
        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            self.databaseLock.release()
            return 1, ""
        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\validationEnc.vtaesb64"):
            self.databaseLock.release()
            return 2, ""
        vtAesFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\validationEnc.vtaesb64",
                         "r")  # Validation Token Aes
        vtAes = vtAesFile.read()
        self.databaseLock.release()
        return 0, vtAes

    def checkVt(self, name, vtB64, ip, newVTSha, newVTEnc):
        #type: (str, str, str, str, str) -> tuple
        # Returns (errorCode, timeUntilUnlock)
        # Error Codes (0 - Correct,
        #              1 - Incorrect,
        #              2 - User doesn't exist,
        #              3 - Strange Error where there isn't validation token,
        #              4 - Invalid Validation Token Characters,
        #              5 - Locked Account)
        self.databaseLock.acquire()

        if os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs\\" + ip):
            triesFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs\\" + ip, "r")
            triesNotRe = triesFile.read()
            triesNotRe = triesNotRe.split("\n")[:-1]
            triesNotReLast = triesNotRe[-1]
            triesRe = re.search("^Ltest: (.+)$", triesNotReLast)
            if triesRe:
                triesNum = triesNotRe.__len__()
                if float(triesRe.group(1)) + pow(2,triesNum)*0.5 > time.time():
                    self.databaseLock.release()
                    waitingTime = (float(triesRe.group(1)) + pow(2,triesNum)*0.5) - time.time()
                    return 5, waitingTime
            triesFile.close()



        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            self.databaseLock.release()
            return 2, 0

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\validation.vtb64"):
            self.databaseLock.release()
            return 3, 0

        if not re.search("^[a-zA-Z0-9+/=]+$", vtB64):
            self.databaseLock.release()
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
            self.databaseLock.release()
            return 0, 0

        ipFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\triesByIPs\\" + ip, "a")
        ipFile.write("Ltest: " + str(time.time()) + "\n")
        self.databaseLock.release()
        return 1, 0

    def getSk_(self, name):
        #type: (str) -> tuple
        # Returns errorCode, skb64
        # Error Codes (0 - All Correct,
        #              1 - Strange Error where there isn't private key,
        #              2 - User Doesn't Exist)

        self.databaseLock.acquire()

        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            self.databaseLock.release()
            return 2, ""

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\privatekey.skaesb64"):
            self.databaseLock.release()
            return 1, ""

        skFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\privatekey.skaesb64", "r")
        sk = skFile.read()

        self.databaseLock.release()
        return 0, sk

    def getPk(self, name):
        # type: (str) -> tuple
        # Returns errorCode, pkb64
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Strange Error Where there isn't Public Key)

        self.databaseLock.acquire()

        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            self.databaseLock.release()
            return 1, ""

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk"):
            self.databaseLock.release()
            return 2, ""

        pkFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk", "r")
        pk = pkFile.read()

        self.databaseLock.release()
        return 0, pk

    def delUser(self, name, signatureB64):
        # type: (str, str) -> int
        # Returns errorCode
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Strange Error Where The User Doesn't Have PK,
        #              3 - Signature not B64,
        #              4 - Faulty Signature,
        #              5 - Error Importing User PK)

        self.databaseLock.acquire()

        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            self.databaseLock.release()
            return 1

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk"):
            self.databaseLock.release()
            return 2

        if not re.search("^[a-zA-Z0-9+/;=\n]+$", signatureB64):
            self.databaseLock.release()
            return 3

        pkFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            self.databaseLock.release()
            return 5

        signature = random.bytes_to_long(base64.b64decode(signatureB64))

        validSignature = pkKey.verify(SHA256.new("delUser;name: " + name).digest(), (signature, None))

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
            self.databaseLock.release()
            return 0

        self.databaseLock.release()
        return 4

    def updateKeys(self, name, signatureB64, newPKB64, newSKAesB64):
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

        self.databaseLock.acquire()

        newPK = base64.b64decode(newPKB64)

        if not os.path.isdir(self.databaseDirectory + "\\Profiles\\" + name):
            self.databaseLock.release()
            return 1

        if not re.search("^[a-zA-Z0-9+/;=\n]+$", signatureB64):
            self.databaseLock.release()
            return 2

        if not re.search("^[a-zA-Z0-9+/;=\n]+$", newSKAesB64):
            self.databaseLock.release()
            return 3

        if not re.search("^-----BEGIN PUBLIC KEY-----\n[a-zA-Z0-9+/=\n]+-----END PUBLIC KEY-----$", newPK):
            self.databaseLock.release()
            return 4

        if not os.path.isfile(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk"):
            self.databaseLock.release()
            return 5

        pkFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            self.databaseLock.release()
            return 6

        signatureToVerify = "updateKeys;name: " + name + ";newPK: " + newPK + ";newSKAesB64: " + newSKAesB64
        signatureToVerify = SHA256.new(signatureToVerify).digest()
        signature = random.bytes_to_long(base64.b64decode(signatureB64))

        validSignature = pkKey.verify(signatureToVerify, (signature, None))

        if validSignature is True:
            pkFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\publickey.pk", "w")
            pkFile.write(newPK)
            pkFile.close()

            skFile = open(self.databaseDirectory + "\\Profiles\\" + name + "\\privatekey.skaesb64", "w")
            skFile.write(newSKAesB64)
            skFile.close()

            self.databaseLock.release()
            return 0

        self.databaseLock.release()
        return 7

    # Not Used
    def __createChat(self, creatorName, chatName, keys, firstMessage, signature, messageValidationSha):
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

        signToVerify = "newChat;creatorName: " + creatorName + ";chatName: " + chatName + ";keys: " + keys
        signToVerify = signToVerify + ";firstMessage: " + firstMessage

        pkFile = open(self.databaseDirectory + "\\Profiles\\" + creatorName + "\\publickey.pk", "r")
        pk = pkFile.read()
        pkFile.close()
        pkKey = RSA.importKey(pk)

        signature = random.bytes_to_long(base64.b64decode(signature))

        validSignature = pkKey.verify(signToVerify, (signature, None))

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

        return 0
