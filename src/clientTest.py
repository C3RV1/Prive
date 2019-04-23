from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
import base64
import socket
import time
import threading
import sys
import re

class exitConsole(threading.Thread):
    def __init__(self, running):
        threading.Thread.__init__(self)
        self.running = running

    def run(self):
        command = raw_input("> ")
        if command == "quit":
            self.running[0] = False

def getRandString(len):
    # type: (int) -> str
    returnString = ""
    for x in range(0,len):
        returnString += chr(random.getrandbits(8))
    return returnString

def encryptWithPadding(key, plaintext):
    #type: (str, str) -> tuple
    length = (16 - (len(plaintext) % 16)) + 16 * random.randint(0,14)
    plaintextPadded = plaintext + getRandString(length-1) + chr(length)
    if len(key) != 16 and len(key) != 32 and len(key) != 24:
        return False, ""
    ciphertext = base64.b64encode(AES.new(key).encrypt(plaintextPadded))
    return True, ciphertext

def decryptWithPadding(key, ciphertext):
    #type: (str, str) -> tuple
    print repr(ciphertext)
    if len(key) != 16 and len(key) != 32 and len(key) != 24:
        return False, ""
    ciphertextNotB64 = base64.b64decode(ciphertext)
    plaintextPadded = AES.new(key).decrypt(ciphertextNotB64)
    plaintext = plaintextPadded[:-ord(plaintextPadded[-1])]
    return True, plaintext

def extractData(msg):
    # type: (str) -> tuple

    msgRe = re.search("^(.+);errorCode: (.+)", msg)
    if not msgRe:
        return "", ""

    msgUserReadeable = msgRe.group(1)
    errorCode = msgRe.group(2)

    return msgUserReadeable, errorCode

def superHash(plaintext, rounds):
    if rounds > 1:
        return superHash(SHA256.new(plaintext).digest(), rounds-1)
    else:
        return SHA256.new(plaintext).digest()


if __name__ == "__main__":

    # Server Public Key
    serverPublicKeyFile = open("serverPublicKey.pk", "r")
    serverPublicKeyStr = serverPublicKeyFile.read()
    serverPublicKey = RSA.importKey(serverPublicKeyStr)

    # Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 4373))

    # Session Key
    sessionKey = ""
    while not len(sessionKey) == 32:
        sessionKey = random.long_to_bytes(random.getrandbits(256))
    sessionKeyEncrypted = serverPublicKey.encrypt(sessionKey, 2)[0]
    sessionKeyB64 = base64.b64encode(sessionKeyEncrypted)

    # Message
    msg = "sessionkey: " + sessionKeyB64 + "\r\n"
    sock.send(msg)
    print sock.recv(2048)
    time.sleep(2)

    # Not Erase
    keepAliveMsg = "keepAlive"

    keepAliveEncrypted = encryptWithPadding(sessionKey, keepAliveMsg)

    print len(sessionKey)

    if not keepAliveEncrypted[0]:
        print "Error"
        sys.exit()

    rsaKeys = RSA.generate(2048)
    privateKey = rsaKeys.exportKey()
    publicKey = base64.b64encode(rsaKeys.publickey().exportKey())
    name = "testUsr"
    password = "none"
    pwdLength = 16 - password.__len__()
    password = password + chr(pwdLength) * pwdLength

    vt = random.long_to_bytes(random.getrandbits(1024))
    vtSha = SHA256.new(vt).digest()
    privateKeyEncrypted = encryptWithPadding(password, privateKey)[1]
    vtEncrypted = encryptWithPadding(password, vt)[1]
    vtShaB64 = base64.b64encode(vtSha)

    message = "newUser;name: " + name + ";pkB64: " + publicKey + ";skAesB64: "
    message = message + privateKeyEncrypted + ";vtB64: " + vtShaB64 + ";vtAesB64: " + vtEncrypted

    msgEncrypted = encryptWithPadding(sessionKey, message)[1]
    sock.send(msgEncrypted + "\r\n")

    response = sock.recv(4096 * 2)[:-2]
    decryptedResponse = decryptWithPadding(sessionKey, response)[1]
    decryptedResponse = extractData(decryptedResponse)[1]

    print decryptedResponse

    vtAesMsg = "getVtAesB64;name: " + name
    vtAesMsgEncrypted = encryptWithPadding(sessionKey, vtAesMsg)[1]
    sock.send(vtAesMsgEncrypted + "\r\n")

    response = sock.recv(4096)[:-2]
    decryptedResponse = decryptWithPadding(sessionKey, response)[1]

    print decryptedResponse


    vtAesDecrypted = re.search("^.+;vt: (.+);errorCode: successful", decryptedResponse).group(1)
    vtAesDecrypted = base64.b64encode(decryptWithPadding(password, vtAesDecrypted)[1])


    message = "checkVT;name: " + name + ";vt: " + vtAesDecrypted
    msgEncrypted = encryptWithPadding(sessionKey, message)[1]
    sock.send(msgEncrypted + "\r\n")

    response = sock.recv(4096 * 2)[:-2]
    decryptedResponse = decryptWithPadding(sessionKey, response)[1]

    print decryptedResponse
    print privateKeyEncrypted


    message = "getPK;name: " + name
    msgEncrypted = encryptWithPadding(sessionKey, message)[1]
    sock.send(msgEncrypted + "\r\n")

    response = sock.recv(4096 * 2)[:-2]
    decryptedResponse = decryptWithPadding(sessionKey, response)[1]

    print decryptedResponse
    print privateKeyEncrypted

    interrupt = raw_input("WWWWWWWWaiting:")

    textToSign = SHA256.new("delUser;name: " + name).digest()
    signature = base64.b64encode(random.long_to_bytes(RSA.importKey(privateKey).sign(textToSign, 0)[0]))
    message = "delUser;name: " + name + ";sign: " + signature
    msgEncrypted = encryptWithPadding(sessionKey, message)[1]
    sock.send(msgEncrypted + "\r\n")

    response = sock.recv(4096 * 2)[:-2]
    decryptedResponse = decryptWithPadding(sessionKey, response)[1]

    print decryptedResponse
    print privateKeyEncrypted


    # AES Encryption
    keepAliveMsg = keepAliveEncrypted[1] + "\r\n"

    # Console
    running = [True]
    exitConsoleObj = exitConsole(running)
    exitConsoleObj.start()

    while running[0]:
        time.sleep(5)
        try:
            sock.send(keepAliveMsg)
        except Exception:
            break

    sock.send("quit\r\n")
    sock.close()
