from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Random import random
import zipfile
import sys
import os
import shutil
import re
import base64
import importlib

if __name__ == "__main__":
    if not sys.argv.__len__() == 2:
        raise Exception("No file input")

    if not os.path.isfile(".\\publickey.pk"):
        newRSAKey = RSA.generate(4096)
        print "PK:"
        print newRSAKey.publickey().exportKey()
        print "SK:"
        print newRSAKey.exportKey()
        raise Exception("No Public Key")

    publicKeyFile = open(".\\publickey.pk", "r")
    publicKeyStr = publicKeyFile.read()
    publicKeyFile.close()
    publicKey = RSA.importKey(publicKeyStr)

    filePath = sys.argv[1]
    fileName = os.path.basename(filePath)

    fileSearch = re.search("^([A-Za-z0-9]+-v[0-9]+)\\.prv", fileName)

    if not fileSearch:
        raise Exception("Bad Filename format")

    if os.path.isfile(".\\SavedPrograms\\" + fileSearch.group(1) + "\\main.py"):
        sys.path.append("SavedPrograms\\" + fileSearch.group(1))
        fn = "main"

        importedMainPy = importlib.import_module(fn)
        importedMainClass = getattr(importedMainPy, "MainClass")
        mainInstance = importedMainClass()
        sys.exit()

    if not os.path.isfile(filePath):
        raise Exception("File doesn't exist")

    newPath = ".\\" + fileSearch.group(1) + ".zip"
    shutil.copyfile(filePath, newPath)

    zip_ref = zipfile.ZipFile(newPath)

    programFolder = ".\\" + fileSearch.group(1)
    os.mkdir(programFolder)

    zip_ref.extractall(programFolder + "\\")
    zip_ref.close()

    if not os.path.isfile(programFolder + "\\mainProgram.zip"):
        raise Exception("Not mainProgram.zip file")

    if not os.path.isfile(programFolder + "\\signature.sign"):
        raise Exception("Not signature file")

    mainProgramZipFile = open(programFolder + "\\mainProgram.zip", "r")
    mainProgramZipStr = mainProgramZipFile.read()
    mainProgramZipFile.close()

    mainProgramZipSHA = SHA256.new(mainProgramZipStr).digest()

    signatureFile = open(programFolder + "\\signature.sign", "r")
    signatureStrB64 = signatureFile.read()
    signatureFile.close()

    signature = random.bytes_to_long(base64.b64decode(signatureStrB64))

    validSignature = publicKey.verify(mainProgramZipSHA, (signature, None))

    if validSignature is True:
        zip_ref2 = zipfile.ZipFile(programFolder + "\\mainProgram.zip")
        os.mkdir(".\\SavedPrograms\\" + fileSearch.group(1))
        zip_ref2.extractall(".\\SavedPrograms\\" + fileSearch.group(1))
        zip_ref2.close()

        if not os.path.isfile(".\\SavedPrograms\\" + fileSearch.group(1) + "\\main.py"):
            raise Exception("Not main.py in program")

        sys.path.append("SavedPrograms\\" + fileSearch.group(1))
        fn = "main"

        importedMainPy = importlib.import_module(fn)
        importedMainClass = getattr(importedMainPy, "MainClass")
        mainInstance = importedMainClass()

        # Garebage collection
        shutil.rmtree(".\\" + fileSearch.group(1))
        os.remove(".\\" + fileSearch.group(1) + ".zip")
    else:
        raise Exception("Invalid file signature")

    pass
