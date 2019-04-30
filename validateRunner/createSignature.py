from Crypto.PublicKey import RSA
from Crypto.Random import random
from Crypto.Hash import SHA256
import os
import base64
import zipfile

if __name__ == "__main__":
    if not os.path.isfile(".\\ToBuild\\mainProgram.zip"):
        raise Exception("No program")

    skFile = open("sk.txt", "r")
    sk = RSA.importKey(skFile.read())
    skFile.close()

    zipFile = open(".\\ToBuild\\mainProgram.zip", "r")
    zipSign = base64.b64encode(random.long_to_bytes(sk.sign(SHA256.new(zipFile.read()).digest(),0)[0]))
    zipFile.close()

    signatureFile = open(".\\ToBuild\\signature.sign", "w")
    signatureFile.write(zipSign)
    signatureFile.close()

    filePaths = []

    # Read all directory, subdirectories and file lists
    os.chdir(".\\ToBuild")
    for root, directories, files in os.walk(".\\"):
        for filename in files:
            # Create the full filepath by using os module.
            filePath = filename
            filePaths.append(filePath)

    appNum = 0

    while True:
        if os.path.isfile("..\\output\\NewApp-v" + str(appNum) + ".prv"):
            appNum = appNum + 1
        else:
            break

    zip_file = zipfile.ZipFile("..\\output\\NewApp-v0" + '.prv', 'w')
    with zip_file:
        # writing each file one by one
        for fileToZip in filePaths:
            zip_file.write(fileToZip)

    print "Successful"

    pass
