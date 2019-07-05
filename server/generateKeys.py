import Crypto.PublicKey.RSA as RSA
import databaseManager
import os
import lineno
import sys

class GenerateKeys:
    def __init__(self, databaseDirectory, keySize):
        self.databaseDirectory = databaseDirectory
        self.keySize = keySize

    def generate(self):
        #type: () -> None

        if not os.path.isdir(self.databaseDirectory):
            print "Error in generateKeys.py, Line {0}: Database directory not found".format(lineno.lineno())
            print "Aborting operation"
            sys.exit(1)

        newKey = RSA.generate(self.keySize)
        newPrivateKeyExported = newKey.export_key()
        newPublicKeyExported = newKey.publickey().export_key()

        privateKeyFile = open(self.databaseDirectory + "\\privateKey.skm", "w")
        privateKeyFile.write(newPrivateKeyExported)
        privateKeyFile.close()
        publicKeyFile = open(self.databaseDirectory + "\\publicKey.pk", "w")
        publicKeyFile.write(newPublicKeyExported)
        publicKeyFile.close()
