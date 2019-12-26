import Crypto.PublicKey.RSA as RSA
import databaseManager
import os
import utils
import sys
import json
import config

class GenerateKeys:
    def __init__(self, databaseDirectory, keySize):
        self.databaseDirectory = databaseDirectory
        self.keySize = keySize

    def generate(self):
        #type: () -> None

        if not os.path.isdir(self.databaseDirectory):
            print "Error in generateKeys.py, Line {0}: Database directory not found".format(utils.lineno())
            print "Aborting operation"
            sys.exit(1)

        print "\nGenerating key pair"

        newKey = RSA.generate(self.keySize)
        newPrivateKeyExported = newKey.export_key()
        newPublicKeyExported = newKey.publickey().export_key()

        privateKeyFile = open(self.databaseDirectory + "/privateKey.skm", "w")
        privateKeyFile.write(newPrivateKeyExported)
        privateKeyFile.close()
        publicKeyFile = open(self.databaseDirectory + "/publicKey.pk", "w")
        publicKeyFile.write(newPublicKeyExported)
        publicKeyFile.close()

        configDict = {"host": config.Config.HOST,
                      "port": config.Config.PORT,
                      "key-size": config.Config.CLIENT_KEYSIZE,
                      "rsa-key": newPublicKeyExported}

        print "Creating Prive Config File (PCF) with conf: \n"

        for key in configDict.keys():
            print "{}. {}".format(key, repr(configDict[key]))

        priveConfigFile = open(self.databaseDirectory + "/priveConfigFile.pcf", "w")
        priveConfigFile.write(json.dumps(configDict, sort_keys=True, indent=4))
        priveConfigFile.close()

        print "Setup Complete\n"
