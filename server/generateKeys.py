import Crypto.PublicKey.RSA as RSA
import databaseManager
import os
import utils
import sys
import json
from config import Config

class GenerateKeys:
    def __init__(self):
        self.databaseDirectory = Config.DATABASE_PATH
        self.keySize = Config.CLIENT_KEYSIZE

    def generate(self):
        #type: () -> None

        if not os.path.isdir(self.databaseDirectory):
            print "Error in generateKeys.py: Database directory not found"
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

        configDict = {"host": Config.HOST,
                      "port": Config.PORT,
                      "key-size": Config.CLIENT_KEYSIZE,
                      "rsa-key": newPublicKeyExported,
                      "pow-0es": Config.POW_NUM_OF_0,
                      "pow-iterations": Config.POW_ITERATIONS}

        print "Creating Prive Config File (PCF) with conf: \n"

        for key in configDict.keys():
            print "{}. {}\n".format(key, repr(configDict[key]))

        priveConfigFile = open(self.databaseDirectory + "/priveConfigFile.pcf", "w")
        priveConfigFile.write(json.dumps(configDict, sort_keys=True, indent=4))
        priveConfigFile.close()

        print "Setup Complete\n"
