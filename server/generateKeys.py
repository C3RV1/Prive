import Crypto.PublicKey.RSA as RSA
import os
import sys
import json
from config import Config

class GenerateKeys:
    def __init__(self):
        self.database_directory = Config.DATABASE_PATH
        self.key_size = Config.CLIENT_KEYSIZE

    def generate(self):
        #type: () -> None

        if not os.path.isdir(self.database_directory):
            print("Error in generateKeys.py: Database directory not found")
            print("Aborting operation")
            sys.exit(1)

        print("\nGenerating key pair")

        new_key = RSA.generate(self.key_size)
        new_private_key_exported = new_key.export_key()
        new_public_key_exported = new_key.publickey().export_key()

        private_key_file = open(self.database_directory + "/privateKey.skm", "wb")
        private_key_file.write(new_private_key_exported)
        private_key_file.close()
        public_key_file = open(self.database_directory + "/publicKey.pk", "wb")
        public_key_file.write(new_public_key_exported)
        public_key_file.close()

        config_dict = {"host": Config.HOST,
                       "port": Config.PORT,
                       "key-size": Config.CLIENT_KEYSIZE,
                       "rsa-key": new_public_key_exported.decode("ascii"),
                       "pow-0es": Config.POW_NUM_OF_0,
                       "pow-iterations": Config.POW_ITERATIONS,
                       "file-send-chunks": Config.FILE_SEND_CHUNKS}

        print("Creating Prive Config File (PCF) with conf: ")

        for key in config_dict.keys():
            print("{}. {}".format(key, repr(config_dict[key])))

        prive_config_file = open(self.database_directory + "/priveConfigFile.pcf", "w")
        prive_config_file.write(json.dumps(config_dict, sort_keys=True, indent=4))
        prive_config_file.close()

        print("Setup Complete\n")
