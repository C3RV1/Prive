import math
import os
import re
import shutil
import threading
import time

from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Sig

import clientHandle
import fileSend
import fileTransfer
import generateKeys
import logger
import server
import utils
from config import Config


# ALL file management is done in this file and in generateKeys.py


class DatabaseManager(threading.Thread):
    def __init__(self, server_master):
        # type: (server.Server) -> None
        threading.Thread.__init__(self)
        self.database_directory = Config.DATABASE_PATH
        self.unaccepted_name_characters = Config.ALLOWED_NAME_CHARCTERS_RE

        if not os.path.isdir(self.database_directory):
            os.mkdir(self.database_directory)
        if not os.path.isdir(self.database_directory + "/Profiles"):
            os.mkdir(self.database_directory + "/Profiles")
        if not os.path.isdir(self.database_directory + "/SessionKeys"):
            os.mkdir(self.database_directory + "/SessionKeys")
        if not os.path.isdir(self.database_directory + "/Challenges"):
            os.mkdir(self.database_directory + "/Challenges")
        if not os.path.isdir(self.database_directory + "/FileSegments"):
            os.mkdir(self.database_directory + "/FileSegments")

        private_key_path = self.database_directory + "/privateKey.skm"  # Private Key Master

        if not os.path.isfile(private_key_path):
            print("Private key not found")
            print("Creating private key")
            gen_key_obj = generateKeys.GenerateKeys()
            gen_key_obj.generate()

        private_key_file = open(private_key_path, "rb")
        private_key_str = private_key_file.read()
        self.private_key = RSA.importKey(private_key_str)

        self.database_lock = threading.Lock()
        self.logger = logger.Logger()
        self.max_file_size = Config.MAX_FILE_SIZE
        self.server_master = server_master

        self.available_functions = ["newUser", "getVTAesB64", "checkVT", "getSK", "getPK",
                                    "delUser", "updateKeys", "addPublicFile",
                                    "addHiddenFile", "addPrivateFile",
                                    "getPublicFileList", "getHiddenFileList",
                                    "getPrivateFileList", "getFile",
                                    "getPrivateFile", "deleteFile", "requestChallenge"]

        self.function_parameters_length = {"newUser": 7,
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
                                           "getFile": 3,
                                           "getPrivateFile": 4,
                                           "deleteFile": 3,
                                           "requestChallenge": 1}

        self.function_name_to_func = {"newUser": self.new_user,
                                      "getVTAesB64": self.get_vt_aes_b64,
                                      "checkVT": self.check_vt,
                                      "getSK": self.get_sk_,
                                      "getPK": self.get_pk,
                                      "delUser": self.del_user,
                                      "updateKeys": self.update_keys,
                                      "addPublicFile": self.add_public_file,
                                      "addHiddenFile": self.add_hidden_file,
                                      "addPrivateFile": self.add_private_file,
                                      "getPublicFileList": self.get_public_file_list,
                                      "getHiddenFileList": self.get_hidden_file_list,
                                      "getPrivateFileList": self.get_private_file_list,
                                      "getFile": self.get_file,
                                      "getPrivateFile": self.get_private_file,
                                      "deleteFile": self.delete_file,
                                      "requestChallenge": self.request_challenge}

        self.database_queue_lock = threading.Lock()
        self.database_queue = []

        self.id_queue_dictionary_lock = threading.Lock()
        self.id_queue_dictionary = {}

        self.results_dictionary_lock = threading.Lock()
        self.results_dictionary = {}

    def log(self, msg, print_on_screen=True, debug=False, error=False):
        # type: (str, bool, bool, bool) -> None
        self.logger.log("DatabaseManager", msg, print_to_screen=print_on_screen, debug=debug, error=error)

    # Queue Functions

    def run(self):
        while self.server_master.running.return_running():
            while len(self.database_queue) > 0:
                self.database_lock.acquire()

                self.database_queue_lock.acquire()
                actionToDo = self.database_queue.pop(0)
                self.database_queue_lock.release()

                self.do_action(actionToDo)

                self.database_lock.release()
            time.sleep(0.05)

    def do_action(self, action_id):
        if action_id not in self.id_queue_dictionary:
            self.log("Id {} not in queue dictionary but in databaseQueue".format(action_id), error=True)
            return

        self.id_queue_dictionary_lock.acquire()
        actionData = self.id_queue_dictionary[action_id]
        self.id_queue_dictionary_lock.release()

        if "function" not in actionData:
            self.log("Id {} in queue dictionary hasn't got a function key".format(action_id), error=True)
            return
        if "params" not in actionData:
            self.log("Id {} in queue dictionary hasn't got a params key".format(action_id), error=True)
            return

        function = actionData["function"]
        params = actionData["params"]

        if function not in self.available_functions:
            self.log("Id {} in queue dictionary function {} not found".format(action_id, function), error=True)
            return

        if function not in self.function_parameters_length:
            self.log("Id {} in queue dictionary function {} not in functionParameters".format(action_id, function),
                     error=True)
            return

        if not len(params) == self.function_parameters_length[function]:
            self.log("Id {} in queue dictionary function {} wrong arguments length: {}".format(action_id, function,
                                                                                               len(params)),
                     error=True)
            return

        if function not in self.function_name_to_func:
            self.log("Id {} in queue dictionary function {} not in functionNameToFunc".format(action_id, function),
                     error=True)
            return

        result = self.function_name_to_func[function](*params)

        self.results_dictionary_lock.acquire()
        self.results_dictionary[action_id] = result
        self.results_dictionary_lock.release()

    def add_to_queue(self, function, params):
        # type: (str, tuple) -> str
        # self.log("Adding to queue {}".format(function), debug=True)
        if function not in self.available_functions:
            self.log("Function {} not in availableFunctions", error=True)
            return ""
        while True:
            newId = utils.base64_encode(utils.get_random_bytes(48))
            if newId not in self.database_queue:
                break

        self.database_queue_lock.acquire()
        self.database_queue.append(newId)
        self.database_queue_lock.release()

        self.id_queue_dictionary_lock.acquire()
        self.id_queue_dictionary[newId] = {"function": function, "params": params}
        self.id_queue_dictionary_lock.release()

        return newId

    def execute_function(self, function, params):
        action_id = self.add_to_queue(function, params)

        if action_id == "":
            return -1

        while action_id not in self.results_dictionary:
            time.sleep(0.02)

        self.results_dictionary_lock.acquire()
        result = self.results_dictionary[action_id]
        del self.results_dictionary[action_id]
        self.results_dictionary_lock.release()

        return result

    # Security section

    def new_session_key(self, host, port, session_key):
        # type: (str, int, bytes) -> bool
        self.database_lock.acquire()
        try:
            return self.__new_session_key(host, port, session_key)
        except:
            self.log("Error newSessionKey", debug=False, error=True)
            return False
        finally:
            self.database_lock.release()

    def __new_session_key(self, host, port, session_key):
        # type: (str, int, bytes) -> bool
        session_key_b64decoded = utils.base64_decode(session_key)
        session_key_decrypted = PKCS1_OAEP.new(self.private_key).decrypt(session_key_b64decoded)
        if len(session_key_decrypted) != 16 and len(session_key_decrypted) != 32 and len(session_key_decrypted) != 24:
            return False
        session_key_decrypted_b64 = utils.base64_encode(session_key_decrypted)
        file_to_write = open(self.database_directory + "/SessionKeys/" + host + "_" + str(port) + ".sessionkey", "wb")
        file_to_write.write(session_key_decrypted_b64)
        return True

    def delete_session_key(self, host, port):
        # type: (str, int) -> None
        self.database_lock.acquire()
        try:
            self.__delete_session_key(host, port)
        except:
            self.log("Error deleteSessionKey", error=True)
        finally:
            self.database_lock.release()

    def __delete_session_key(self, host, port):
        # type: (str, int) -> None
        file_path = self.database_directory + "/SessionKeys/" + host + "_" + str(port) + ".sessionkey"
        if not os.path.isfile(file_path):
            return
        os.remove(self.database_directory + "/SessionKeys/" + host + "_" + str(port) + ".sessionkey")

    def get_session_key(self, host, port):
        # type: (str, int) -> tuple
        self.database_lock.acquire()
        ret_value = (-1, "")
        try:
            ret_value = self.__get_session_key(host, port)
        except:
            self.log("Error getSessionKey", error=True)
        finally:
            self.database_lock.release()
        return ret_value

    def __get_session_key(self, host, port):
        # type: (str, int) -> tuple
        file_path = self.database_directory + "/SessionKeys/" + host + "_" + str(port) + ".sessionkey"
        if not os.path.isfile(file_path):
            return False, b""
        file_to_read = open(file_path, "rb")
        session_key = file_to_read.read()
        if session_key == b"None":
            return False, b""
        return True, utils.base64_decode(session_key)

    def request_challenge(self, ip):
        # type: (str) -> tuple
        ret_value = (-1, b"")
        try:
            ret_value = self.__request_challenge(ip)
        except:
            self.log("Error requestChallenge", error=True)
        return ret_value

    def __request_challenge(self, ip):
        # type: (str) -> tuple
        if not os.path.isfile(self.database_directory + "/Challenges/" + ip + ".chll"):
            random_challenge = utils.base64_encode(utils.get_random_bytes(48))

            chl_file = open(self.database_directory + "/Challenges/" + ip + ".chll", "wb")
            chl_file.write(random_challenge)
            chl_file.close()

        chl_file = open(self.database_directory + "/Challenges/" + ip + ".chll", "rb")
        challenge = chl_file.read()
        chl_file.close()
        return 0, challenge

    def check_pow_(self, proof_of_work, ip):
        # type: (str, str) -> int
        if not os.path.isfile(self.database_directory + "/Challenges/" + ip + ".chll"):
            return 1

        challenge_file = open(self.database_directory + "/Challenges/" + ip + ".chll", "rb")
        challenge = challenge_file.read()
        challenge_file.close()

        try:
            challenge = utils.base64_decode(challenge)
        except Exception as e:
            self.log("Proof of work error decoding base64. Error: {}".format(e), error=True)
            try:
                os.remove(self.database_directory + "/Challenges/" + ip + ".chll")
            except:
                pass
            return 1

        challenge_solved = challenge + proof_of_work

        check = utils.check_proof_of_work(challenge_solved, Config.POW_NUM_OF_0, Config.POW_ITERATIONS)

        if check:
            try:
                os.remove(self.database_directory + "/Challenges/" + ip + ".chll")
            except:
                pass
            return 0
        else:

            try:
                os.remove(self.database_directory + "/Challenges/" + ip + ".chll")
            except:
                pass
            return 2

    # User section

    def new_user(self, name, pk, sk_aes_b64, vt_b64, vt_aes_b64, proof_of_work, ip):
        # type: (bytes, bytes, bytes, bytes, bytes, bytes, str) -> int
        ret_value = -1
        try:
            ret_value = self.__new_user(name, pk, sk_aes_b64, vt_b64, vt_aes_b64, proof_of_work, ip)
        except:
            self.log("Error newUser", error=True)
        return ret_value

    def __new_user(self, name, pk, sk_aes_b64, vt_b64, vt_aes_b64, proof_of_work, ip):
        # type: (bytes, bytes, bytes, bytes, bytes, bytes, str) -> int
        # Returns errorNumber (0 - All Correct,
        #                      1 - AlreadyExists,
        #                      2 - Bad Characters Name,
        #                      3 - " " Private Key,
        #                      4 - " " Public Key,
        #                      5 - " " Validation Token,
        #                      6 - " " Validation Token Encrypted,
        #                      7 - " " Proof of Work,
        #                      8/9 - Proof of work errors (checkPOW_))

        if not re.search(self.unaccepted_name_characters, name):
            return 2

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(name).decode("ascii")

        if os.path.isdir(user_folder):
            return 1

        if not utils.is_base64(sk_aes_b64):
            return 3

        if not re.search(b"^-----BEGIN PUBLIC KEY-----\n[a-zA-Z0-9+/=\n]+-----END PUBLIC KEY-----$", pk):
            return 4

        if not utils.is_base64(vt_b64):
            return 5

        if not utils.is_base64(vt_aes_b64):
            return 6

        if not utils.is_base64(proof_of_work):
            return 7

        proof_of_work = utils.base64_decode(proof_of_work)

        powVerification = self.check_pow_(proof_of_work, ip)
        if powVerification != 0:
            return powVerification+7

        os.mkdir(user_folder)

        pk_file = open(user_folder + "/publickey.pk", "wb")  # Public Key
        pk_file.write(pk)
        pk_file.close()

        sk_file = open(user_folder + "/privatekey.skaesb64", "wb")  # Secret Key Aes
        sk_file.write(sk_aes_b64)
        sk_file.close()

        vt_file = open(user_folder + "/validation.vtb64", "wb")  # Validation Token
        vt_file.write(vt_b64)
        vt_file.close()

        vt_aes_file = open(user_folder + "/validationEnc.vtaesb64",
                         "wb")  # Validation Token Aes
        vt_aes_file.write(vt_aes_b64)
        vt_aes_file.close()

        os.mkdir(user_folder + "/triesByIPs")

        public_file_list = open(user_folder + "/publicFileList.pufl", "wb")
        public_file_list.write(b",")
        public_file_list.close()

        hidden_file_list = open(user_folder + "/hiddenFileList.hfl", "wb")
        hidden_file_list.write(b",")
        hidden_file_list.close()

        private_file_list = open(user_folder + "/privateFileList.prfl", "wb")
        private_file_list.write(b",")
        private_file_list.close()

        return 0

    def get_vt_aes_b64(self, name):
        # type: (bytes) -> tuple
        ret_value = (-1, b"")
        try:
            ret_value = self.__get_vt_aes_b64(name)
        except:
            self.log("Error getVtAesB64", error=True)
        return ret_value

    def __get_vt_aes_b64(self, name):
        # type: (bytes) -> tuple
        # Returns (errorCode, vtAesB64)
        # Error Codes (0 - All Correct,
        #              1 - User doesn't exist,
        #              2 - Strange Error where there isn't vtaesb64)

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(name).decode("ascii")

        if not os.path.isdir(user_folder):
            return 1, b""

        if not os.path.isfile(user_folder + "/validationEnc.vtaesb64"):
            return 2, b""

        vt_aes_file = open(user_folder + "/validationEnc.vtaesb64", "rb")  # Validation Token Aes
        vt_aes = vt_aes_file.read()

        return 0, vt_aes

    def check_vt(self, name, vt_b64, ip, new_vt_sha, new_vt_enc):
        # type: (bytes, bytes, str, bytes, bytes) -> tuple
        ret_value = (-1, b"")
        try:
            ret_value = self.__check_vt(name, vt_b64, ip, new_vt_sha, new_vt_enc)
        except:
            self.log("Error checkVt", error=True)
        return ret_value

    def __check_vt(self, name, vt_b64, ip, new_vt_sha, new_vt_enc):
        # type: (bytes, bytes, str, bytes, bytes) -> tuple
        # Returns (errorCode, timeUntilUnlock)
        # Error Codes (0 - Correct,
        #              1 - Incorrect,
        #              2 - User doesn't exist,
        #              3 - Strange Error where there isn't validation token,
        #              4 - Invalid Validation Token Characters,
        #              5 - Locked Account)

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(name).decode("ascii")

        if os.path.isfile(user_folder + "/triesByIPs/" + ip):
            tries_file = open(user_folder + "/triesByIPs/" + ip, "rb")
            tries_not_re = tries_file.read()
            tries_not_re = tries_not_re.split(b"\n")[:-1]
            tries_not_re_last = tries_not_re[-1]
            tries_re = re.search(b"^Ltest: (.+)$", tries_not_re_last)
            if tries_re:
                tries_num = tries_not_re.__len__()
                if float(tries_re.group(1)) + pow(2, tries_num)*0.5 > time.time():
                    waiting_time = (float(tries_re.group(1)) + pow(2, tries_num)*0.5) - time.time()
                    return 5, waiting_time
            tries_file.close()

        if not os.path.isdir(user_folder):
            return 2, 0

        if not os.path.isfile(user_folder + "/validation.vtb64"):
            return 3, 0

        if not utils.is_base64(vt_b64):
            return 4, 0

        vt_file = open(user_folder + "/validation.vtb64", "rb")
        vt_b64_correct = vt_file.read()
        vt_file.close()

        vt_sha_b64 = utils.base64_encode(SHA256.new(utils.base64_decode(vt_b64)).digest())

        if vt_sha_b64 == vt_b64_correct:
            # Empty Ip Tries File
            if os.path.isfile(user_folder + "/triesByIPs/" + ip):
                os.remove(user_folder + "/triesByIPs/" + ip)
            vt_file = open(user_folder + "/validation.vtb64", "wb")
            vt_file.write(new_vt_sha)
            vt_file.close()
            vt_enc_file = open(user_folder + "/validationEnc.vtaesb64", "wb")
            vt_enc_file.write(new_vt_enc)
            vt_enc_file.close()
            return 0, 0

        ip_file = open(user_folder + "/triesByIPs/" + ip, "ab")
        ip_file.write(b"Ltest: " + str(time.time()).encode("ascii") + b"\n")
        return 1, 0

    def get_sk_(self, name):
        # type: (bytes) -> list
        ret_value = [-1, b""]
        try:
            ret_value = self.__get_sk_(name)
        except:
            self.log("Error getSk_", error=True)
        return ret_value

    def __get_sk_(self, name):
        # type: (bytes) -> list
        # Returns errorCode, skb64
        # Error Codes (0 - All Correct,
        #              1 - Strange Error where there isn't private key,
        #              2 - User Doesn't Exist)

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(name).decode("ascii")

        if not os.path.isdir(user_folder):
            return [2, b""]

        if not os.path.isfile(user_folder + "/privatekey.skaesb64"):
            return [1, b""]

        sk_file = open(user_folder + "/privatekey.skaesb64", "rb")
        sk = sk_file.read()
        sk_file.close()

        return [0, sk]

    def get_pk(self, name):
        # type: (bytes) -> tuple
        ret_value = (-1, b"")
        try:
            ret_value = self.__get_pk(name)
        except:
            self.log("Error getPk", error=True)
        return ret_value

    def __get_pk(self, name):
        # type: (bytes) -> tuple
        # Returns errorCode, pkb64
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Strange Error Where there isn't Public Key)

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(name).decode("ascii")

        if not os.path.isdir(user_folder):
            return 1, b""

        if not os.path.isfile(user_folder + "/publickey.pk"):
            return 2, b""

        pk_file = open(user_folder + "/publickey.pk", "rb")
        pk = pk_file.read()
        pk_file.close()

        return 0, pk

    def del_user(self, name, signature_b64):
        # type: (bytes, bytes) -> int
        ret_value = -1
        try:
            ret_value = self.__del_user(name, signature_b64)
        except:
            self.log("Error delUser", error=True)
        return ret_value

    def __del_user(self, name, signature_b64):
        # type: (bytes, bytes) -> int
        # Returns errorCode
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Strange Error Where The User Doesn't Have PK,
        #              3 - Signature not B64,
        #              4 - Faulty Signature,
        #              5 - Error Importing User PK)

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(name).decode("ascii")

        if not os.path.isdir(user_folder):
            return 1

        if not os.path.isfile(user_folder + "/publickey.pk"):
            return 2

        if not utils.is_base64(signature_b64):
            return 3

        pk_file = open(user_folder + "/publickey.pk", "rb")
        pk = pk_file.read()
        pk_file.close()

        try:
            pk_key = RSA.importKey(pk)
        except:
            return 5

        signature = utils.base64_decode(signature_b64)
        sign_to_verify = SHA256.new()
        sign_to_verify.update(b"delUser;name: " + name)

        try:
            PKCS1_v1_5_Sig.new(pk_key).verify(sign_to_verify, signature)
            valid_signature = True
        except ValueError:
            valid_signature = False

        if valid_signature is True:
            shutil.rmtree(user_folder)
            return 0

        return 4

    def update_keys(self, name, signature_b64, new_pk_b64, new_sk_aes_b64, new_vt_sha, new_vt_enc):
        # type: (bytes, bytes, bytes, bytes, bytes, bytes) -> int
        ret_value = -1
        try:
            ret_value = self.__update_keys(name, signature_b64, new_pk_b64, new_sk_aes_b64, new_vt_sha, new_vt_enc)
        except:
            self.log("Error updateKeys", error=True)
        return ret_value

    def __update_keys(self, name, signature_b64, new_pk_b64, new_sk_aes_b64, new_vt_sha, new_vt_enc):
        # type: (bytes, bytes, bytes, bytes, bytes, bytes) -> int
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

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(name).decode("ascii")
        new_pk = utils.base64_decode(new_pk_b64)

        if not os.path.isdir(user_folder):
            return 1

        if not utils.is_base64(signature_b64):
            return 2

        if not utils.is_base64(new_sk_aes_b64):
            return 3

        if not re.search(b"^-----BEGIN PUBLIC KEY-----\n[a-zA-Z0-9+/=\n]+-----END PUBLIC KEY-----$", new_pk):
            return 4

        if not utils.is_base64(new_vt_sha):
            return 5

        if not utils.is_base64(new_vt_enc):
            return 6

        if not os.path.isfile(user_folder + "/publickey.pk"):
            return 7

        pk_file = open(user_folder + "/publickey.pk", "rb")
        pk = pk_file.read()
        pk_file.close()

        try:
            pk_key = RSA.importKey(pk)
        except:
            return 8

        signature_to_verify = SHA256.new()
        signature_to_verify.update(b"updateKeys;name: " + name + b";newPK: " + new_pk + b";newSKAesB64: " +
                                   new_sk_aes_b64 + b";newVtSha: " + new_vt_sha + b";newVtEnc: " + new_vt_enc)
        signature = utils.base64_decode(signature_b64)

        try:
            PKCS1_v1_5_Sig.new(pk_key).verify(signature_to_verify, signature)
            valid_signature = True
        except:
            valid_signature = False

        if valid_signature is True:
            pk_file = open(user_folder + "/publickey.pk", "wb")
            pk_file.write(new_pk)
            pk_file.close()

            sk_file = open(user_folder + "/privatekey.skaesb64", "wb")
            sk_file.write(new_sk_aes_b64)
            sk_file.close()

            vt_file = open(user_folder + "/validation.vtb64", "wb")
            vt_file.write(new_vt_sha)
            vt_file.close()

            vt_enc_file = open(user_folder + "/validationEnc.vtaesb64", "wb")
            vt_enc_file.write(new_vt_enc)
            vt_enc_file.close()

            return 0

        return 9

    # File section

    def add_public_file(self, user, file_name_b64, file_b64_size, signature_b64, client_handler):
        # type: (bytes, bytes, bytes, bytes, clientHandle.ClientHandle) -> int
        retValue = -1
        try:
            retValue = self.__add_public_file(user, file_name_b64, file_b64_size, signature_b64, client_handler)
        except Exception as e:
            self.log("Error addPublicFile: {0}".format(e), error=True)
        return retValue

    def __add_public_file(self, user, file_name_b64, file_b64_size, signature_b64, client_handler):
        # type: (bytes, bytes, bytes, bytes, clientHandle.ClientHandle) -> int
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

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(user).decode("ascii")

        if not os.path.isdir(user_folder):
            return 1

        if not utils.is_base64(file_name_b64):
            return 2

        if not utils.is_int(file_b64_size):
            return 3

        file_b64_size = int(file_b64_size)

        if not utils.is_base64(signature_b64):
            return 4

        if not os.path.isfile(user_folder + "/publickey.pk"):
            return 5

        if not os.path.isfile(user_folder + "/publicFileList.pufl"):
            return 8

        public_file_list_file = open(user_folder + "/publicFileList.pufl", "rb")
        public_file_list_files_split = public_file_list_file.read().split(b",")[1:-1]
        public_file_list_sizes = [0]
        for i in public_file_list_files_split:
            public_file_list_re = re.search(b"fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if public_file_list_re:
                public_file_list_sizes.append(int(public_file_list_re.group(3)))
        public_file_list_file.close()

        # self.log("Total size: {}".format(str(sum(publicFileListSizes))), debug=True)

        if file_b64_size > (4 * math.ceil(self.max_file_size / 3.0)) - sum(public_file_list_sizes):
            return 9

        pk_file = open(user_folder + "/publickey.pk", "rb")
        pk = pk_file.read()
        pk_file.close()

        try:
            pkKey = RSA.importKey(pk)
        except:
            return 6

        signature_to_verify = SHA256.new()
        signature_to_verify.update(
            b"addPublicFile;name: " + user + b";fileNameB64: " + file_name_b64 + b";fileB64Size: " +
            str(file_b64_size).encode("ascii"))
        signature = utils.base64_decode(signature_b64)

        try:
            PKCS1_v1_5_Sig.new(pkKey).verify(signature_to_verify, signature)
            valid_signature = True
        except:
            valid_signature = False

        if valid_signature is True:

            random_id_b64 = ""

            while True:
                random_id_b64 = utils.base64_encode(utils.get_random_bytes(48)).decode("ascii")
                if not os.path.isfile(user_folder + "/" + random_id_b64 + ".fd"):
                    if not os.path.isdir(self.database_directory + "/FileSegments/" + random_id_b64):
                        break
                self.log("1 in a 2^384 possibilities. AMAZINGGGGGG", debug=True)

            os.mkdir(self.database_directory + "/FileSegments/" + random_id_b64)

            file_trans = fileTransfer.FileTransfer(client_handler.client_socket, client_handler.client_address,
                                                   self, self.server_master,
                                                   self.database_directory + "/FileSegments/" + random_id_b64 + "/",
                                                   file_b64_size,
                                                   user_folder + "/" + random_id_b64 + ".fd",
                                                   client_handler, user_folder + "/publicFileList.pufl",
                                                   b"fileName:%s.id:%s.size:%d," % (file_name_b64,
                                                                                    random_id_b64.encode("ascii"),
                                                                                    file_b64_size))
            file_trans.start()

            return 0

        return 7

    def add_hidden_file(self, user, file_name_b64, file_b64_size, signature_b64, client_handler):
        # type: (bytes, bytes, bytes, bytes, clientHandle.ClientHandle) -> int
        ret_value = -1
        try:
            ret_value = self.__add_hidden_file(user, file_name_b64, file_b64_size, signature_b64, client_handler)
        except:
            self.log("Error addHiddenFile", error=True)
        return ret_value

    def __add_hidden_file(self, user, file_name_b64, file_b64_size, signature_b64, client_handler):
        # type: (bytes, bytes, bytes, bytes, clientHandle.ClientHandle) -> int
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

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(user).decode("ascii")

        if not os.path.isdir(user_folder):
            return 1

        if not utils.is_base64(file_name_b64):
            return 2

        if not utils.is_int(file_b64_size):
            return 3

        file_b64_size = int(file_b64_size)

        if not utils.is_base64(signature_b64):
            return 4

        if not os.path.isfile(user_folder + "/publickey.pk"):
            return 5

        if not os.path.isfile(user_folder + "/hiddenFileList.hfl"):
            return 8

        hidden_file_list_file = open(user_folder + "/hiddenFileList.hfl", "rb")
        hidden_file_list_files_split = hidden_file_list_file.read().split(b",")[1:-1]
        hidden_file_list_sizes = [0]
        for i in hidden_file_list_files_split:
            hidden_file_list_re = re.search(b"fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if hidden_file_list_re:
                hidden_file_list_sizes.append(int(hidden_file_list_re.group(3)))
        hidden_file_list_file.close()

        if file_b64_size > (4 * math.ceil(self.max_file_size / 3.0)) - sum(hidden_file_list_sizes):
            return 9

        pk_file = open(user_folder + "/publickey.pk", "rb")
        pk = pk_file.read()
        pk_file.close()

        try:
            pk_key = RSA.importKey(pk)
        except:
            return 6

        signature_to_verify = SHA256.new()
        signature_to_verify.update(
            b"addHiddenFile;name: " + user + b";fileNameB64: " + file_name_b64 + b";fileB64Size: " +
            str(file_b64_size).encode("ascii"))
        signature = utils.base64_decode(signature_b64)

        try:
            PKCS1_v1_5_Sig.new(pk_key).verify(signature_to_verify, signature)
            valid_signature = True
        except:
            valid_signature = False

        if valid_signature is True:

            random_id_b64 = ""

            while True:
                random_id_b64 = utils.base64_encode(utils.get_random_bytes(48)).decode("ascii")
                if not os.path.isfile(user_folder + "/" + random_id_b64 + ".fd"):
                    if not os.path.isdir(self.database_directory + "/FileSegments/" + random_id_b64):
                        break
                self.log("1 in a 2^384 possibilities. AMAZINGGGGGG", debug=True)

            os.mkdir(self.database_directory + "/FileSegments/" + random_id_b64)

            file_trans = fileTransfer.FileTransfer(client_handler.client_socket, client_handler.client_address,
                                                   self, self.server_master,
                                                   self.database_directory + "/FileSegments/" + random_id_b64 + "/",
                                                   file_b64_size,
                                                   user_folder + "/" + random_id_b64 + ".fd",
                                                   client_handler,
                                                   user_folder + "/hiddenFileList.hfl",
                                                   b"fileName:%s.id:%s.size:%d," % (file_name_b64,
                                                                                    random_id_b64.encode("ascii"),
                                                                                    file_b64_size))
            file_trans.start()

            return 0

        return 7

    def add_private_file(self, user, file_name_b64, file_b64_size, signature_b64, client_handler):
        # type: (bytes, bytes, bytes, bytes, clientHandle.ClientHandle) -> int
        ret_value = -1
        try:
            ret_value = self.__add_private_file(user, file_name_b64, file_b64_size, signature_b64, client_handler)
        except ZeroDivisionError:
            self.log("Error addPrivateFile", error=True)
        return ret_value

    def __add_private_file(self, user, file_name_b64, file_b64_size, signature_b64, client_handler):
        # type: (bytes, bytes, bytes, bytes, clientHandle.ClientHandle) -> int
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

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(user).decode("ascii")

        if not os.path.isdir(user_folder):
            return 1

        if not utils.is_base64(file_name_b64):
            return 2

        if not utils.is_int(file_b64_size):
            return 3

        file_b64_size = int(file_b64_size)

        if not utils.is_base64(signature_b64):
            return 4

        if not os.path.isfile(user_folder + "/publickey.pk"):
            return 5

        if not os.path.isfile(user_folder + "/privateFileList.prfl"):
            return 8

        private_file_list_file = open(user_folder + "/privateFileList.prfl", "rb")
        private_file_list_files_split = private_file_list_file.read().split(b",")[1:-1]
        private_file_sizes = [0]
        for i in private_file_list_files_split:
            private_file_list_re = re.search(b"fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if private_file_list_re:
                private_file_sizes.append(int(private_file_list_re.group(3)))
        private_file_list_file.close()

        if file_b64_size > (4 * math.ceil(self.max_file_size / 3.0)) - sum(private_file_sizes):
            return 9

        pk_file = open(user_folder + "/publickey.pk", "rb")
        pk = pk_file.read()
        pk_file.close()

        try:
            pk_key = RSA.importKey(pk)
        except:
            return 6

        signature_to_verify = SHA256.new()
        signature_to_verify.update(
            b"addPrivateFile;name: " + user + b";fileNameB64: " + file_name_b64 + b";fileB64Size: " +
            str(file_b64_size).encode("ascii"))
        signature = utils.base64_decode(signature_b64)

        try:
            PKCS1_v1_5_Sig.new(pk_key).verify(signature_to_verify, signature)
            valid_signature = True
        except:
            valid_signature = False

        if valid_signature is True:

            random_id_b64 = ""

            while True:
                random_id_b64 = utils.base64_encode(utils.get_random_bytes(48)).decode("ascii")
                if not os.path.isfile(user_folder + "/" + random_id_b64 + ".fd"):
                    if not os.path.isdir(self.database_directory + "/FileSegments/" + random_id_b64):
                        break
                self.log("1 in a 2^384 possibilities. AMAZINGGGGGG", debug=True)

            os.mkdir(self.database_directory + "/FileSegments/" + random_id_b64)

            file_trans = fileTransfer.FileTransfer(client_handler.client_socket, client_handler.client_address,
                                                   self, self.server_master,
                                                   self.database_directory + "/FileSegments/" + random_id_b64 + "/",
                                                   file_b64_size,
                                                   user_folder + "/" + random_id_b64 + ".fd",
                                                   client_handler,
                                                   user_folder + "/privateFileList.prfl",
                                                   b"fileName:%s.id:%s.size:%d," % (file_name_b64,
                                                                                    random_id_b64.encode("ascii"),
                                                                                    file_b64_size))
            file_trans.start()

            return 0

        return 7

    def get_public_file_list(self, user):
        # type: (bytes) -> list
        ret_value = [-1, b""]
        try:
            ret_value = self.__get_public_file_list(user)
        except:
            self.log("Error getPublicFileList", error=True)
        return ret_value

    def __get_public_file_list(self, user):
        # type: (bytes) -> list
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Missing Public File List (PUFL))

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(user).decode("ascii")

        if not os.path.isdir(user_folder):
            return [1, b""]

        if not os.path.isfile(user_folder + "/publicFileList.pufl"):
            return [2, b""]

        public_file_list = open(user_folder + "/publicFileList.pufl", "rb")  # Stands for Public File List (PUFL)
        public_file_list_contents = public_file_list.read()
        public_file_list.close()
        return [0, public_file_list_contents]

    def get_hidden_file_list(self, user, signature_b64):
        # type: (bytes, bytes) -> list
        ret_value = [-1, b""]
        try:
            ret_value = self.__get_hidden_file_list(user, signature_b64)
        except:
            self.log("Error getHiddenFileList", error=True)
        return ret_value

    def __get_hidden_file_list(self, user, signature_b64):
        # type: (bytes, bytes) -> list
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Missing Hidden File List (HFL),
        #              3 - Wrong SignatureB64 characters,
        #              4 - Strange Error Where User Doesn't have PK,
        #              5 - Error Importing User PK,
        #              6 - Faulty Signature)

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(user).decode("ascii")

        if not os.path.isdir(user_folder):
            return [1, b""]

        if not os.path.isfile(user_folder + "/hiddenFileList.hfl"):
            return [2, b""]

        if not utils.is_base64(signature_b64):
            return [3, b""]

        if not os.path.isfile(user_folder + "/publickey.pk"):
            return [4, b""]

        pk_file = open(user_folder + "/publickey.pk", "rb")
        pk = pk_file.read()
        pk_file.close()

        try:
            pk_key = RSA.importKey(pk)
        except:
            return [5, b""]

        signature_to_verify = SHA256.new()
        signature_to_verify.update(b"getHiddenFileList;name: " + user)
        signature = utils.base64_decode(signature_b64)

        try:
            PKCS1_v1_5_Sig.new(pk_key).verify(signature_to_verify, signature)
            valid_signature = True
        except:
            valid_signature = False

        if valid_signature:
            hidden_file_list = open(user_folder + "/hiddenFileList.hfl", "rb")  # Stands for Hidden File List (HFL)
            hidden_file_list_contents = hidden_file_list.read()
            hidden_file_list.close()
            return [0, hidden_file_list_contents]

        return [6, b""]

    def get_private_file_list(self, user, signature_b64):
        # type: (bytes, bytes) -> list
        ret_value = [-1, b""]
        try:
            ret_value = self.__get_private_file_list(user, signature_b64)
        except:
            self.log("Error getPrivateFileList", error=True)
        return ret_value

    def __get_private_file_list(self, user, signature_b64):
        # type: (bytes, bytes) -> list
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Missing Private File List (PRFL),
        #              3 - Wrong SignatureB64 characters,
        #              4 - Strange Error Where User Doesn't have PK,
        #              5 - Error Importing User PK,
        #              6 - Faulty Signature)

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(user).decode("ascii")

        if not os.path.isdir(user_folder):
            return [1, b""]

        if not os.path.isfile(user_folder + "/privateFileList.prfl"):
            return [2, b""]

        if not utils.is_base64(signature_b64):
            return [3, b""]

        if not os.path.isfile(user_folder + "/publickey.pk"):
            return [4, b""]

        pk_file = open(user_folder + "/publickey.pk", "rb")
        pk = pk_file.read()
        pk_file.close()

        try:
            pk_key = RSA.importKey(pk)
        except:
            return [5, b""]

        signature_to_verify = SHA256.new()
        signature_to_verify.update(b"getPrivateFileList;name: " + user)
        signature = utils.base64_decode(signature_b64)

        try:
            PKCS1_v1_5_Sig.new(pk_key).verify(signature_to_verify, signature)
            valid_signature = True
        except:
            valid_signature = False

        if valid_signature:
            private_file_list = open(user_folder + "/privateFileList.prfl", "rb")  # Stands for Hidden File List (HFL)
            private_file_list_contents = private_file_list.read()
            private_file_list.close()
            return [0, private_file_list_contents]

        return [6, b""]

    def get_file(self, user, file_id_b64, client_handler):  # Works for both Public & Hidden Files
        # type: (bytes, bytes, clientHandle.ClientHandle) -> tuple
        ret_value = -1, 0
        try:
            ret_value = self.__get_file(user, file_id_b64, client_handler)
        except Exception as e:
            self.log("Error getFile: {}".format(e), error=True)
        return ret_value

    def __get_file(self, user, file_id_b64, client_handler):
        # type: (bytes, bytes, clientHandle.ClientHandle) -> tuple
        # Error Codes (0 - All Correct,
        #              1 - User Doesn't Exist,
        #              2 - Missing Public File List (PUFL),
        #              3 - Missing Hidden File List (HFL),
        #              4 - Invalid File Id Characters,
        #              5 - File In A File List but Nonexistent,
        #              6 - File Not Found)

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(user).decode("ascii")

        if not os.path.isdir(user_folder):
            return 1, 0

        if not os.path.isfile(user_folder + "/publicFileList.pufl"):
            return 2, 0

        if not os.path.isfile(user_folder + "/hiddenFileList.hfl"):
            return 3, 0

        if not utils.is_base64(file_id_b64):
            return 4, 0

        public_file_list_file = open(user_folder + "/publicFileList.pufl", "rb")
        hidden_file_list_file = open(user_folder + "/hiddenFileList.hfl", "rb")

        public_file_list_contents = public_file_list_file.read()
        hidden_file_list_contents = hidden_file_list_file.read()

        public_file_list_file.close()
        hidden_file_list_file.close()

        public_file_list_contents_split = public_file_list_contents.split(b",")
        public_file_list_contents_split = public_file_list_contents_split[1:-1]

        hidden_file_list_contents_split = hidden_file_list_contents.split(b",")
        hidden_file_list_contents_split = hidden_file_list_contents_split[1:-1]

        all_ids = []
        sizes = {}
        for i in public_file_list_contents_split:
            id_re = re.search(b"fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if id_re:
                sizes[id_re.group(2)] = int(id_re.group(3))
                all_ids.append(id_re.group(2))
        for i in hidden_file_list_contents_split:
            id_re = re.search(b"fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if id_re:
                sizes[id_re.group(2)] = int(id_re.group(3))
                all_ids.append(id_re.group(2))

        # self.log("Allids: {}".format(str(allIds)), debug=True)
        # self.log("FileIDB64: {}".format(fileIdB64),debug=True)

        if file_id_b64 in all_ids:
            if not os.path.isfile(user_folder + "/" + file_id_b64.decode("ascii") + ".fd"):
                return 5, 0
            file_sender = fileSend.FileSend(client_handler, user_folder + "/" + file_id_b64.decode("ascii") + ".fd")
            file_sender.start()
            return 0, (int(sizes[file_id_b64]) * 3) / 4
        else:
            return 6, 0

    def get_private_file(self, user, file_id_b64, signature_b64, client_handler):
        # type: (bytes, bytes, bytes, clientHandle.ClientHandle) -> tuple
        ret_value = -1, 0
        try:
            ret_value = self.__get_private_file(user, file_id_b64, signature_b64, client_handler)
        except Exception as e:
            self.log("Error getPrivateFile", error=True)
        return ret_value

    def __get_private_file(self, user, file_id_b64, signature_b64, client_handler):
        # type: (bytes, bytes, bytes, clientHandle.ClientHandle) -> tuple
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

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(user).decode("ascii")

        if not os.path.isdir(user_folder):
            return 1, 0

        if not os.path.isfile(user_folder + "/publickey.pk"):
            return 2, 0

        if not utils.is_base64(signature_b64):
            return 3, 0

        if not utils.is_base64(file_id_b64):
            return 4, 0

        if not os.path.isfile(user_folder + "/privateFileList.prfl"):
            return 5, 0

        pk_file = open(user_folder + "/publickey.pk", "rb")
        pk = pk_file.read()
        pk_file.close()

        try:
            pk_key = RSA.importKey(pk)
        except:
            return 6, 0

        signature_to_verify = SHA256.new()
        signature_to_verify.update(b"getPrivateFile;name: " + user + b";id: " + file_id_b64)
        signature = utils.base64_decode(signature_b64)

        try:
            PKCS1_v1_5_Sig.new(pk_key).verify(signature_to_verify, signature)
            valid_signature = True
        except:
            valid_signature = False

        if valid_signature:
            private_file_list = open(user_folder + "/privateFileList.prfl", "rb")
            private_file_list_split = private_file_list.read().split(b",")
            private_file_list_split = private_file_list_split[1:-1]
            private_file_list.close()

            all_ids = []
            sizes = {}
            for i in private_file_list_split:
                id_re = re.search(b"fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
                if id_re:
                    all_ids.append(id_re.group(2))
                    sizes[id_re.group(2)] = id_re.group(3)

            if file_id_b64 in all_ids:
                if not os.path.isfile(user_folder + "/" + file_id_b64.decode("ascii") + ".fd"):
                    return 9, 0
                file_sender = fileSend.FileSend(client_handler, user_folder + "/" + file_id_b64.decode("ascii") + ".fd")
                file_sender.start()
                return 0, (int(sizes[file_id_b64]) * 3) / 4
            else:
                return 8, 0

        return 7, 0

    def delete_file(self, user, file_id_b64, signature_b64):
        # type: (bytes, bytes, bytes) -> int
        ret_value = -1
        try:
            ret_value = self.__delete_file(user, file_id_b64, signature_b64)
        except:
            self.log("Error deleteFile", error=True)
        return ret_value

    def __delete_file(self, user, file_id_b64, signature_b64):
        # type: (bytes, bytes, bytes) -> int
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

        user_folder = self.database_directory + "/Profiles/" + utils.base64_encode(user).decode("ascii")

        if not os.path.isdir(user_folder):
            return 1

        if not utils.is_base64(signature_b64):
            return 2

        if not utils.is_base64(file_id_b64):
            return 3

        if not os.path.isfile(user_folder + "/publicFileList.pufl"):
            return 4

        if not os.path.isfile(user_folder + "/hiddenFileList.hfl"):
            return 5

        if not os.path.isfile(user_folder + "/privateFileList.prfl"):
            return 6

        if not os.path.isfile(user_folder + "/publickey.pk"):
            return 7

        pk_file = open(user_folder + "/publickey.pk", "rb")
        pk = pk_file.read()
        pk_file.close()

        try:
            pk_key = RSA.importKey(pk)
        except:
            return 8

        signature_to_verify = SHA256.new()
        signature_to_verify.update(b"deleteFile;name: " + user + b";id: " + file_id_b64)
        signature = utils.base64_decode(signature_b64)

        try:
            PKCS1_v1_5_Sig.new(pk_key).verify(signature_to_verify, signature)
            valid_signature = True
        except:
            valid_signature = False

        if valid_signature:
            public_file_list_file = open(user_folder + "/publicFileList.pufl", "rb")
            hidden_file_list_file = open(user_folder + "/hiddenFileList.hfl", "rb")
            private_file_list_file = open(user_folder + "/privateFileList.prfl", "rb")

            public_file_list_split_comma = public_file_list_file.read().split(b",")[1:-1]
            hidden_file_list_split_comma = hidden_file_list_file.read().split(b",")[1:-1]
            private_file_list_split_comma = private_file_list_file.read().split(b",")[1:-1]

            found = False
            index = 0

            for i in range(0, len(public_file_list_split_comma)):
                if b"id:" + file_id_b64 in public_file_list_split_comma[i]:
                    found = True
                    index = i
                    break

            if found:
                public_file_list_split_comma.pop(index)
            else:
                for i in range(0, len(hidden_file_list_split_comma)):
                    if b"id:" + file_id_b64 in hidden_file_list_split_comma[i]:
                        found = True
                        index = i
                        break
                if found:
                    hidden_file_list_split_comma.pop(index)
                else:
                    for i in range(0, len(private_file_list_split_comma)):
                        if b"id:" + file_id_b64 in private_file_list_split_comma[i]:
                            found = True
                            index = i
                            break
                    if found:
                        private_file_list_split_comma.pop(index)
                    else:
                        return 10

            file_to_delete = file_id_b64.decode("ascii") + ".fd"
            if not os.path.isfile(user_folder + "/" + file_to_delete):
                return 11

            # Could potentially be exploited to remove any file, but we have sanitized the input to be Base64
            os.remove(user_folder + "/" + file_to_delete)

            public_file_list_file = open(user_folder + "/publicFileList.pufl", "wb")
            hidden_file_list_file = open(user_folder + "/hiddenFileList.hfl", "wb")
            private_file_list_file = open(user_folder + "/privateFileList.prfl", "wb")

            result = b","

            for i in public_file_list_split_comma:
                result += i + b","

            public_file_list_file.write(result)
            public_file_list_file.close()

            result = b","

            for i in hidden_file_list_split_comma:
                result += i + b","

            hidden_file_list_file.write(result)
            hidden_file_list_file.close()

            result = b","

            for i in private_file_list_split_comma:
                result += i + b","

            private_file_list_file.write(result)
            private_file_list_file.close()

            return 0
        else:
            return 9
