from Crypto.Random import *
from Crypto.Random import random
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Sign
import socket
import re
import time
import threading
import PriveAPI.utils as utils
import random
import math
import string
import os
import types

alphabet = list(string.ascii_lowercase.encode("ascii"))
alphabet.extend(i for i in range(0, 10))
alphabet.extend(string.ascii_uppercase.encode("ascii"))

bytes3ChunksToSend = 65536


class AutoKeepAlive(threading.Thread):

    def __init__(self, server_socket, keep_alive_msg, send_lock):
        # type: (PriveAPIInstance, str, threading.Lock) -> None
        threading.Thread.__init__(self)
        self.serverSock = server_socket
        self.keepAliveMsg = keep_alive_msg
        self.event = threading.Event()
        self.send_lock = send_lock

    def run(self):
        while True:
            if self.event.is_set():
                time.sleep(0.2)
                continue
            try:
                self.send_lock.acquire()
                self.serverSock.send(self.keepAliveMsg)
                self.send_lock.release()
                time.sleep(0.2)
            except:
                break


class PriveAPIInstance:

    def __init__(self, server_ip, server_public_key, server_port=4373, auto_keep_alive=True,
                 key_size=4096, proof_of_work0es=5, proof_of_work_iterations=2, file_chunks_to_send=65536):
        # type: (str, bytes, int, bool, int, int, int, int) -> None
        self.sock = None
        self.session_key_set = False
        self.logged_in_sk = None  # Private Key
        self.logged_in_user = b""  # Active User
        self.logged_in_password = b""  # Active User Password
        self.logged_in = False
        self.key_size = key_size
        self.proof_of_work0es = proof_of_work0es
        self.proof_of_work_iterations = proof_of_work_iterations

        self.send_lock = threading.Lock()

        self.file_chunks_to_send = file_chunks_to_send

        self.server_ip = server_ip
        try:
            socket.inet_aton(self.server_ip)
        except:
            try:
                self.server_ip = socket.gethostbyname(self.server_ip)
            except:
                raise Exception("Couldn't resolve host")

        self.server_port = server_port
        self.auto_keep_alive_enabled = auto_keep_alive

        self.server_public_key = RSA.importKey(server_public_key)

        self.connected = False

        self.keep_alive_msg = b""
        self.auto_keep_alive = None

    def connect(self):
        if self.connected:
            raise Exception("Already connected")

        # Server Socket

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.sock.connect((self.server_ip, self.server_port))
        except:
            self.sock.close()
            raise Exception("Couldn't connect to server")

        self.connected = True

        self.__send_create_session_key_message()

        self.keep_alive_msg = b"keepAlive"

        keepAliveEncrypted = self.encrypt_with_padding(self.sessionKey, self.keep_alive_msg)
        self.keep_alive_msg = keepAliveEncrypted[1] + b"\r\n"

        if self.auto_keep_alive_enabled:
            self.auto_keep_alive = AutoKeepAlive(self.sock, self.keep_alive_msg, self.send_lock)
            self.auto_keep_alive.start()

    def close(self):
        """

        Closes the connection to the server

        :return: Nothing
        """
        self.__send_msg(b"quit")
        self.sock.close()
        self.connected = False

    # Generate Session Key
    def __generate_session_key(self):
        self.sessionKey = b""
        while not len(self.sessionKey) == 32:
            self.sessionKey = get_random_bytes(32)

    # Creates a Session Key and sends it
    def __send_create_session_key_message(self):
        # Generate Session Key
        self.__generate_session_key()

        # Encrypt Session Key & Turn to B64
        session_key_encrypted = PKCS1_OAEP.new(self.server_public_key).encrypt(self.sessionKey)
        session_key_b64 = utils.base64_encode(session_key_encrypted)

        # Message
        msg = b"sessionkey: " + session_key_b64 + b"\r\n"

        # Send Message & Check For Errors
        if not self.__send_msg(msg) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        # Receive Message & Check For Errors
        msg_received = self.__receive_response()
        if not msg_received[0] == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        msg_received = msg_received[1]

        msg_data_extracted = self.extract_data(msg_received)
        msg_error_code = msg_data_extracted[1]
        if msg_error_code == b"":
            self.close()
            raise Exception("Error Parsing Received Message (Error 1)")

        if not msg_error_code == b"successful":
            self.close()
            raise Exception("Error Settting Session Key (Error 2)")

        self.session_key_set = True

        return

    def solve_proof_of_work(self, challenge):
        if isinstance(challenge, str):
            challenge = challenge.encode("ascii")
        random.seed(time.time())
        numToAppend = random.randint(0, 10000000000000000)
        while True:
            testStr = challenge + PriveAPIInstance.num_to_alphabet(numToAppend)
            h = SHA256.new(testStr)
            for i in range(0, self.proof_of_work_iterations - 1):
                h.update(h.hexdigest().encode("ascii"))
            if re.search("^" + "0" * self.proof_of_work0es, h.hexdigest()):
                # Debug
                # print "Check: {}".format(utils.checkProofOfWork(testStr, self.proofOfWork0es,
                #                                                 self.proofOfWorkIterations))
                return PriveAPIInstance.num_to_alphabet(numToAppend)
            numToAppend += 1

    def request_challenge_and_solve(self):
        # type: () -> tuple

        if not self.connected:
            raise Exception("Not connected")

        message = b"requestChallenge"
        if not self.__send_msg(message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        msg_received = self.__receive_response()
        if not msg_received[0] == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        msg_received = msg_received[1]

        # Extract Data
        msg_dict = self.extract_keys(msg_received)

        if msg_dict[b"errorCode"] != b"successful":
            return False, b""

        challenge = utils.base64_decode(msg_dict[b"challenge"])
        return True, self.solve_proof_of_work(challenge)

    def send_file(self, file_path, file_size, progress_function=None):

        if not self.connected:
            raise Exception("Not connected")

        self.auto_keep_alive.event.set()
        file_handler = open(file_path, "rb")
        segment = 0

        msg_dict = {}

        current_bytes_sent = 0

        while True:
            data_to_send = file_handler.read(3 * self.file_chunks_to_send)
            current_bytes_sent += len(data_to_send)
            if data_to_send == b"":
                break
            data_to_send = utils.base64_encode(data_to_send)
            segment_message = b"segment;num: %d;data: %s" % (segment, data_to_send)
            if not self.__send_msg(segment_message) == 0:
                Exception("Error Communicating with Server (Error 0)")

            response = self.__receive_response()
            if response[0] == 1:
                self.close()
                raise Exception("Error Communicating with Server (Error 0)")
            response = response[1]

            # print "DBG: {}".format(response)

            msg_dict = self.extract_keys(response)

            if msg_dict[b"errorCode"] != b"successful":
                self.close()
                raise Exception("Error Transfering File (Error 5): {}".format(msg_dict))
            segment += 1

            if progress_function is not None:
                progress_function(current_bytes_sent, file_size, 0)

        self.auto_keep_alive.event.clear()
        return msg_dict

    def create_user(self, user_name, password):
        # type: (str, str) -> dict
        """

        Creates User with userName param as name and password param as password

        :param user_name: Name for the user that is created
        :param password: Password for the user that is created
        :return: errorMsg
        """

        if isinstance(user_name, str):
            user_name = user_name.encode("ascii")
        if isinstance(password, str):
            password = password.encode("ascii")

        if not self.connected:
            raise Exception("Not connected")

        # Generate RSA Keys
        rsa_keys = RSA.generate(self.key_size)
        private_key = rsa_keys.exportKey()
        public_key = utils.base64_encode(rsa_keys.publickey().exportKey())

        # Padding Password
        if len(password) > 16:
            self.close()
            raise Exception("Password exceeds max passwd length")
        pwd_length = 16 - password.__len__()
        password = password + bytes([pwd_length]) * pwd_length

        # Validation Token
        vt = get_random_bytes(128)
        vt_sha = SHA256.new(vt).digest()

        # Encrypt & B64
        private_key_encrypted = self.encrypt_with_padding(password, private_key)[1]
        vt_encrypted = self.encrypt_with_padding(password, vt)[1]
        vt_sha_b64 = utils.base64_encode(vt_sha)

        proof_of_work = self.request_challenge_and_solve()
        if proof_of_work[0] is False:
            self.close()
            raise Exception("Error Calculation Proof of Work (Error 4)")

        # Create Message
        message = b"newUser;name: " + user_name + b";pkB64: " + public_key + b";skAesB64: "
        message = message + private_key_encrypted + b";vtB64: " + vt_sha_b64 + b";vtAesB64: " + vt_encrypted
        message = message + b";pow: " + utils.base64_encode(proof_of_work[1])

        # Send Message
        if not self.__send_msg(message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        # Receive Message & Check For Errors
        msg_received = self.__receive_response()
        if not msg_received[0] == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        msg_received = msg_received[1]

        # Extract Data
        msg_dict = self.extract_keys(msg_received)

        return msg_dict

    def __get_vt(self, user_name):
        # type: (bytes) -> dict

        if isinstance(user_name, str):
            user_name = user_name.encode("ascii")

        if not self.connected:
            raise Exception("Not connected")

        # Create Message
        vt_aes_msg = b"getVtAesB64;name: " + user_name

        # Send & Check For Errors
        if not self.__send_msg(vt_aes_msg) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        # Receive Message & Check For Errors
        msg_received = self.__receive_response()
        if not msg_received[0] == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        msg_received = msg_received[1]

        # Extract Data
        msg_dict = self.extract_keys(msg_received)

        return msg_dict

    def __check_vt(self, user_name, password, vt_decrypted):
        # type: (bytes, bytes, bytes) -> dict
        if not self.connected:
            raise Exception("Not connected")

        if isinstance(user_name, str):
            user_name = user_name.encode("ascii")
        if isinstance(password, str):
            password = password.encode("ascii")
        if isinstance(vt_decrypted, str):
            vt_decrypted = vt_decrypted.encode("ascii")

        # Validation Token
        new_vt = get_random_bytes(128)
        new_vt_sha = SHA256.new(new_vt)

        # Encrypt & B64
        new_vt_encrypted = self.encrypt_with_padding(password, new_vt)[1]
        new_vt_sha_b64 = utils.base64_encode(new_vt_sha.digest())

        message = b"checkVT;name: " + user_name + b";vt: " + vt_decrypted + b";newVTSha: " + new_vt_sha_b64 +\
                  b";newVTEnc: " + new_vt_encrypted
        if not self.__send_msg(message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if not response[0] == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        # Extract Data
        msg_dict = self.extract_keys(response)
        return msg_dict

    def login(self, user_name, password):
        # type: (bytes, bytes) -> dict
        """

        Login as <userName> using <password>

        :param user_name: User to login to
        :param password: Password for user
        :return: errorMsg, timeUntilUnlock
        """

        if isinstance(user_name, str):
            user_name = user_name.encode("ascii")
        if isinstance(password, str):
            password = password.encode("ascii")

        if not self.connected:
            raise Exception("Not connected")

        # Padding passwd
        pwd_length = 16 - len(password)
        password = password + bytes([pwd_length]) * pwd_length

        # Get VT
        vt = self.__get_vt(user_name)
        if vt[b"errorCode"] != b"successful":
            return vt

        # Get SK
        sk_decrypted = self.__check_vt(user_name, password,
                                       utils.base64_encode(self.decrypt_with_padding(password, vt[b"vt"])[1]))
        if sk_decrypted[b"errorCode"] != b"successful":
            return sk_decrypted

        # Import SK
        self.logged_in_sk = RSA.importKey(self.decrypt_with_padding(password, sk_decrypted[b"sk"])[1])
        if not self.logged_in_sk:
            self.close()
            raise Exception("Error Importing RSA Key (Error 3)")
        self.logged_in_user = user_name
        self.logged_in = True
        self.logged_in_password = password
        return sk_decrypted

    def delete_user(self):
        # type: () -> dict
        """

        Deletes User if Logged In

        :return: errorMsg
        """

        if not self.connected:
            raise Exception("Not connected")

        if not self.logged_in:
            self.close()
            raise Exception("Not logged in")

        text_to_sign = SHA256.new(b"delUser;name: " + self.logged_in_user)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.logged_in_sk).sign(text_to_sign))
        message = b"delUser;name: " + self.logged_in_user + b";signatureB64: " + signature
        if not self.__send_msg(message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msg_dict = self.extract_keys(response)
        if msg_dict[b"errorCode"] == b"successful":
            self.logged_in = False
            self.logged_in_password = b""
            self.logged_in_sk = None
            self.logged_in_user = b""
        return msg_dict

    def update_keys(self, new_passwd):
        # type: (bytes) -> dict

        if isinstance(new_passwd, str):
            new_passwd = new_passwd.encode("ascii")

        if not self.connected:
            raise Exception("Not connected")

        if not self.logged_in:
            self.close()
            raise Exception("Not logged in")

        pwd_length = 16 - len(new_passwd)
        new_passwd = new_passwd + bytes([pwd_length]) * pwd_length

        new_rsa_key = RSA.generate(self.key_size)
        new_pk_exported = new_rsa_key.publickey().exportKey()
        new_pk_exported_b64 = utils.base64_encode(new_rsa_key.publickey().exportKey())
        new_sk_exported = new_rsa_key.exportKey()

        # Validation Token
        new_vt = get_random_bytes(128)
        new_vt_sha = SHA256.new(new_vt)

        # Encrypt & B64
        new_vt_encrypted = self.encrypt_with_padding(new_passwd, new_vt)[1]
        new_vt_sha_b64 = utils.base64_encode(new_vt_sha.digest())

        # Encrypt & B64
        private_key_encrypted = self.encrypt_with_padding(new_passwd, new_sk_exported)[1]

        text_to_sign = b"updateKeys;name: " + self.logged_in_user + b";newPK: " + new_pk_exported + b";newSKAesB64: " +\
                       private_key_encrypted + b";newVTSha: " + new_vt_sha_b64 + b";newVTEnc: " + new_vt_encrypted
        text_to_sign = SHA256.new(text_to_sign)

        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.logged_in_sk).sign(text_to_sign))
        message = b"updateKeys;name: " + self.logged_in_user + b";signatureB64: " + signature + b";newPKB64: "
        message = message + new_pk_exported_b64 + b";newSKAesB64: " + private_key_encrypted
        message = message + b";newVTSha: " + new_vt_sha_b64 + b";newVTEnc: " + new_vt_encrypted
        if not self.__send_msg(message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msg_dict = self.extract_keys(response)

        if msg_dict[b"errorCode"] == b"successful":
            self.logged_in_sk = new_rsa_key
            self.logged_in_password = new_passwd

        return msg_dict

    def get_user_pk(self, user):
        # type: (bytes) -> dict
        if not self.connected:
            raise Exception("Not connected")

        if isinstance(user, str):
            user = user.encode("ascii")

        message = b"getPK;name: " + user
        if not self.__send_msg(message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if not response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = response[1]
        msg_dict = self.extract_keys(response)

        return msg_dict

    def add_file(self, file_name, file_path, visibility=b"Public", progress_function=None):
        if not self.connected:
            raise Exception("Not connected")

        if isinstance(file_name, str):
            file_name = file_name.encode("ascii")
        if isinstance(visibility, str):
            visibility = visibility.encode("ascii")

        if not self.logged_in:
            self.close()
            raise Exception("Not logged in")

        if visibility != b"Public" and visibility != b"Hidden" and visibility != b"Private":
            self.close()
            raise Exception("Visibility unknown")

        if not os.path.isfile(file_path):
            self.close()
            raise Exception("File not found")

        file_size = int(math.ceil(os.stat(file_path).st_size / 3.0) * 4)
        file_size2 = os.stat(file_path).st_size

        if visibility == b"Private":
            # Encrypt file before sending
            tmp_private_file_path = "{}.tmp".format(utils.base64_encode(get_random_bytes(8)).decode("ascii"))
            tmp_private_file = open(tmp_private_file_path, "wb")
            file_handler = open(file_path, "rb")
            current_bytes_encrypted = 0
            while True:
                file_data = file_handler.read(65536 * 2)
                current_bytes_encrypted += len(file_data)
                if file_data == b"":
                    break
                if len(file_data) != 65536 * 2:
                    file_data = utils.base64_decode(self.encrypt_with_padding(self.logged_in_password, file_data)[1])
                else:
                    file_data = utils.base64_decode(self.encrypt_with_padding(self.logged_in_password, file_data,
                                                                              use_padding=False)[1])

                if progress_function is not None:
                    progress_function(current_bytes_encrypted, file_size2, 1)

                tmp_private_file.write(file_data)
            tmp_private_file.close()
            file_handler.close()
            file_path = tmp_private_file_path

        file_name_b64 = utils.base64_encode(file_name)

        message = b"add" + visibility + b"File;name: " + self.logged_in_user + b";fileNameB64: " + file_name_b64 +\
                  b";fileB64Size: " + str(file_size).encode("ascii")
        text_to_sign = SHA256.new(message)

        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.logged_in_sk).sign(text_to_sign))
        message = message + b";signatureB64: " + signature

        if not self.__send_msg(message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msgDict = self.extract_keys(response)

        if msgDict[b"errorCode"] == b"successful":
            msgDict = self.send_file(file_path, file_size2, progress_function=progress_function)

        if visibility == b"Private":
            os.remove(file_path)

        return msgDict

    def get_files(self, user=b""):
        # type: (bytes) -> dict

        if not self.connected:
            raise Exception("Not connected")

        if isinstance(user, str):
            user = user.encode("ascii")

        if user == b"" or user == self.logged_in_user:
            return self.__get_files()
        public_file_list_message = b"getPublicFileList;name: " + user

        if not self.__send_msg(public_file_list_message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msg_dict = self.extract_keys(response)

        if msg_dict[b"errorCode"] != b"successful":
            return msg_dict

        files_dict = self.extract_files(msg_dict[b"pufl"], visibility=b"Public")
        files_dict[b"errorCode"] = b"successful"

        return files_dict

    def __get_files(self):

        if not self.connected:
            raise Exception("Not connected")

        if not self.logged_in:
            self.close()
            raise Exception("Not logged in")

        public_file_list_message = b"getPublicFileList;name: " + self.logged_in_user

        if not self.__send_msg(public_file_list_message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msg_dict = self.extract_keys(response)

        if msg_dict[b"errorCode"] != b"successful":
            return msg_dict

        filesDict = self.extract_files(msg_dict[b"pufl"], visibility=b"Public")
        filesDict[b"errorCode"] = b"successful"

        hidden_file_list_message = b"getHiddenFileList;name: " + self.logged_in_user
        text_to_sign = SHA256.new(hidden_file_list_message)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.logged_in_sk).sign(text_to_sign))
        hidden_file_list_message = hidden_file_list_message + b";signatureB64: " + signature

        if not self.__send_msg(hidden_file_list_message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msg_dict = self.extract_keys(response)

        if msg_dict[b"errorCode"] != b"successful":
            return msg_dict

        filesDict.update(self.extract_files(msg_dict[b"hfl"], visibility=b"Hidden"))

        privateFileListMessage = b"getPrivateFileList;name: " + self.logged_in_user
        text_to_sign = SHA256.new(privateFileListMessage)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.logged_in_sk).sign(text_to_sign))
        hidden_file_list_message = privateFileListMessage + b";signatureB64: " + signature

        if not self.__send_msg(hidden_file_list_message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msg_dict = self.extract_keys(response)

        if msg_dict[b"errorCode"] != b"successful":
            return msg_dict

        filesDict.update(self.extract_files(msg_dict[b"prfl"], visibility=b"Private"))
        filesDict[b"errorCode"] = b"successful"
        return filesDict

    def get_file(self, file_id, visibility, output_path, user=b"", progress_function=None):
        # type: (bytes, bytes, str, bytes, types.FunctionType) -> dict

        if not self.connected:
            raise Exception("Not connected")

        if isinstance(file_id, str):
            file_id = file_id.encode("ascii")
        if isinstance(visibility, str):
            visibility = visibility.encode("ascii")
        if isinstance(user, str):
            user = user.encode("ascii")

        if user == "":
            if not self.logged_in:
                self.close()
                raise Exception("Not logged in")
            user = self.logged_in_user

        if visibility == b"Private":
            return self.__get_private_file(user, file_id, output_path, progress_function=progress_function)

        get_file_message = b"getFile;name: " + user + b";id: " + file_id

        if not self.__send_msg(get_file_message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msg_dict = self.extract_keys(response)
        if msg_dict[b"errorCode"] != b"successful":
            return msg_dict

        size = int(msg_dict[b"fileSize"])

        self.auto_keep_alive.event.set()

        ouFile = open(output_path, "wb")

        currentBytesReceived = 0

        while True:
            if not self.__send_msg(b"segment") == 0:
                self.close()
                raise Exception("Error Communicating with Server (Error 0)")

            response = self.__receive_response()
            if response[0] == 1:
                self.close()
                raise Exception("Error Communicating with Server (Error 0)")

            response = response[1]

            msg_dict = self.extract_keys(response)
            if msg_dict[b"errorCode"] == b"allSent":
                msg_dict[b"errorCode"] = b"successful"
                ouFile.close()
                break
            elif msg_dict[b"errorCode"] == b"successful":
                dataToWrite = utils.base64_decode(msg_dict[b"data"])

                currentBytesReceived += len(dataToWrite)
                if progress_function is not None:
                    progress_function(currentBytesReceived, size, 2)

                ouFile.write(dataToWrite)
            elif msg_dict[b"errorCode"] == b"fileError":
                ouFile.close()
                os.remove(output_path)
                break
            else:
                ouFile.close()
                os.remove(output_path)
                break

        self.auto_keep_alive.event.clear()
        return msg_dict

    def __get_private_file(self, user, file_id, output_path, progress_function=None):
        # type: (bytes, bytes, str, types.FunctionType) -> dict
        if not self.connected:
            raise Exception("Not connected")

        if isinstance(user, str):
            user = user.encode("ascii")
        if isinstance(file_id, str):
            file_id = file_id.encode("ascii")

        get_private_file_message = b"getPrivateFile;name: " + user + b";id: " + file_id
        text_to_sign = SHA256.new(get_private_file_message)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.logged_in_sk).sign(text_to_sign))
        get_private_file_message = get_private_file_message + b";signatureB64: " + signature

        if not self.__send_msg(get_private_file_message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msg_dict = self.extract_keys(response)
        if msg_dict[b"errorCode"] != b"successful":
            return msg_dict
        size = int(msg_dict[b"fileSize"])

        self.auto_keep_alive.event.set()

        tmp_private_file_path = "{}.tmp".format(utils.base64_encode(get_random_bytes(8)).decode("ascii"))
        tmp_private_file = open(tmp_private_file_path, "wb")

        current_bytes_received = 0

        while True:
            if not self.__send_msg(b"segment") == 0:
                self.close()
                raise Exception("Error Communicating with Server (Error 0)")

            response = self.__receive_response()
            if response[0] == 1:
                self.close()
                raise Exception("Error Communicating with Server (Error 0)")
            response = response[1]

            msg_dict = self.extract_keys(response)
            if msg_dict[b"errorCode"] == b"allSent":
                msg_dict[b"errorCode"] = b"successful"
                break
            elif msg_dict[b"errorCode"] == b"successful":
                msg_dict[b"data"] = utils.base64_decode(msg_dict[b"data"])

                current_bytes_received += len(msg_dict[b"data"])

                if progress_function is not None:
                    progress_function(current_bytes_received, size, 2)

                tmp_private_file.write(msg_dict[b"data"])
            elif msg_dict[b"errorCode"] == b"fileError":
                tmp_private_file.close()
                os.remove(tmp_private_file_path)
                self.auto_keep_alive.event.clear()
                return msg_dict
            else:
                tmp_private_file.close()
                os.remove(tmp_private_file_path)
                self.auto_keep_alive.event.clear()
                return msg_dict

        tmp_private_file.close()

        tmp_private_file = open(tmp_private_file_path, "rb")
        ou_file = open(output_path, "wb")

        current_bytes_decrypted = 0

        while True:
            data = tmp_private_file.read(65536 * 2)
            if data == "":
                break
            if len(data) != 65536 * 2:
                ou_file.write(self.decrypt_with_padding(self.logged_in_password, utils.base64_encode(data))[1])
            else:
                ou_file.write(self.decrypt_with_padding(self.logged_in_password, utils.base64_encode(data),
                                                        use_padding=False)[1])
            current_bytes_decrypted += len(data)
            if progress_function is not None:
                progress_function(current_bytes_decrypted, size, 3)

        ou_file.close()
        tmp_private_file.close()
        os.remove(tmp_private_file_path)

        self.auto_keep_alive.event.clear()
        return msg_dict

    def delete_file(self, file_id):
        if not self.connected:
            raise Exception("Not connected")

        if isinstance(file_id, str):
            file_id = file_id.encode("ascii")

        if not self.logged_in:
            self.close()
            raise Exception("Not logged in")

        delete_file_message = b"deleteFile;name: " + self.logged_in_user + b";id: " + file_id
        text_to_sign = SHA256.new(delete_file_message)
        signature = utils.base64_encode(PKCS1_v1_5_Sign.new(self.logged_in_sk).sign(text_to_sign))
        delete_file_message = delete_file_message + b";signatureB64: " + signature

        if not self.__send_msg(delete_file_message) == 0:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")

        response = self.__receive_response()
        if response[0] == 1:
            self.close()
            raise Exception("Error Communicating with Server (Error 0)")
        response = response[1]

        msg_dict = self.extract_keys(response)
        return msg_dict

    def logout(self):
        if not self.connected:
            raise Exception("Not connected")

        self.logged_in = False
        self.logged_in_password = ""
        self.logged_in_sk = None
        self.logged_in_user = ""

    def keep_alive(self):
        if not self.connected:
            raise Exception("Not connected")
        self.sock.send(self.keep_alive_msg)

    def __send_msg(self, msg):
        # type: (bytes) -> int
        """

        Sends msg parameter and encrypts it if there is a Session Key set.
        Adds \\\\r\\\\n

        ErrorCodes (0 - Successful,
                    1 - Error Sending)

        :param msg:Message To Send
        :return: errorCode
        """

        if not self.connected:
            raise Exception("Not connected")

        if not self.session_key_set:
            msg_to_send = msg
            if msg_to_send[-2:] != b"\r\n":
                msg_to_send = msg + b"\r\n"
            try:
                self.sock.send(msg_to_send)
            except:
                return 1
        elif self.session_key_set:
            msg_to_send = msg
            msg_to_send = self.encrypt_with_padding(self.sessionKey, msg_to_send)[1] + b"\r\n"
            try:
                self.send_lock.acquire()
                self.sock.send(msg_to_send)
                self.send_lock.release()
            except:
                return 1
        return 0

    def __receive_response(self):
        # type: () -> tuple
        """

        Receives and decrypts if there is session key set.
        Removes \\\\r\\\\n


        ErrorCodes (0 - Successful,
                    1 - Error Receiving)

        :return: ErrorCode, Data
        """

        if not self.connected:
            raise Exception("Not connected")

        data = b""
        while True:
            try:
                newData = self.sock.recv(4096)
            except:
                return 1, b""
            data = data + newData
            if re.search(b"\r\n", newData):
                break
        if not self.session_key_set:
            return 0, data.split(b"\r\n")[0]
        else:
            data = data.split(b"\r\n")[0]
            data = self.decrypt_with_padding(self.sessionKey, data)[1]
            return 0, data

    def get_logged_in_passwd(self):
        """

        Returns the password used for login.
        Raises exception if not logged in.

        :return: password
        """

        if not self.connected:
            raise Exception("Not connected")

        if not self.logged_in:
            self.close()
            raise Exception("Password requested while not logged in")

        return self.logged_in_password[:-self.logged_in_password[-1]]

    # Get Random String
    @staticmethod
    def get_rand_string(length):
        # type: (int) -> bytes
        returnString = b""
        for x in range(0, length):
            returnString += get_random_bytes(1)
        if b"\x00" in returnString:
            return PriveAPIInstance.get_rand_string(length)
        return returnString

    # Encrypt Using AES and Padding
    @staticmethod
    def encrypt_with_padding(key, plaintext, use_padding=True):
        # type: (bytes, bytes, bool) -> tuple
        """

        Encrypts plaintext param with AES using key param as key.
        Also, returns base64-ed output.

        ErrorCodes (True  - Encrypted Correctly,
                    False - Password not padded (ciphertext = \"\")

        :param key: key used to encrypt
        :param plaintext: plaintext to encrypt
        :param use_padding: whether to use padding on the message
        :return: ErrorCode, Ciphertext
        """
        length = (16 - (len(plaintext) % 16)) + 16 * random.randint(0, 14)

        if use_padding:
            plaintext_padded = plaintext + PriveAPIInstance.get_rand_string(length - 1) + bytes([length])
        else:
            plaintext_padded = plaintext

        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, b""
        ciphertext = utils.base64_encode(AES.new(key, AES.MODE_ECB).encrypt(plaintext_padded))
        return True, ciphertext

    # Decrypt Using AES padded message
    @staticmethod
    def decrypt_with_padding(key, ciphertext, use_padding=True):
        # type: (bytes, bytes, bool) -> tuple
        """

        Decrypts ciphertext param using key param as key.

        ErrorCodes (True  - Encrypted Correctly,
                    False - Password not padded (plainText = \"\")

        :param key: key used to decrypt
        :param ciphertext: ciphertext to decrypt
        :param use_padding: whether to use padding on the message
        :return: ErrorCode, Plaintext
        """
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, b""
        ciphertext_not_b64 = utils.base64_decode(ciphertext)
        plaintext_padded = AES.new(key, AES.MODE_ECB).decrypt(ciphertext_not_b64)
        if use_padding:
            plaintext = plaintext_padded[:-plaintext_padded[-1]]
        else:
            plaintext = plaintext_padded
        return True, plaintext

    # Extract Data from Prive Message (msgData, errorCode)
    @staticmethod
    def extract_data(msg):
        # type: (bytes) -> tuple
        """

        Extract Data from Prive Message (data;errorCode: eC)

        Returns (\"\", \"\") if it is not a prive message

        :param msg: Message to extract data from
        :return: data, eC
        """

        msgRe = re.search(b"^(.+);errorCode: (.+)", msg)
        if not msgRe:
            return b"", b""

        msgData = msgRe.group(1)
        errorCode = msgRe.group(2)

        return msgData, errorCode

    @staticmethod
    def extract_keys(msg):
        # type: (bytes) -> dict
        msgSplit = msg.split(b";")
        returnDict = {}
        for key in msgSplit:
            regex = re.search(b"^(.+): (.+)$", key)
            if regex:
                returnDict[regex.group(1)] = regex.group(2)

        return returnDict

    @staticmethod
    def extract_files(file_list, visibility):
        file_list_split = file_list.split(b",")[1:-1]
        return_dict = {}
        for i in file_list_split:
            regex = re.search(b"fileName:(.+)\\.id:(.+)\\.size:(.+)", i)
            if regex:
                return_dict[regex.group(2)] = {b"name": utils.base64_decode(regex.group(1)),
                                               b"visibility": visibility,
                                               b"id": regex.group(2),
                                               b"size": int(
                                                   (int(regex.group(3)) * 3) / 4)}  # Transform b64 size to bytes
        return return_dict

    @staticmethod
    def num_to_alphabet(num):
        res = b""
        while num > 0:
            res += bytes([alphabet[num % len(alphabet)]])
            num = int((num - num % len(alphabet)) / len(alphabet))
        return res
