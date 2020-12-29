from Crypto.Cipher import AES
from Crypto.Random import random
import server
import re
import databaseManager
import socket
import threading
import time
import utils
from config import Config


class Timeout(threading.Thread):
    def __init__(self, client_handler_master, sock, client_address, database_manager):
        # type: (ClientHandle, socket.socket, tuple, databaseManager.DatabaseManager) -> None
        self.database_manager = database_manager
        self.client_address = client_address
        # self.log("Starting Timeout Thread on Client " + str(client_address[0]) + " " + str(client_address[1]),
        #          print_on_screen=False)
        threading.Thread.__init__(self)
        self.socket = sock
        self.start_timeout = time.time()
        self.timeout_event = threading.Event()
        self.timeout = Config.CLIENT_TIMEOUT
        self.client_handler_master = client_handler_master

    def log(self, msg, print_on_screen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.database_manager.logger.log("ClientTimeout:" + self.client_address[0] + ":" + str(self.client_address[1]),
                                         msg, print_to_screen=print_on_screen, debug=debug)

    def stop(self):
        self.timeout_event.set()

    def reset_time(self):
        self.start_timeout = time.time()

    def run(self):
        while not self.timeout_event.is_set():
            if time.time() - self.start_timeout >= self.timeout:
                # self.log("Client " + str(self.client_address[0]) + " " + str(self.client_address[1]) +
                #          " has reached the timeout",
                #          print_on_screen=False)
                self.client_handler_master.close_all()
                break
            time.sleep(1)
        # self.log("Exiting Timeout", print_on_screen=False)


class ClientHandle(threading.Thread):

    def __init__(self, client_socket, client_address, database_manager, server_master):
        # type: (ClientHandle, socket.socket, tuple, databaseManager.DatabaseManager, server.Server) -> None
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.client_address = client_address
        self.database_manager = database_manager
        self.server_master = server_master
        self.timeout_list = [0, False]  # Because all instances share the same object
        self.timeout_controller = Timeout(self, self.client_socket, self.client_address, database_manager)
        self.timeout_controller.start()
        self.running_event = threading.Event()
        self.receive_event = threading.Event()  # Lock if receiving file

    def run(self):
        while not self.running_event.is_set():
            try:
                if self.receive_event.is_set():
                    time.sleep(0.1)
                    self.timeout_controller.reset_time()
                    continue
                data = b""
                while True:
                    newData = self.client_socket.recv(4096)
                    data = data + newData
                    if re.search(b"\r\n", newData):
                        break

                    # ANTI MEMORY LEAKING
                    if len(data) >= Config.CLIENT_MAX_SEND:
                        break
                if self.running_event.is_set():
                    break
                if self.handle_message(data):
                    break
                if not self.server_master.running.return_running():
                    self.send(b"quit\r\n")
                    break
            except Exception as e:
                self.log(str(e), error=True)
                self.close_all()
                return
        self.close_all()

    def close_all(self):
        if self.running_event.is_set():
            return
        self.running_event.set()
        self.database_manager.delete_session_key(self.client_address[0], self.client_address[1])
        self.log("Closing", print_on_screen=False)
        try:
            self.client_socket.close()
        except Exception:
            # self.log("Client Already Closed", print_on_screen=False)
            pass
        # self.log("Removing Timeout", print_on_screen=False)
        self.timeout_controller.stop()
        try:
            self.timeout_controller.join()
        except:
            pass
        self.timeout_controller = None
        # self.log("Removing Self", print_on_screen=False)
        self.server_master.delete_client_thread(self)

    def log(self, msg, print_on_screen=False, debug=False, error=False, save_to_file=True):
        # type: (str, bool, bool, bool, bool) -> None
        self.database_manager.logger.log("Client:" + self.client_address[0] + ":" + str(self.client_address[1]),
                                         msg, print_to_screen=print_on_screen, debug=debug, error=error,
                                         save_to_file=save_to_file)

    def send(self, msg, encrypted=False, key=b""):
        # type: (bytes, bool, bytes) -> None
        # self.log("Sending [{}]".format(msg), print_on_screen=False)
        # self.log("Sending {}".format(msg.split(';')[0]), saveToFile=False)
        if encrypted:
            msg = self.encrypt_with_padding(key, msg)[1] + b"\r\n"
        else:
            msg += b"\r\n"
        self.client_socket.send(msg)

    def handle_message(self, data):
        # type: (bytes) -> bool
        # Reset timeout time
        self.timeout_controller.reset_time()

        # Remove \r\n from message
        data = data[:-2]

        if re.search(b"^quit$", data):
            return True

        # Check if session key message
        session_key_re = re.search(b"^sessionkey: (.*)$", data)

        # Get session key if exists
        session_key = self.database_manager.get_session_key(self.client_address[0], self.client_address[1])

        # Check if it was a session key message
        if session_key_re:
            # self.log("Received session key", saveToFile=False)
            if not session_key[0]:
                validSEK = self.database_manager.new_session_key(self.client_address[0], self.client_address[1],
                                                                 session_key_re.group(1))
                if not validSEK:
                    self.send(b"msg: Invalid Session Key;errorCode: invalid")
                else:
                    self.send(b"msg: Session Key Updated;errorCode: successful")
                return False
            else:
                self.send(b"msg: Already Session Key;errorCode: already")
                return False

        if not session_key[0]:
            self.send(b"msg: No Session Key;errorCode: missingSessionKey")
            return False

        session_key = session_key[1]

        decrypted_message = self.decrypt_with_padding(session_key, data)[1]  # type: bytes

        """show_txt = decrypted_message.split(b";")[0]

        if show_txt != b"keepAlive":
            self.log("Received: [" + decrypted_message.decode("ascii") + "]", print_on_screen=False)"""

        if re.search(b"^quit$", decrypted_message):
            return True
        if re.search(b"^keepAlive$", decrypted_message):
            return False

        request_challenge = re.search(b"^requestChallenge$", decrypted_message)

        if request_challenge:
            l_database_query_result = self.database_manager.execute_function("requestChallenge",
                                                                             (self.client_address[0],))

            response_dict = {0: b"msg: Returning Challenge;challenge: %s;errorCode: successful" %
                                l_database_query_result[1],
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_result[0], b"msg: Bad Error Code;errorCode: badErrorCode")
            self.send(msg, encrypted=True, key=session_key)
            return False

        new_user = re.search(b"^newUser;name: (.+);pkB64: (.+);skAesB64: (.+);vtB64: (.+);vtAesB64: (.+);pow: (.+)$",
                             decrypted_message)
        if new_user:
            l_name = new_user.group(1)
            l_pk_b64 = utils.base64_decode(new_user.group(2))
            l_sk_aes_b64 = new_user.group(3)
            l_vt_sha_b64 = new_user.group(4)
            l_vt_aes_b64 = new_user.group(5)
            l_proof_of_work = new_user.group(6)

            l_database_query_error_code = self.database_manager.execute_function("newUser", (l_name,
                                                                                             l_pk_b64,
                                                                                             l_sk_aes_b64,
                                                                                             l_vt_sha_b64,
                                                                                             l_vt_aes_b64,
                                                                                             l_proof_of_work,
                                                                                             self.client_address[0]))

            self.log("new_user name: {} error_code: {}".format(l_name, l_database_query_error_code))

            response_dict = {0: b"msg: New User Registered!;errorCode: successful",
                             1: b"msg: User Already Exists;errorCode: usrAlreadyExists",
                             2: b"msg: Invalid Name Characters;errorCode: invalidName",
                             3: b"msg: Invalid Private Key Characters;errorCode: invalidSK",
                             4: b"msg: Invalid Public Key Characters;errorCode: invalidPK",
                             5: b"msg: Invalid Validation Token Characters;errorCode: invalidVT",
                             6: b"msg: Invalid Encrypted Validation Token Characters;errorCode: invalidVTEnc",
                             7: b"msg: Invalid Proof Of Work Characters;errorCode: invalidPOWCh",
                             8: b"msg: Challenge Not Previously Requested/Found;errorCode: noChallenge",
                             9: b"msg: Invalid Proof Of Work;errorCode: invalidPOW",
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        get_vt_aes_b64 = re.search(b"^getVtAesB64;name: (.+)$", decrypted_message)

        if get_vt_aes_b64:
            l_name = get_vt_aes_b64.group(1)

            l_database_query_result = self.database_manager.execute_function("getVTAesB64", (l_name,))

            l_database_query_error_code = l_database_query_result[0]

            self.log("get_vt_aes_b64 name: {} error_code: {}".format(l_name, l_database_query_error_code))

            response_dict = {0: b"msg: Returning vtAesB64;vt: " + l_database_query_result[1] +
                                b";errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: User Without VtAesB64;errorCode: userWithoutVtEnc",
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        check_vt = re.search(b"^checkVT;name: (.+);vt: (.+);newVTSha: (.+);newVTEnc: (.+)$", decrypted_message)

        if check_vt:
            l_name = check_vt.group(1)
            l_vt_b64 = check_vt.group(2)
            l_new_vt_sha = check_vt.group(3)
            l_new_vt_enc = check_vt.group(4)

            l_database_query_result = self.database_manager.execute_function("checkVT", (l_name,
                                                                                         l_vt_b64,
                                                                                         self.client_address[0],
                                                                                         l_new_vt_sha, l_new_vt_enc))

            l_database_query_error_code = l_database_query_result[0]

            self.log("check_vt name: {} error_code: {}".format(l_name, l_database_query_error_code))

            if l_database_query_error_code == 0:
                l_sk_aes_b64 = self.database_manager.execute_function("getSK", (l_name,))
                l_sk_aes_b64_error_code = l_sk_aes_b64[0]

                response_dict = {0: b"msg: VT Correct!;sk: " + l_sk_aes_b64[1] + b";errorCode: successful",
                                 1: b"msg: User Without SK;errorCode: userWithoutSK",
                                 2: b"msg: User Deleted Before getSK execution;errorCode: userDeletedBeforeExecution",
                                 -1: b"msg: Server Panic 2!;errorCode: serverPanic2"}

                msg = response_dict.get(l_sk_aes_b64_error_code, b"msg: Bad Error Code 2;errorCode: badErrorCode2")
            else:
                response_dict = {1: b"msg: Incorrect VT;errorCode: incorrect",
                                 2: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                                 3: b"msg: User Without VT;errorCode: userWithoutVt",
                                 4: b"msg: Invalid Validation Token Characters;errorCode: invalidVT",
                                 5: b"msg: Account Locked;timeBeforeUnlocking: " +
                                    bytes(str(l_database_query_result[1]).encode("ascii")) +
                                    b";errorCode: accountLocked",
                                 -1: b"msg: Server Panic!;errorCode: serverPanic"}

                msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        get_pk = re.search(b"^getPK;name: (.+)$", decrypted_message)

        if get_pk:
            l_name = get_pk.group(1)

            l_database_query_result = self.database_manager.execute_function("getPK", (l_name,))

            l_database_query_error_code = l_database_query_result[0]

            self.log("get_pk name: {} error_code: {}".format(l_name, l_database_query_error_code))

            response_dict = {0: b"msg: Returning pk;pk: " + l_database_query_result[1] + b";errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: User Without PK;errorCode: userWithoutPK",
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        del_user = re.search(b"^delUser;name: (.+);signatureB64: (.+)$", decrypted_message)

        if del_user:
            l_name = del_user.group(1)
            l_signature_b64 = del_user.group(2)

            l_database_query_error_code = self.database_manager.execute_function("delUser", (l_name, l_signature_b64))

            self.log("del_user name: {} error_code: {}".format(l_name, l_database_query_error_code))

            response_dict = {0: b"msg: User Deleted Successfully;errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: User Without PK;errorCode: userWithoutPK",
                             3: b"msg: Invalid Signature Characters;errorCode: invalidSignCh",
                             4: b"msg: Faulty Signature;errorCode: invalidSign",
                             5: b"msg: Error Importing User PK;errorCode: faultyPK",
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        update_keys = re.search(b"^updateKeys;name: (.+);signatureB64: (.+);newPKB64: (.+);newSKAesB64: (.+);" +
                                b"newVTSha: (.+);newVTEnc: (.+)$",
                                decrypted_message)

        if update_keys:
            l_name = update_keys.group(1)
            l_signature_b64 = update_keys.group(2)
            l_new_pk = update_keys.group(3)
            l_new_sk_aes_b64 = update_keys.group(4)
            l_new_vt_sha = update_keys.group(5)
            l_new_vt_enc = update_keys.group(6)

            l_database_query_error_code = self.database_manager.execute_function("updateKeys", (l_name,
                                                                                                l_signature_b64,
                                                                                                l_new_pk,
                                                                                                l_new_sk_aes_b64,
                                                                                                l_new_vt_sha,
                                                                                                l_new_vt_enc))

            self.log("update_keys name: {} error_code: {}".format(l_name, l_database_query_error_code))

            response_dict = {0: b"msg: Keys Updated;errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: Invalid Signature Characters;errorCode: invalidSignCh",
                             3: b"msg: Invalid newSKAesB64 Characters;errorCode: invalidNewSKAesB64",
                             4: b"msg: Invalid newPK Format or Characters;errorCode: invalidNewPK",
                             5: b"msg: Invalid Validation Token Sha Characters;errorCode: invalidVTSha",
                             6: b"msg: Invalid Validation Token Encrypted Characters;errorCode: invalidVTEnc",
                             7: b"msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                             8: b"msg: Error Importing User PK;errorCode: faultyPK",
                             9: b"msg: Faulty Signature;errorCode: invalidSign",
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        add_public_file = re.search(b"^addPublicFile;name: (.+);fileNameB64: (.+);fileB64Size: ([0-9]+);" +
                                    b"signatureB64: (.+)$",
                                    decrypted_message)

        if add_public_file:
            l_name = add_public_file.group(1)
            l_file_name_b64 = add_public_file.group(2)
            l_file_b64_size = add_public_file.group(3)
            l_signature_b64 = add_public_file.group(4)

            l_database_query_error_code = self.database_manager.execute_function("addPublicFile", (l_name,
                                                                                                   l_file_name_b64,
                                                                                                   l_file_b64_size,
                                                                                                   l_signature_b64,
                                                                                                   self))

            self.log("add_public_file name: {} error_code: {} file_name: {}".format(l_name, l_database_query_error_code,
                                                                                    l_file_name_b64))

            response_dict = {0: b"msg: Starting File Transmission;errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: Invalid Filename Characters;errorCode: invalidFilename",
                             3: b"msg: Invalid File Characters;errorCode: invalidFileCharacters",
                             4: b"msg: Invalid Signature Characters;errorCode: invalidSignCh",
                             5: b"msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                             6: b"msg: Error Importing User PK;errorCode: faultyPK",
                             7: b"msg: Faulty Signature;errorCode: invalidSign",
                             8: b"msg: Missing Public File List;errorCode: missingPUFL",
                             9: b"msg: File exceeds max file size;maxSize: %d;errorCode: fileTooBig" %
                                self.database_manager.max_file_size,
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        add_hidden_file = re.search(b"^addHiddenFile;name: (.+);fileNameB64: (.+);fileB64Size: ([0-9]+);" +
                                    b"signatureB64: (.+)$",
                                    decrypted_message)

        if add_hidden_file:
            l_name = add_hidden_file.group(1)
            l_file_name_b64 = add_hidden_file.group(2)
            l_file_b64_size = add_hidden_file.group(3)
            l_signature_b64 = add_hidden_file.group(4)

            l_database_query_error_code = self.database_manager.execute_function("addHiddenFile", (l_name,
                                                                                                   l_file_name_b64,
                                                                                                   l_file_b64_size,
                                                                                                   l_signature_b64,
                                                                                                   self))

            self.log("add_hidden_file name: {} error_code: {} file_name: {}".format(l_name, l_database_query_error_code,
                                                                                    l_file_name_b64))

            response_dict = {0: b"msg: File Added;errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: Invalid Filename Characters;errorCode: invalidFilename",
                             3: b"msg: Invalid File Characters;errorCode: invalidFileCharacters",
                             4: b"msg: Invalid Signature Characters;errorCode: invalidSignCh",
                             5: b"msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                             6: b"msg: Error Importing User PK;errorCode: faultyPK",
                             7: b"msg: Faulty Signature;errorCode: invalidSign",
                             8: b"msg: Missing Hidden File List;errorCode: missingHFL",
                             9: b"msg: File exceeds max file size;maxSize: %d;errorCode: fileTooBig" %
                                self.database_manager.max_file_size,
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        add_private_file = re.search(b"^addPrivateFile;name: (.+);fileNameB64: (.+);fileB64Size: ([0-9]+);" +
                                     b"signatureB64: (.+)$",
                                     decrypted_message)

        if add_private_file:
            l_name = add_private_file.group(1)
            l_file_name_b64 = add_private_file.group(2)
            l_file_b64_size = add_private_file.group(3)
            l_signature_b64 = add_private_file.group(4)

            l_database_query_error_code = self.database_manager.execute_function("addPrivateFile", (l_name,
                                                                                                    l_file_name_b64,
                                                                                                    l_file_b64_size,
                                                                                                    l_signature_b64,
                                                                                                    self))

            self.log("add_private_file name: {} error_code: {} file_name: {}".format(l_name,
                                                                                     l_database_query_error_code,
                                                                                     l_file_name_b64))

            response_dict = {0: b"msg: File Added;errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: Invalid Filename Characters;errorCode: invalidFilename",
                             3: b"msg: Invalid File Characters;errorCode: invalidFileCharacters",
                             4: b"msg: Invalid Signature Characters;errorCode: invalidSignCh",
                             5: b"msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                             6: b"msg: Error Importing User PK;errorCode: faultyPK",
                             7: b"msg: Faulty Signature;errorCode: invalidSign",
                             8: b"msg: Missing Private File List;errorCode: missingPRFL",
                             9: b"msg: File exceeds max file size;maxSize: %d;errorCode: fileTooBig" %
                                self.database_manager.max_file_size,
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        get_public_file_list = re.search(b"^getPublicFileList;name: (.+)$", decrypted_message)

        if get_public_file_list:
            l_name = get_public_file_list.group(1)

            l_database_query_result = self.database_manager.execute_function("getPublicFileList", (l_name,))
            l_database_query_error_code = l_database_query_result[0]

            self.log("get_public_file_list name: {} error_code: {}".format(l_name, l_database_query_error_code))

            response_dict = {0: b"msg: Returning PUFL;pufl: " + l_database_query_result[1] + b";errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: Missing Public File List;errorCode: missingHFL",
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        get_hidden_file_list = re.search(b"^getHiddenFileList;name: (.+);signatureB64: (.+)$", decrypted_message)

        if get_hidden_file_list:
            l_name = get_hidden_file_list.group(1)
            l_signature_b64 = get_hidden_file_list.group(2)

            l_database_query_result = self.database_manager.execute_function("getHiddenFileList", (l_name,
                                                                                                   l_signature_b64))
            l_database_query_error_code = l_database_query_result[0]

            self.log("get_hidden_file_list name: {} error_code: {}".format(l_name, l_database_query_error_code))

            response_dict = {0: b"msg: Returning HFL;hfl: " + l_database_query_result[1] + b";errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: Missing Hidden File List;errorCode: missingHFL",
                             3: b"msg: Invalid Signature Characters;errorCode: invalidSignCh",
                             4: b"msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                             5: b"msg: Error Importing User PK;errorCode: faultyPK",
                             6: b"msg: Faulty Signature;errorCode: invalidSign",
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        get_private_file_list = re.search(b"^getPrivateFileList;name: (.+);signatureB64: (.+)$", decrypted_message)

        if get_private_file_list:
            l_name = get_private_file_list.group(1)
            l_signature_b64 = get_private_file_list.group(2)

            l_database_query_result = self.database_manager.execute_function("getPrivateFileList", (l_name,
                                                                                                    l_signature_b64))
            l_database_query_error_code = l_database_query_result[0]

            self.log("get_private_file_list name: {} error_code: {}".format(l_name, l_database_query_error_code))

            response_dict = {0: b"msg: Returning PRFL;prfl: " + l_database_query_result[1] + b";errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: Missing Private File List;errorCode: missingPRFL",
                             3: b"msg: Invalid Signature Characters;errorCode: invalidSignCh",
                             4: b"msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                             5: b"msg: Error Importing User PK;errorCode: faultyPK",
                             6: b"msg: Faulty Signature;errorCode: invalidSign",
                             -1: b"msg: Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        get_file = re.search(b"^getFile;name: (.+);id: (.+)$", decrypted_message)

        if get_file:
            l_name = get_file.group(1)
            l_id = get_file.group(2)

            l_database_query_result = self.database_manager.execute_function("getFile", (l_name,
                                                                                         l_id,
                                                                                         self))
            l_database_query_error_code = l_database_query_result[0]

            self.log("get_file name: {} error_code: {} file_id: {}".format(l_name, l_database_query_error_code,
                                                                           l_id))

            response_dict = {0: b"msg: Sending file;fileSize: %d;errorCode: successful" %
                                l_database_query_result[1],
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: Missing Public File List;errorCode: missingPUFL",
                             3: b"msg: Missing Hidden File List;errorCode: missingHFL",
                             4: b"msg: Invalid Id Characters;errorCode: invalidIdCh",
                             5: b"msg: File in a list but nonexistent;errorCode: fileInListButNonexistent",
                             6: b"msg: File not found;errorCode: fileNotFound",
                             -1: b"msg: Server Panic!;errorCode: thisShouldNeverBeSeenByAnyone"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        get_private_file = re.search(b"^getPrivateFile;name: (.+);id: (.+);signatureB64: (.+)$", decrypted_message)

        if get_private_file:
            l_name = get_private_file.group(1)
            l_id = get_private_file.group(2)
            l_signature_b64 = get_private_file.group(3)

            l_database_query_result = self.database_manager.execute_function("getPrivateFile", (l_name, l_id,
                                                                                                l_signature_b64,
                                                                                                self))
            l_database_query_error_code = l_database_query_result[0]

            self.log("get_private_file name: {} error_code: {} file_id: {}".format(l_name, l_database_query_error_code,
                                                                                   l_id))

            response_dict = {0: b"msg: Returning fileB64;fileSize: %d;errorCode: successful" %
                                l_database_query_result[1],
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: Strange Error Where User Doesn't Have PK;errorCode: wtfHappenedToThePK",
                             3: b"msg: Invalid Signature Characters;errorCode: invalidSignCh",
                             4: b"msg: Invalid Id Characters;errorCode: invalidIdCh",
                             5: b"msg: Missing Private File List;errorCode: missingPRFL",
                             6: b"msg: Error Importing User PK;errorCode: faultyPK",
                             7: b"msg: Faulty Signature;errorCode: invalidSign",
                             8: b"msg: File not found;errorCode: fileNotFound",
                             9: b"msg: File in a list but nonexistent;errorCode: fileInListButNonexistent",
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        delete_file = re.search(b"^deleteFile;name: (.+);id: (.+);signatureB64: (.+)$", decrypted_message)

        if delete_file:
            l_name = delete_file.group(1)
            l_id = delete_file.group(2)
            l_signature_b64 = delete_file.group(3)

            l_database_query_error_code = self.database_manager.execute_function("deleteFile", (l_name, l_id,
                                                                                                l_signature_b64))

            self.log("delete_file name: {} error_code: {} file_id: {}".format(l_name, l_database_query_error_code,
                                                                              l_id))

            response_dict = {0: b"msg: File Deleted;errorCode: successful",
                             1: b"msg: User Doesn't Exist;errorCode: usrNotFound",
                             2: b"msg: Invalid Signature Characters;errorCode: invalidSignCh",
                             3: b"msg: Invalid Id Characters;errorCode: invalidIdCh",
                             4: b"msg: Missing Public File List;errorCode: missingPUFL",
                             5: b"msg: Missing Hidden File List;errorCode: missingHFL",
                             6: b"msg: Missing Private File List;errorCode: missingPRFL",
                             7: b"msg: Strange Error Where User Doesn't Have PK;errorCode: userWithoutPK",
                             8: b"msg: Error Importing User PK;errorCode: faultyPK",
                             9: b"msg: Faulty Signature;errorCode: invalidSign",
                             10: b"msg: File not found;errorCode: fileNotFound",
                             11: b"msg: File in a list but nonexistent;errorCode: fileInListButNonexistent",
                             -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = response_dict.get(l_database_query_error_code, b"msg: Bad Error Code;errorCode: badErrorCode")

            self.send(msg, encrypted=True, key=session_key)
            return False

        msg = b"msg: Invalid Request;errorCode: invalidReq"
        self.log("invalid_req")
        self.send(msg, encrypted=True, key=session_key)
        return False

    @staticmethod
    def encrypt_with_padding(key, plaintext):
        # type: (bytes, bytes) -> tuple
        length = (16 - (len(plaintext) % 16)) + 16 * random.randint(0, 14)
        plaintextPadded = plaintext + utils.get_rand_string(length - 1) + bytes([length])
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, b""
        ciphertext = utils.base64_encode(AES.new(key, AES.MODE_ECB).encrypt(plaintextPadded))
        return True, ciphertext

    @staticmethod
    def decrypt_with_padding(key, ciphertext):
        # type: (bytes, bytes) -> tuple
        if len(key) != 16 and len(key) != 32 and len(key) != 24:
            return False, b""
        ciphertextNotB64 = utils.base64_decode(ciphertext)
        plaintextPadded = AES.new(key, AES.MODE_ECB).decrypt(ciphertextNotB64)
        plaintext = plaintextPadded[:-plaintextPadded[-1]]
        return True, plaintext
