from Crypto.Cipher import AES
from Crypto.Random import random
import re
import databaseManager
import socket
import threading
import time
import utils
import clientHandle
from config import Config


class Timeout(threading.Thread):
    def __init__(self, client_handler_master, sock, client_address, timeout, database_manager):
        # type: (FileSend, socket.socket, tuple, int, databaseManager.DatabaseManager) -> None
        self.database_manager = database_manager
        self.client_address = client_address
        # self.log("Starting Timeout Thread on ClientFT " + str(client_address[0]) + " " + str(client_address[1]),
        #          print_on_screen=False)
        threading.Thread.__init__(self)
        self.socket = sock
        self.start_timeout = time.time()
        self.timeout_event = threading.Event()
        self.timeout = timeout
        self.client_handler_master = client_handler_master

    def log(self, msg, print_on_screen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.database_manager.logger.log("Client.FS.Timeout:" + str(self.client_address[0]) + ":" +
                                         str(self.client_address[1]),
                                         msg, print_to_screen=print_on_screen, debug=debug)

    def stop(self):
        self.timeout_event.set()

    def reset_time(self):
        self.start_timeout = time.time()

    def run(self):
        while not self.timeout_event.is_set():
            if time.time() - self.start_timeout >= self.timeout:
                # self.log("ClientFS " + str(self.client_address[0]) + " " + str(self.client_address[1]) +
                #          " has reached the timeout",
                #          print_on_screen=False)
                self.client_handler_master.client_handle.close_all()
                self.client_handler_master.end_transmission()
                break
            time.sleep(1)
        # self.log("Exiting Timeout", print_on_screen=False)


class FileSend(threading.Thread):

    def __init__(self, client_handler, path):
        # type: (clientHandle.ClientHandle, str) -> None
        threading.Thread.__init__(self)
        self.client_socket = client_handler.client_socket
        self.client_address = client_handler.client_address
        self.database_manager = client_handler.database_manager
        self.server_master = client_handler.server_master
        self.timeout_list = [0, False]  # Because all instances share the same object
        self.time_out_controller = Timeout(self, self.client_socket, self.client_address,
                                           client_handler.timeout_controller.timeout, self.database_manager)
        self.time_out_controller.start()
        self.running_event = threading.Event()

        self.client_handle = client_handler
        self.client_handle.receive_event.set()

        self.path = path
        self.segment = 0

    def run(self):
        self.log("start", print_on_screen=False)
        while not self.running_event.is_set():
            try:
                data = b""
                while True:
                    newData = self.client_socket.recv(4096)
                    data = data + newData
                    if re.search(b"\r\n", newData):
                        break

                    # ANTI MEMORY LEAK
                    if len(data) > len(b"keepAlive\r\n"):
                        break
                if self.running_event.is_set():
                    break
                if self.handle_message(data):
                    break
                if not self.server_master.running.return_running():
                    self.send(b"quit")
                    self.client_handle.close_all()
                    break
            except Exception as e:
                self.log("Error:" + str(e), error=True)
                self.client_handle.close_all()
                return self.end_transmission()
        return self.end_transmission()

    def end_transmission(self):
        if self.running_event.is_set():
            return
        self.running_event.set()
        self.log("ending", print_on_screen=False)
        # self.log("Removing Timeout", print_on_screen=False)
        self.time_out_controller.stop()
        try:
            self.time_out_controller.join()
        except:
            pass
        self.time_out_controller = None
        self.client_handle.receive_event.clear()
        return None

    def log(self, msg, print_on_screen=True, debug=False, error=False, save_to_file=True):
        # type: (str, bool, bool, bool, bool) -> None
        self.database_manager.logger.log(
            "ClientFileSend:" + self.client_address[0] + ":" + str(self.client_address[1]),
            msg, print_to_screen=print_on_screen, debug=debug, error=error, save_to_file=save_to_file)

    def send(self, msg, encrypted=False, key=b""):
        # type: (bytes, bool, bytes) -> None
        if encrypted:
            msg = self.encrypt_with_padding(key, msg)[1]
        msg += b"\r\n"
        self.client_socket.send(msg)

    def handle_message(self, data):
        # Reset timeout time
        self.time_out_controller.reset_time()

        # Remove \r\n from message
        data = data[:-2]

        if re.search(b"^quit$", data):
            return True

        # Get session key if exists
        session_key = self.database_manager.get_session_key(self.client_address[0], self.client_address[1])

        session_key = session_key[1]

        decrypted_message = self.decrypt_with_padding(session_key, data)[1]
        showTxt = decrypted_message.split(b";")[0]

        if showTxt != b"keepAlive" and showTxt != b"segment":
            self.log("Received: [" + decrypted_message.decode("ascii") + "]", print_on_screen=False)

        if re.search(b"^quit$", decrypted_message):
            return True
        if re.search(b"^keepAlive$", decrypted_message):
            return False

        segment = re.search(b"^segment$", decrypted_message)

        if segment:
            result = self.handle_segment()
            errorCode = result[1]

            responseDict = {0: b"msg: Sending Segment;segment: %d;data: %s;errorCode: successful" % (result[3],
                                                                                                     result[2]),
                            1: b"msg: All Segments Sent;errorCode: allSent",
                            2: b"msg: File May Have Been Deleted While Reading;errorCode: fileError",
                            -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(errorCode, b"msg: Bad Error Code;errorCode: badErrorCode")
            self.send(msg, encrypted=True, key=session_key)
            return result[0]

        msg = b"msg: Invalid Request;errorCode: invalidReq"
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

    def handle_segment(self):
        try:
            f = open(self.path, "rb")
            f.seek(self.segment*Config.FILE_SEND_CHUNKS*4)
            fileData = f.read(Config.FILE_SEND_CHUNKS*4)
            self.segment += 1
            f.close()
            if fileData == b"":
                return True, 1, fileData, self.segment
            else:
                return False, 0, fileData, self.segment
        except:
            return True, 2, b"", self.segment
