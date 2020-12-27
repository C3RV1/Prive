from Crypto.Cipher import AES
from Crypto.Random import random
import server
import re
import databaseManager
import socket
import threading
import time
import utils
import os
import shutil
import clientHandle
from config import Config


class Timeout(threading.Thread):
    def __init__(self, client_handler_master, sock, client_address, database_manager):
        # type: (FileTransfer, socket.socket, tuple, databaseManager.DatabaseManager) -> None
        self.database_manager = database_manager
        self.client_address = client_address
        # self.log("Starting Timeout Thread on ClientFT " + str(client_address[0]) + " " + str(client_address[1]),
        #          print_on_screen=False)
        threading.Thread.__init__(self)
        self.socket = sock
        self.start_timeout = time.time()
        self.timeout_event = threading.Event()
        self.timeout = Config.CLIENT_TIMEOUT
        self.client_handler_master = client_handler_master

    def log(self, msg, print_on_screen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.database_manager.logger.log("Client.FT.Timeout:" + str(self.client_address[0]) + ":" +
                                         str(self.client_address[1]),
                                         msg, print_to_screen=print_on_screen, debug=debug)

    def stop(self):
        self.timeout_event.set()

    def reset_time(self):
        self.start_timeout = time.time()

    def run(self):
        while not self.timeout_event.is_set():
            if time.time() - self.start_timeout >= self.timeout:
                # self.log("ClientFT " + str(self.client_address[0]) + " " + str(self.client_address[1]) +
                #          " has reached the timeout",
                #          print_on_screen=False)
                self.client_handler_master.client_handle.close_all()
                self.client_handler_master.end_transmission()
                break
            time.sleep(1)
        # self.log("Exiting Timeout", print_on_screen=False)


class FileTransfer(threading.Thread):

    def __init__(self, client_socket, client_address, database_manager, server_master, tmp_folder, receive_size,
                 end_file_path, client_handle, list_path, list_data):
        # type: (socket.socket, tuple, databaseManager.DatabaseManager, server.Server, str, int, str, clientHandle.ClientHandle, str, bytes) -> None
        threading.Thread.__init__(self)
        self.client_socket = client_socket
        self.client_address = client_address
        self.database_manager = database_manager
        self.server_master = server_master
        self.timeout_list = [0, False]  # Because all instances share the same object
        self.time_out_controller = Timeout(self, self.client_socket, self.client_address, database_manager)
        self.time_out_controller.start()
        self.running_event = threading.Event()

        self.client_handle = client_handle
        self.client_handle.receive_event.set()

        self.currently_received = 0
        self.tmp_folder = tmp_folder
        self.receive_size = receive_size
        self.end_file_path = end_file_path
        self.transmission_completed = False

        self.list_path = list_path
        self.list_data = list_data

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
                    if len(data) > utils.from_byte_to_b64_length(Config.FILE_SEND_CHUNKS * 4 +
                                                                 len(b"segment;num: ;data: ") + len(b"00000000")):
                        # self.log("Maximum reached (Length {}, Max: {})".format(len(data),
                        #                                                        utils.from_byte_to_b64_length(
                        #                                                            Config.FILE_SEND_CHUNKS * 4 +
                        #                                                            len("segment;num: ;data: ") +
                        #                                                            len("00000000"))), debug=True)
                        break
                if self.running_event.is_set():
                    break
                if self.handle_message(data):
                    if not self.transmission_completed:
                        self.client_handle.close_all()
                    break
                if not self.server_master.running.return_running():
                    self.send(b"quit")
                    self.client_handle.close_all()
                    break
            except ZeroDivisionError as e:
                self.log("Error:" + str(e), error=True)
                self.client_handle.close_all()
                self.end_transmission()
        self.end_transmission()

    def end_transmission(self):
        if self.running_event.is_set():
            return
        self.running_event.set()
        self.log("ending", print_on_screen=False)
        # self.log("Removing Timeout", print_on_screen=False)
        try:
            shutil.rmtree(self.tmp_folder[:-1])
        except:
            pass
        self.time_out_controller.stop()
        try:
            self.time_out_controller.join()
        except:
            pass
        self.time_out_controller = None
        self.client_handle.receive_event.clear()

    def log(self, msg, print_on_screen=True, debug=False, error=False, save_to_file=True):
        # type: (str, bool, bool, bool, bool) -> None
        self.database_manager.logger.log("ClientFileTransfer:" + str(self.client_address[0]) + ":" +
                                         str(self.client_address[1]),
                                         msg, print_to_screen=print_on_screen, debug=debug, error=error,
                                         save_to_file=save_to_file)

    def send(self, msg, encrypted=False, key=b""):
        # type: (bytes, bool, bytes) -> None
        if encrypted:
            msg = self.encrypt_with_padding(key, msg)[1]
        msg += b"\r\n"
        self.client_socket.send(msg)

    def handle_message(self, data):
        # type: (bytes) -> bool
        # Reset timeout time
        self.time_out_controller.reset_time()

        # Remove \r\n from message
        data = data[:-2]

        if re.search(b"^quit$", data):
            return True

        # Get session key if exists
        session_key = self.database_manager.get_session_key(self.client_address[0], self.client_address[1])

        session_key = session_key[1]

        decrypted_message = self.decrypt_with_padding(session_key, data)[1]  # type: bytes
        showTxt = decrypted_message.split(b";")[0]
        if showTxt != b"keepAlive" and showTxt != b"segment":
            self.log("Received: [" + decrypted_message.decode("ascii") + "]", print_on_screen=False)

        if re.search(b"^quit$", decrypted_message):
            return True
        if re.search(b"^keepAlive$", decrypted_message):
            return False

        segment = re.search(b"^segment;num: ([0-9]+);data: (.+)$", decrypted_message)

        if segment:
            segmentNum = segment.group(1)
            data = segment.group(2)

            result = self.handle_segment(segmentNum, data)
            errorCode = result[1]

            if errorCode == 4:
                self.complete_transmission()

            responseDict = {0: b"msg: Segment Received Correctly;errorCode: successful",
                            1: b"msg: Segment Already Exists;errorCode: segmentAlreadyExists",
                            2: b"msg: Invalid Data Characters;errorCode: invalidDataCh",
                            3: b"msg: Invalid Data Chunk;errorCode: invalidDataCk",
                            4: b"msg: Data Transmission Finished;errorCode: successful",
                            -1: b"msg: Server Panic!;errorCode: serverPanic"}

            msg = responseDict.get(errorCode, b"msg: Bad Error Code;errorCode: badErrorCode")
            self.send(msg, encrypted=True, key=session_key)
            return result[0]

        msg = b"msg: Invalid Request;errorCode: invalidReq"
        self.send(msg, encrypted=True, key=session_key)
        return True

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

    def handle_segment(self, segment_num, data):
        # type: (bytes, bytes) -> tuple
        if os.path.isfile("{}tmp-{}.tfd".format(self.tmp_folder, segment_num.decode("ascii"))):
            return False, 1

        if not utils.is_base64(data):
            return True, 2

        if re.search(b"=$", data) and self.currently_received + len(data) < self.receive_size:
            return True, 3

        self.currently_received += len(data)

        tmpFile = open("{}tmp-{}.tfd".format(self.tmp_folder, segment_num.decode("ascii")), "wb")
        tmpFile.write(data)
        tmpFile.close()

        if self.currently_received >= self.receive_size:
            return True, 4

        return False, 0

    def complete_transmission(self):
        self.log("completed", print_on_screen=False)

        self.database_manager.database_lock.acquire()

        list_of_segments = os.listdir(self.tmp_folder)
        list_of_segments_num = []
        for segment in list_of_segments:
            group = re.search("^tmp-([0-9]+).tfd$", segment)
            if group:
                list_of_segments_num.append(int(group.group(1)))
        list_of_segments_num.sort()

        outputFile = open(self.end_file_path, "wb")
        for segmentNum in list_of_segments_num:
            openSegmentFile = open("{}tmp-{}.tfd".format(self.tmp_folder, segmentNum), "rb")
            outputFile.write(openSegmentFile.read())
            openSegmentFile.close()
        outputFile.close()

        self.transmission_completed = True

        fileList = open(self.list_path, "ab")
        fileList.write(self.list_data)
        fileList.close()
        
        self.database_manager.database_lock.release()
