import socket
import threading
import databaseManager
import clientHandle
import time
from config import Config


class ConsoleForExit(threading.Thread):
    def __init__(self, server_master):
        # type: (Server) -> None
        threading.Thread.__init__(self)
        self.running = True
        self.serverMaster = server_master

    def run(self):
        while True:
            try:
                command = input("> ")
            except Exception as e:
                print(e)
                continue
            if command in ["stop", "quit", "exit"]:
                self.serverMaster.log("Stopping the server")
                self.running = False
                disconnect_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                disconnect_socket.connect((self.serverMaster.host, self.serverMaster.port))
                disconnect_socket.send(b"quit\r\n")
                disconnect_socket.close()
                break
            elif command == "clear_log":
                self.serverMaster.log("Clearing Log", save_to_file=False)
                self.serverMaster.database.logger.clear_log()
            elif command == "help":
                self.serverMaster.log("=== Help ===")
                self.serverMaster.log("stop:          stop the server", save_to_file=False)
                self.serverMaster.log("clear_log:     clear the log", save_to_file=False)
                self.serverMaster.log("name:          show the name of the server", save_to_file=False)
                self.serverMaster.log("version:       show the version of the server", save_to_file=False)
                self.serverMaster.log("current_users: show the number of user connected", save_to_file=False)
            elif command == "name":
                self.serverMaster.log("Server name: {}".format(self.serverMaster.name), save_to_file=False)
            elif command == "version":
                self.serverMaster.log("Server version: {}".format(self.serverMaster.version), save_to_file=False)
            elif command == "current_users":
                self.serverMaster.log("Current users connected: {}".format(len(self.serverMaster.client_threads)),
                                      save_to_file=False)

    def return_running(self):
        return self.running


class Server:

    def __init__(self):
        # type: () -> None
        self.name = Config.SERVER_NAME
        self.host = Config.HOST
        self.port = Config.PORT
        self.max_current_users = Config.MAX_CURRENT_USERS
        self.version = Config.VERSION
        print("Starting up server: " + self.name)
        print("Server version: " + self.version)

        # Master socket for connection accepting
        self.listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listen_socket.bind(("0.0.0.0", self.port))
        self.listen_socket.listen(self.max_current_users)

        # List of client threads
        self.client_threads = []
        try:
            self.database = databaseManager.DatabaseManager(self)
        except Exception as e:
            print(e)
            return

        # Command Console
        self.running = ConsoleForExit(self)
        self.running.start()
        self.database.start()
        self.log("Startup done")
        self.run()

    def log(self, msg, print_on_screen=True, debug=False, save_to_file=True):
        # type: (str, bool, bool, bool) -> None
        self.database.logger.log("Server " + self.name + " " + self.version, msg, print_to_screen=print_on_screen,
                                 debug=debug, save_to_file=save_to_file)

    def run(self):
        while self.running.return_running():
            if len(self.client_threads) >= self.max_current_users:
                time.sleep(0.5)
                continue
            client_socket, client_address = self.listen_socket.accept()
            self.log("Client " + str(client_address[0]) + " " + str(client_address[1]) + " Connected",
                     print_on_screen=False)
            self.client_threads.append(clientHandle.ClientHandle(client_socket, client_address, self.database, self))
            self.client_threads[-1].start()
            # self.log("N of clients:" + str(len(self.clientThreads)), printOnScreen=False)

        for thread in self.client_threads:
            thread.join()
        self.listen_socket.close()
        self.log("Exiting")

    def delete_client_thread(self, client_thread):
        # type: (clientHandle.ClientHandle) -> None
        self.client_threads.remove(client_thread)
        # self.log("N of clients:" + str(len(self.clientThreads)), printOnScreen=False)
