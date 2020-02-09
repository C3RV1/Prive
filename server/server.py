import socket
import threading
import databaseManager
import clientHandle
import time
from config import Config

class ConsoleForExit(threading.Thread):

    def __init__(self, serverMaster):
        #type: (Server) -> None
        threading.Thread.__init__(self)
        self.running = True
        self.serverMaster = serverMaster

    def run(self):
        while True:
            try:
                command = raw_input("> ")
            except Exception as e:
                print e
                continue
            if command in ["stop", "quit", "exit"]:
                self.serverMaster.log("Stopping the server")
                self.running = False
                disconectSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                disconectSocket.connect((self.serverMaster.host, self.serverMaster.port))
                disconectSocket.send("quit\r\n")
                disconectSocket.close()
                break
            elif command == "clear_log":
                self.serverMaster.log("Clearing Log", saveToFile=False)
                self.serverMaster.database.logger.clearLog()
            elif command == "help":
                self.serverMaster.log("=== Help ===")
                self.serverMaster.log("stop:          stop the server", saveToFile=False)
                self.serverMaster.log("clear_log:     clear the log", saveToFile=False)
                self.serverMaster.log("name:          show the name of the server", saveToFile=False)
                self.serverMaster.log("version:       show the version of the server", saveToFile=False)
                self.serverMaster.log("current_users: show the number of user connected", saveToFile=False)
            elif command == "name":
                self.serverMaster.log("Server name: {}".format(self.serverMaster.name), saveToFile=False)
            elif command == "version":
                self.serverMaster.log("Server version: {}".format(self.serverMaster.version), saveToFile=False)
            elif command == "current_users":
                self.serverMaster.log("Current users connected: {}".format(len(self.serverMaster.clientThreads)),
                                      saveToFile=False)

    def returnRunning(self):
        return self.running


class Server:

    def __init__(self):
        # type: () -> None
        self.name = Config.SERVER_NAME
        self.host = Config.HOST
        self.port = Config.PORT
        self.maxCurrentUsers = Config.MAX_CURRENT_USERS
        self.version = Config.VERSION
        print "Starting up server: " + self.name
        print "Server version: " + self.version

        # Master socket for connection accepting
        self.listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listenSocket.bind(("0.0.0.0", self.port))
        self.listenSocket.listen(self.maxCurrentUsers)

        # List of client threads
        self.clientThreads = []
        try:
            self.database = databaseManager.DatabaseManager(self)
        except Exception as e:
            print e
            return

        # Command Console
        self.running = ConsoleForExit(self)
        self.running.start()
        self.database.start()
        self.log("Startup done")
        self.run()

    def log(self, msg, printOnScreen=True, debug=False, saveToFile=True):
        # type: (str, bool, bool, bool) -> None
        self.database.logger.log("Server " + self.name + " " + self.version, msg, printToScreen=printOnScreen,
                                 debug=debug, saveToFile=saveToFile)

    def run(self):
        while self.running.returnRunning():
            if len(self.clientThreads) >= self.maxCurrentUsers:
                time.sleep(0.5)
                continue
            clientSocket, clientAddress = self.listenSocket.accept()
            self.log("Client " + str(clientAddress[0]) + " " + str(clientAddress[1]) + " Connected",
                     printOnScreen=False)
            self.clientThreads.append(clientHandle.ClientHandle(clientSocket, clientAddress, self.database, self))
            self.clientThreads[-1].start()
            # self.log("N of clients:" + str(len(self.clientThreads)), printOnScreen=False)

        for thread in self.clientThreads:
            thread.join()
        self.listenSocket.close()
        self.log("Exiting")

    def deleteClientThread(self, clientThread):
        # type: (clientHandle.ClientHandle) -> None
        self.clientThreads.remove(clientThread)
        # self.log("N of clients:" + str(len(self.clientThreads)), printOnScreen=False)
