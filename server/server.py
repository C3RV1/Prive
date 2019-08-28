import socket
import threading
import databaseManager
import clientHandle
import time

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
            if command == "exit":
                self.serverMaster.log("Exiting")
                self.running = False
                disconectSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                disconectSocket.connect((self.serverMaster.host, self.serverMaster.port))
                disconectSocket.send("quit\r\n")
                disconectSocket.close()
                break
            if command == "clearLog":
                self.serverMaster.log("Clearing Log")
                self.serverMaster.database.logger.clearLog()

    def returnRunning(self):
        return self.running


class Server:

    def __init__(self, host, port, name, maxCurrentUsers, databasePath, logFile, unacceptedNameCharacters,
                 clientTimeout, keySize, version, maxFileSize):
        # type: (str, int, str, int, str, str, str, int, int, str) -> None
        self.name = name
        self.host = host
        self.port = port
        self.maxCurrentUsers = maxCurrentUsers
        self.version = version
        print "Starting up server: " + name
        print "Server version: " + version

        # Master socket for connection accepting
        self.listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listenSocket.bind((host, port))
        self.listenSocket.listen(maxCurrentUsers)

        # List of client threads
        self.clientThreads = []
        self.clientTimeout = clientTimeout
        try:
            self.database = databaseManager.DatabaseManager(databasePath, logFile, unacceptedNameCharacters, keySize, maxFileSize)
        except Exception as e:
            print e.message
            return

        # Command Console
        self.running = ConsoleForExit(self)
        self.running.start()
        self.log("Startup done")
        self.run()

    def log(self, msg, printOnScreen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.database.logger.log("Server " + self.name, msg, printToScreen=printOnScreen, debug=debug)

    def run(self):
        while self.running.returnRunning():
            if len(self.clientThreads) >= self.maxCurrentUsers:
                time.sleep(0.5)
                continue
            clientSocket, clientAddress = self.listenSocket.accept()
            self.log("Client " + str(clientAddress[0]) + " " + str(clientAddress[1]) + " Connected")
            self.clientThreads.append(clientHandle.ClientHandle(clientSocket, clientAddress, self.database, self,
                                                                self.clientTimeout))
            self.clientThreads[-1].start()
            self.log("N of clients:" + str(len(self.clientThreads)))

        for thread in self.clientThreads:
            thread.join()
        self.listenSocket.close()
        self.log("Exiting")

    def deleteClientThread(self, clientThread):
        # type: (clientHandle.ClientHandle) -> None
        self.clientThreads.remove(clientThread)
        self.log("N of clients:" + str(len(self.clientThreads)))
