import socket
import threading
import databaseManager
import clientHandle

class ConsoleForExit(threading.Thread):

    def __init__(self, serverMaster):
        #type: (Server) -> None
        threading.Thread.__init__(self)
        self.running = True
        self.serverMaster = serverMaster

    def run(self):
        while True:
            command = raw_input("> ")
            if command == "quit":
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
                 clientTimeout, keySize):
        # type: (str, int, str, int, str, str, str, int, int) -> None
        self.name = name
        self.host = host
        self.port = port
        print "Starting server: " + name
        self.listenSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listenSocket.bind((host, port))
        self.listenSocket.listen(maxCurrentUsers)
        self.clientThreads = []
        self.clientTimeout = clientTimeout
        try:
            self.database = databaseManager.DatabaseManager(databasePath, logFile, unacceptedNameCharacters)
        except Exception as e:
            print e.message
            return
        self.running = ConsoleForExit(self)
        self.running.start()
        self.run()

    def log(self, msg, printOnScreen=True, debug=False):
        # type: (str, bool, bool) -> None
        self.database.logger.log("[Server" + self.name + "] " + msg, printToScreen=printOnScreen, debug=debug)

    def run(self):
        while self.running.returnRunning():
            clientSocket, clientAddress = self.listenSocket.accept()
            self.log("Client " + str(clientAddress[0]) + " " + str(clientAddress[1]) + " Connected")
            self.clientThreads.append(clientHandle.ClientHandle(clientSocket, clientAddress, self.database, self,
                                                                self.clientTimeout))
            self.clientThreads[-1].start()

        for thread in self.clientThreads:
            thread.join()
        self.listenSocket.close()
        self.log("Exiting server: " + self.name)

    def deleteClientThread(self, clientThread):
        # type: (clientHandle.ClientHandle) -> None
        self.clientThreads.remove(clientThread)
