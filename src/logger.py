import threading
import datetime

class Logger:
    def __init__(self, filename):
        # type: (str) -> None
        self.filename = filename
        self.fileHandler = open(filename, "a")
        now = datetime.datetime.now()
        self.fileHandler.write("\n[Started at " + now.strftime("%Y-%m-%d %H:%M") + "]\n")
        self.fileLock = threading.Lock()

    def log(self, msg, printToScreen=True, debug=False):
        self.fileLock.acquire()
        if printToScreen or debug:
            print msg
        self.fileHandler.write(msg + "\n")
        self.fileLock.release()

    def clearLog(self):
        self.fileLock.acquire()
        self.fileHandler = open(self.filename, "w")
        self.fileHandler.close()
        self.fileHandler = open(self.filename, "w")
        self.fileLock.release()