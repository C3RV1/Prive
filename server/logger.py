import threading
import datetime
from colorama import init, Fore, Back, Style
import loggerConfig

init(convert=True)

class Logger:
    def __init__(self, filename):
        # type: (str) -> None
        self.filename = filename
        self.fileHandler = open(filename, "a")
        now = datetime.datetime.now()
        self.fileHandler.write("\n[Started at " + now.strftime("%Y-%m-%d %H:%M") + "]\n")
        self.fileLock = threading.Lock()

    def log(self, name, message, printToScreen=True, debug=False, error=False, saveToFile=True):
        # type: (str, str, bool, bool, bool, bool) -> None
        # [ServerTest]
        reload(loggerConfig)
        msg = loggerConfig.nameAndMessage(name, message)
        self.fileLock.acquire()
        if printToScreen or debug or error:
            if debug:
                print ""
                print Fore.GREEN + " ***[DEBUG]*** " + msg
                print ""
            elif error:
                print ""
                print Fore.RED + " ***[ERROR]*** " + msg
                print ""
            else:
                print Fore.WHITE + msg
        if saveToFile:
            if debug:
                self.fileHandler.write(" ***[DEBUG]*** " + msg + "\n")
            elif error:
                self.fileHandler.write(" ***[ERROR]*** " + msg + "\n")
            else:
                self.fileHandler.write(msg + "\n")
        self.fileLock.release()

    def clearLog(self):
        self.fileLock.acquire()
        self.fileHandler = open(self.filename, "w")
        self.fileHandler.close()
        self.fileHandler = open(self.filename, "w")
        self.fileLock.release()