import threading
import datetime
from colorama import init, Fore, Back, Style

init(convert=True)

class Logger:
    def __init__(self, filename):
        # type: (str) -> None
        self.filename = filename
        self.fileHandler = open(filename, "a")
        now = datetime.datetime.now()
        self.fileHandler.write("\n[Started at " + now.strftime("%Y-%m-%d %H:%M") + "]\n")
        self.fileLock = threading.Lock()

    def log(self, msg, printToScreen=True, debug=False, error=False):
        #type: (str, bool, bool, bool)
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
        self.fileHandler.write(msg + "\n")
        self.fileLock.release()

    def clearLog(self):
        self.fileLock.acquire()
        self.fileHandler = open(self.filename, "w")
        self.fileHandler.close()
        self.fileHandler = open(self.filename, "w")
        self.fileLock.release()