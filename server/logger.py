import threading
import datetime
from colorama import init, Fore, Back, Style
import loggerConfig
from config import Config
import os

init(convert=True)

class Logger:
    def __init__(self):
        # type: () -> None
        self.originalFilename = Config.LOGFILE
        self.folder = Config.LOGFOLDER
        if not os.path.isdir(self.folder):
            os.mkdir(self.folder)
        self.filename = ""
        self.updateFilename()
        self.fileLock = threading.Lock()

    def updateFilename(self):
        previousFilename = self.filename
        now = datetime.datetime.now()
        self.filename = self.folder + "/" + self.originalFilename + " " + now.strftime(Config.LOG_FILE_DIFF) + ".log"
        if not previousFilename == self.filename:
            self.fileHandler = open(self.filename, "w")
            self.fileHandler.write("\n[Started at " + now.strftime("%Y-%m-%d %H:%M") + "]\n")
            self.fileHandler.close()

    def log(self, name, message, printToScreen=True, debug=False, error=False, saveToFile=True):
        # type: (str, str, bool, bool, bool, bool) -> None
        # [ServerTest]
        reload(loggerConfig)
        msg = loggerConfig.nameAndMessage(name, message)
        self.fileLock.acquire()
        self.updateFilename()
        self.fileHandler = open(self.filename, "a")
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
        self.fileHandler.close()
        self.fileLock.release()

    def clearLog(self):
        self.fileLock.acquire()
        os.rmdir(self.folder)
        os.mkdir(self.folder)
        self.updateFilename()
        self.fileLock.release()