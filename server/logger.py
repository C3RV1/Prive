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
        self.original_filename = Config.LOGFILE
        self.folder = Config.LOGFOLDER
        if not os.path.isdir(self.folder):
            os.mkdir(self.folder)
        self.filename = ""
        self.file_handler = None
        self.update_filename()
        self.file_lock = threading.Lock()

    def update_filename(self):
        previous_filename = self.filename
        now = datetime.datetime.now()
        self.filename = self.folder + "/" + self.original_filename + " " + now.strftime(Config.LOG_FILE_DIFF) + ".log"
        if not previous_filename == self.filename:
            if not os.path.isfile(self.filename):
                self.file_handler = open(self.filename, "w")
            else:
                self.file_handler = open(self.filename, "a")
            self.file_handler.write("\n[Started at " + now.strftime("%Y-%m-%d %H:%M") + "]\n")
            self.file_handler.close()

    def log(self, name, message, print_to_screen=True, debug=False, error=False, save_to_file=True):
        # type: (str, str, bool, bool, bool, bool) -> None
        # [ServerTest]
        # reload(loggerConfig)
        msg = loggerConfig.name_and_message(name, message)
        self.file_lock.acquire()
        self.update_filename()
        self.file_handler = open(self.filename, "a")
        if print_to_screen or debug or error:
            if debug:
                print("")
                print(Fore.GREEN + "DEBUG " + msg + Fore.WHITE)
                print("")
            elif error:
                print("")
                print(Fore.RED + "ERROR " + msg + Fore.WHITE)
                print("")
            else:
                print(Fore.WHITE + "INFO " + msg)
        if save_to_file:
            if debug:
                self.file_handler.write("DEBUG " + msg + "\n")
            elif error:
                self.file_handler.write("ERROR " + msg + "\n")
            else:
                self.file_handler.write("INFO " + msg + "\n")
        self.file_handler.close()
        self.file_lock.release()

    def clear_log(self):
        self.file_lock.acquire()
        os.rmdir(self.folder)
        os.mkdir(self.folder)
        self.update_filename()
        self.file_lock.release()