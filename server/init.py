import server
from config import Config
from colorama import init, Fore

__author__ = "KeyFr4me"

if __name__ == "__main__":
    init(convert=True)  # Color coding
    print Fore.WHITE
    print "Program Init"
    serv = server.Server(host=Config.HOST, port=Config.PORT, name=Config.SERVER_NAME,
                         maxCurrentUsers=Config.MAX_CURRENT_USERS, databasePath=Config.DATABASE_PATH,
                         logFile=Config.LOGFILE, unacceptedNameCharacters=Config.ALLOWED_NAME_CHARCTERS_RE,
                         clientTimeout=Config.CLIENT_TIMEOUT, keySize=Config.KEYSIZE, version=Config.VERSION,
                         maxFileSize=Config.MAX_FILE_SIZE)
    print Fore.WHITE + "Program Exit"
