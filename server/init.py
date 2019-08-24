import server
from config import Config
from colorama import init, Fore

__author__ = "KeyFr4me"

if __name__ == "__main__":
    init(convert=True)
    print Fore.WHITE
    print "Program Init"
    serv = server.Server(host=Config.HOST, port=Config.PORT, name=Config.SERVER_NAME,
                         maxCurrentUsers=Config.MAX_CURRENT_USERS, databasePath=Config.DATABASE_PATH,
                         logFile=Config.LOGFILE, unacceptedNameCharacters=Config.UNACCEPTED_NAME_CHARCTERS,
                         clientTimeout=Config.CLIENT_TIMEOUT, keySize=Config.KEYSIZE, version=Config.VERSION)
    print Fore.WHITE + "Program Exit"
