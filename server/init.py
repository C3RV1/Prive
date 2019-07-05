import server
from config import Config

__author__ = "KeyFr4me"

if __name__ == "__main__":
    print "Program Init"
    serv = server.Server(host=Config.HOST, port=Config.PORT, name=Config.SERVER_NAME,
                         maxCurrentUsers=Config.MAX_CURRENT_USERS, databasePath=Config.DATABASE_PATH,
                         logFile=Config.LOGFILE, unacceptedNameCharacters=Config.UNACCEPTED_NAME_CHARCTERS,
                         clientTimeout=Config.CLIENT_TIMEOUT, keySize=Config.KEYSIZE)
    print "Program Exit"
