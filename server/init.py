import server
from config import Config
from colorama import init, Fore

__author__ = "KeyFr4me"

if __name__ == "__main__":
    init(convert=True)  # Color coding
    print Fore.WHITE
    print "Program Init"
    serv = server.Server()
    print Fore.WHITE + "Program Exit"
