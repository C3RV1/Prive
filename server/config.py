

class Config:
    SERVER_NAME = "Prive"
    HOST = "127.0.0.1"
    PORT = 4373
    MAX_CURRENT_USERS = 10
    DATABASE_PATH = "../PriveDatabase"
    LOGFILE = "../prive.log"
    ALLOWED_NAME_CHARCTERS_RE = "^[A-Za-z0-9._]+$"
    CLIENT_TIMEOUT = 10
    KEYSIZE = 4096
    VERSION = "v0.0.2"
    MAX_FILE_SIZE = 1000000  # 10mb in bytes
    MAX_FILES = 10
