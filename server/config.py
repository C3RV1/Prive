

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
    CLIENT_KEYSIZE = 2048
    VERSION = "v1.0.0"
    MAX_FILE_SIZE = 1000000  # 1mb in bytes
    POW_NUM_OF_0 = 4  # Num of hexadecimal zeroes in front of verification
    POW_ITERATIONS = 2  # Num of hash iterations
