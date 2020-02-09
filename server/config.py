

class Config:
    SERVER_NAME = "Prive"
    HOST = "127.0.0.1"
    PORT = 4373
    MAX_CURRENT_USERS = 10
    DATABASE_PATH = "../PriveDatabase"
    LOGFILE = "prive"
    LOGFOLDER = "../log"
    LOG_FILE_DIFF = "%A"  # Difference at the end of log file names to know where they were created

    # Note: %A means that it will be replaced with the day of the week, meaning
    #       that it will overwrite the log files every week.

    ALLOWED_NAME_CHARCTERS_RE = "^[A-Za-z0-9._]+$"
    CLIENT_TIMEOUT = 10
    KEYSIZE = 4096
    CLIENT_KEYSIZE = 2048
    VERSION = "v2.6.0"
    MAX_FILE_SIZE = 1000000000  # 1gb in bytes
                                # Maximum user size: 4000000000

    # Note: Max file size is for every individual type of file (public, hidden and private) in bytes,
    #       what means that the total storage in bytes is 3 times the previously specified value.
    #       If we converted this total size in bytes to base 64 size (bytes*4/3) we have a maximum size
    #       for each user of the max file size multiplied by 4 plus the size keys and other profile data
    #       occupy.

    POW_NUM_OF_0 = 4  # Num of hexadecimal zeroes in front of hash for it to be verified
    POW_ITERATIONS = 2  # Num of hash iterations
    FILE_SEND_CHUNKS = 65536*4  # Size of chunks to be sent
