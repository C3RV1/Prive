import inspect
import base64
from Crypto.Random import random, get_random_bytes


def lineno():
    return inspect.currentframe().f_back.f_lineno

def isBase64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False

def getRandString(len):
    # type: (int) -> str
    returnString = ""
    for x in range(0, len):
        returnString += get_random_bytes(1)
    return returnString
