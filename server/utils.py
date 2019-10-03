import inspect
import base64
from Crypto.Random import random, get_random_bytes
import re


def lineno():
    return inspect.currentframe().f_back.f_lineno

def base64_encode(str):
    return base64.b64encode(str).replace("/", "_")

def base64_decode(str):
    return base64.b64decode(str.replace("_", "/"))

def isBase64(s):
    try:
        return base64_encode(base64_decode(s)) == s
    except Exception:
        return False

def getRandString(len):
    # type: (int) -> str
    returnString = ""
    for x in range(0, len):
        returnString += get_random_bytes(1)
    if "\x00" in returnString:
        return getRandString(len)
    return returnString

def extractData(msg):
        # type: (str) -> tuple
        """

        Extract Data from Prive Message (data;errorCode: eC)

        Returns ("", "") if it is not a prive message

        :param msg: Message to extract data from
        :return: data, eC
        """

        msgRe = re.search("^(.+);errorCode: (.+)", msg)
        if not msgRe:
            return "", ""

        msgData = msgRe.group(1)
        errorCode = msgRe.group(2)

        return msgData, errorCode