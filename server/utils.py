import inspect
import base64
from Crypto.Random import random, get_random_bytes
from Crypto.Hash import SHA256
import re
import math


def lineno():
    return inspect.currentframe().f_back.f_lineno


def base64_encode(string):
    return base64.b64encode(string).replace(b"/", b"_")


def base64_decode(string):
    return base64.b64decode(string.replace(b"_", b"/"))


def is_base64(s):
    try:
        return base64_encode(base64_decode(s)) == s
    except Exception:
        return False


def get_rand_string(length):
    # type: (int) -> bytes
    while True:
        returnString = b""
        for x in range(0, length):
            returnString += get_random_bytes(1)
        if b"\x00" not in returnString:
            break
    return returnString


def extract_data(msg):
    # type: (bytes) -> tuple
    """

        Extract Data from Prive Message (data;errorCode: eC)

        Returns ("", "") if it is not a prive message

        :param msg: Message to extract data from
        :return: data, eC
    """

    msgRe = re.search(b"^(.+);errorCode: (.+)", msg)
    if not msgRe:
        return b"", b""

    msgData = msgRe.group(1)
    errorCode = msgRe.group(2)

    return msgData, errorCode


def check_proof_of_work(msg_to_verify, pow0es, pow_iterations):
    # type: (bytes, int, int) -> bool
    hash = SHA256.new(msg_to_verify)
    for i in range(0, pow_iterations - 1):
        hash.update(hash.hexdigest().encode("ascii"))

    if re.search(b"^" + b"0" * pow0es, hash.hexdigest().encode("ascii")):
        return True
    else:
        return False


def is_int(str_to_test):
    try:
        num = int(str_to_test)
        return True
    except:
        return False


def from_byte_to_b64_length(length):
    return int(math.ceil(length/3.0)*4)
