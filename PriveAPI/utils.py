import base64
import re
from Crypto.Hash import SHA256


def base64_encode(str):
    return base64.b64encode(str).replace("/", "_")

def base64_decode(str):
    return base64.b64decode(str.replace("_", "/"))

def isBase64(s):
    try:
        return base64_encode(base64_decode(s)) == s
    except Exception:
        return False

def checkProofOfWork(msgToVerify, pow0es, powIterations):
    # type: (str, int, int) -> bool
    hash = SHA256.new(msgToVerify)
    for i in range(0, powIterations - 1):
        hash.update(hash.hexdigest())

    if re.search("^" + "0" * pow0es, hash.hexdigest()):
        return True
    else:
        return False
