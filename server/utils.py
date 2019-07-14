import inspect
import base64


def lineno():
    return inspect.currentframe().f_back.f_lineno

def isBase64(s):
    try:
        return base64.b64encode(base64.b64decode(s)) == s
    except Exception:
        return False
