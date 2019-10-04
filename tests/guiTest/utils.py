import base64

def base64_encode(str):
    return base64.b64encode(str).replace("/", "_")

def base64_decode(str):
    return base64.b64decode(str.replace("_", "/"))

def isBase64(s):
    try:
        return base64_encode(base64_decode(s)) == s
    except Exception:
        return False