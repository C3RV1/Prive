import base64
import re
from Crypto.Hash import SHA256


def base64_encode(string):
    return base64.b64encode(string).replace(b"/", b"_")


def base64_decode(string):
    return base64.b64decode(string.replace(b"_", b"/"))


def is_base64(s):
    try:
        return base64_encode(base64_decode(s)) == s
    except Exception:
        return False


def check_proof_of_work(msg_to_verify, pow0es, pow_iterations):
    # type: (bytes, int, int) -> bool
    h = SHA256.new(msg_to_verify)
    for i in range(0, pow_iterations - 1):
        h.update(h.hexdigest().encode("ascii"))

    if re.search(b"^" + b"0" * pow0es, h.hexdigest().encode("ascii")):
        return True
    else:
        return False
