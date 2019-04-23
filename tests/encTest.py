from Crypto.PublicKey import RSA
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto.Random import random
import binascii
import base64
import re

def nothing():
    key = RSA.generate(2048)
    #exportedPublicKey = ""
    #exportedPublicKey += "-----BEGIN PUBLIC KEY-----\n"
    #exportedPublicKey += "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAl8B65k97I4CpWmm1+xOE\n"
    #exportedPublicKey += "uf9GH9jfDvrcChoZk4H0RvT0KECyIw5VPbmCaFIznDMXPLnUEPFPK4AzZudcjL6N\n"
    #exportedPublicKey += "eePV70zhgxCA/nK6Fheb3Ff8RIUUdLxA62yrGN8OBAtu5CjJ9xtT/wr5Wh5YjiMK\n"
    #exportedPublicKey += "QsnXTraLZHvrQvsmS8TKVjFJxgVrpPCEOS1Y7bzdsDwINxVeqLy+GsZBzwmO/HD1\n"
    #exportedPublicKey += "S1fPjBIEMLtgir86SRLDap+Ijfon86Kl3tWnczLlDOIU8vYgtDO4d4j7+JleeDrK\n"
    #exportedPublicKey += "HFrrOVh2HkRQqt7u1+HdOAogxxzD6Y0Q4Pg6jSLs5DXOS8iwaOktpTOB35LAlDC0\n"
    #exportedPublicKey += "2wIDAQAB\n"
    #exportedPublicKey += "-----END PUBLIC KEY-----\n"
    #exportedPrivateKey = ""
    ##exportedPrivateKey += "-----BEGIN RSA PRIVATE KEY-----"
    #exportedPrivateKey += "MIIEpAIBAAKCAQEAl8B65k97I4CpWmm1+xOEuf9GH9jfDvrcChoZk4H0RvT0KECy"
    #exportedPrivateKey += "Iw5VPbmCaFIznDMXPLnUEPFPK4AzZudcjL6NeePV70zhgxCA/nK6Fheb3Ff8RIUU"
    #exportedPrivateKey += "dLxA62yrGN8OBAtu5CjJ9xtT/wr5Wh5YjiMKQsnXTraLZHvrQvsmS8TKVjFJxgVr"
    #exportedPrivateKey += "pPCEOS1Y7bzdsDwINxVeqLy+GsZBzwmO/HD1S1fPjBIEMLtgir86SRLDap+Ijfon"
    #exportedPrivateKey += "86Kl3tWnczLlDOIU8vYgtDO4d4j7+JleeDrKHFrrOVh2HkRQqt7u1+HdOAogxxzD"
    #exportedPrivateKey += "6Y0Q4Pg6jSLs5DXOS8iwaOktpTOB35LAlDC02wIDAQABAoIBAQCLI6cMKPAk+0FM"
    #exportedPrivateKey += "bwS2s4zM5aysYrMTDxxV/txYjZ0muk5r4fXzgp7Ru5hAgq5jl8zElzZEWp1Wq3N1"
    #exportedPrivateKey += "9Mi9G7KogiiUA4/6FlXP9+17eCYmgF4DjWnWJw33TmoKoeo99yWz+VpFQj9f5/X9"
    #exportedPrivateKey += "lTlpCePMnTjXKTTh62UowxK4AjXrlFev5P6qR1ctYP3fZEZwDJsGxfpzfW+BQyax"
    #exportedPrivateKey += "yrgRRepeRAb88bEgBZo1s9GnOoWtnOJJxoRG+TcW4mAmPt85Z2P+pz44pYpw0lDG"
    #exportedPrivateKey += "W8KoQ+bsU9or79sE+VrQxJ7xNz2V05/+50GwzKvKWpsOmG4GJEHXKHmWNOWtP4xO"
    #exportedPrivateKey += "cI/kHLOBAoGBALqo4ZT0Om4z/OWAvrnfp6UMGYeh83xiJmdkBnIvCaD4SX9g2D/G"
    #exportedPrivateKey += "kmQpuZamCbB2Q03JpK3tOxqP8mpAahpKfe/BKz8wkOuqCytcXVTkWzARdN3Pwffb"
    #exportedPrivateKey += "woJcWlS43dPjv2y1AO301QvfxSY+u99JJgwh1bgYv0JY+Z7/KAzAxsI7AoGBANAf"
    #exportedPrivateKey += "6AFDFfhZQJeNH4QAfHuObm155jjszS7GpzgNFhiRq/jc9iOqyz3jUXU0MwitnJpO"
    #exportedPrivateKey += "GWpBcg7qixtIr7OFylfmbnRq4n66Mp08rJtLx1ax9TMmn+4N7wPDnkrwuzmTnIS8"
    #exportedPrivateKey += "oA4fiHa9vZm3SMKLtNGUfR55Slcf7lp6zAgDuQ3hAoGAW9sd38psMq08x8gak6ff"
    #exportedPrivateKey += "fRY+PgPRqaU3VuvfTDOfnmpw6NFEueXDRq1N2jftTrx0FISlmL3EtyadWfJHBJch"
    #exportedPrivateKey += "8Gl0Gc2Rk5eDlZwHhe42faopg7porsujpblC7qxm5Y4PNrTAN1mjugstnsuCcrgx"
    #exportedPrivateKey += "lAjWfpkXDdRxSvAvyk7XwN8CgYEAslSUe/haq+j2EqWGepncEBa0AjQwE1i8Wzc2"
    #exportedPrivateKey += "cy2rYDP5sgzLDza6XXYZBx9KF0aDaChBWK1pKOTJewBmJKIgBf9ZZ4FqP4IV+mrR"
    #exportedPrivateKey += "z2M4E836NvECmnzv7z6/tKDfG++ibo4datyUFoJwInVM7/27WtUr/F+bVlny5y5P"
    #exportedPrivateKey += "AxMFjqECgYBILmQ0LeXmga69OUvYDmqo1O1MmxmIFUmslAe5wixOrvQPTFVQH00h"
    #exportedPrivateKey += "ir0RZT0rmAHI6zp6ew0p5XWs9wCtgxPrQa42M4GT2aZeW/38lc6bruHxEFaw3ooZ"
    #exportedPrivateKey += "0ko0n27KD4ckr/vmRvPQnHrfqxG5u96nN48ilapEyGS5cGcbUVAMZw=="
    # exportedPrivateKey += "-----END RSA PRIVATE KEY-----"
    # print exportedPublicKey
    # print exportedPrivateKey
    # exportedPrivateKey_notb64 = base64.b64decode(exportedPrivateKey)
    # exportedAES = XOR.new(SHA256.new("alex0605").digest()).encrypt(exportedPrivateKey_notb64)
    # exportedAES_b64 = base64.b64encode(exportedAES)
    # exportedAES_formatted = "-----BEGIN RSA PRIVATE KEY-----\n"
    # exportedAES_formatted += re.sub("(.{64})", "\\1\r\n", exportedAES_b64, 0, re.DOTALL)
    # exportedAES_formatted += "-----END RSA PRIVATE KEY-----\n"
    # newRSA = RSA.importKey(exportedAES_formatted)

    #vt = random.getrandbits(256)
    #vt = random.long_to_bytes(vt)
    #print repr(vt)
    #print type(vt)
    #pwd = "cervi0605"
    #pwdSalted = "priveSalt" + pwd
    #pwdHash = SHA256.new(pwdSalted).digest()
    #vtEncrypted = AES.new(pwdHash).encrypt(vt)

    print key.exportKey()


if __name__ == "__main__":
    #data = "sessionkey: asdasdg\r\n"
    #sessionKeyRe = re.search("sessionkey: (.*)\r\n", data)
    #print sessionKeyRe.group(1)
    #name = "testName"
    #nameHash = SHA256.new(name).digest()
    #print type(nameHash)
    nothing()

