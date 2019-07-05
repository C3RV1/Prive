import PriveAPI.PriveAPI as PriveAPI
import PriveAPI.PriveAPI_ErrorCodes as PriveAPI_eC
import PriveAPI.PriveAPI_MainClass as PriveAPI_mC

class MainClass(PriveAPI_mC.MainClassBase):

    programName = "PriveMessager.Proto"

    def __init__(self):
        PriveAPI_mC.MainClassBase.__init__(self)
        self.priveConnection = PriveAPI.PriveAPIInstance("127.0.0.1", serverPublicKeyFile="serverPublicKey.pk", keySize=2048)
        self.menu()

    def menu(self):
        pass