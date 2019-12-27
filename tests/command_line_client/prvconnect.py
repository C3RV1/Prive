import PriveAPI
import argparse
import os
import sys
import json

def nameToMoreLong(name, chars):
    if len(name) <= chars - 3:
        return name
    else:
        return name[0:chars - 3] + "..."

def spacesFormatting(string, spaces):
    string = nameToMoreLong(string, spaces)
    return string + " "*(spaces-len(string))

class PRVConnect:
    def __init__(self, user, passwd, pcfpath, register):
        if not os.path.isfile(pcfpath):
            print "Prive configuration file not found (--pcf)"
            sys.exit(0)

        pcfFile = open(pcfpath, "r")
        pcf = pcfFile.read()
        pcfFile.close()

        try:
            config = json.loads(pcf)
        except:
            print "Error exporting prive configuration file (--pcf)"
            sys.exit(0)

        if not "host" in config.keys() or not "rsa-key" in config.keys():
            print "Missing keys in prive configuration file (--pcf)"
            sys.exit(0)

        if not "key-size" in config.keys():
            config["key-size"] = 2048

        if not "port" in config.keys():
            config["port"] = 4373

        try:
            self.priveConnection = PriveAPI.PriveAPIInstance(config["host"], config["rsa-key"],
                                                             keySize=config["key-size"],
                                                             serverPort=config["port"])
        except Exception as e:
            print "Error stablishing connection (prive connection)"
            print "Error {}".format(e.message)
            sys.exit(0)

        if register is True:
            registerResult = self.priveConnection.createUser(user, passwd)
            if registerResult["errorCode"] != "successful":
                print "Error registering"
                print "Error {}".format(registerResult["msg"])
            else:
                print "User registered correctly"
            self.priveConnection.close()
            sys.exit(0)

        loginResult = self.priveConnection.login(user, passwd)
        if loginResult["errorCode"] != "successful":
            print "Error logging in"
            print "Error {}".format(loginResult["msg"])
            self.priveConnection.close()
            sys.exit(0)

    def uploadPublic(self, path):
        if not os.path.isfile(path):
            print "File not found"
            sys.exit(0)
        f = open(path, "r")
        content = f.read()
        f.close()

        result = self.priveConnection.addFile(os.path.basename(path), content, "Public")
        if result["errorCode"] != "successful":
            print "Error uploading file"
            print "Error: {} ({})".format(result["msg"], result["errorCode"])
        else:
            print "File Uploaded Successfully"
        self.priveConnection.close()
        sys.exit(0)

    def uploadHidden(self, path):
        if not os.path.isfile(path):
            print "File not found"
            sys.exit(0)
        f = open(path, "r")
        content = f.read()
        f.close()

        result = self.priveConnection.addFile(os.path.basename(path), content, "Hidden")
        if result["errorCode"] != "successful":
            print "Error uploading file"
            print "Error: {} ({})".format(result["msg"], result["errorCode"])
        else:
            print "File Uploaded Successfully"
        self.priveConnection.close()
        sys.exit(0)

    def uploadPrivate(self, path):
        if not os.path.isfile(path):
            print "File not found"
            sys.exit(0)
        f = open(path, "r")
        content = f.read()
        f.close()

        result = self.priveConnection.addFile(os.path.basename(path), content, "Private")
        if result["errorCode"] != "successful":
            print "Error uploading file"
            print "Error: {} ({})".format(result["msg"], result["errorCode"])
        else:
            print "File Uploaded Successfully"
        self.priveConnection.close()
        sys.exit(0)

    def download(self, id):
        pass

    def delete(self, id):
        pass

    def list(self):
        queryResult = self.priveConnection.getFiles()
        if queryResult["errorCode"] != "successful":
            print "Error getting file list"
            print "Error: {} ({})".format(queryResult["msg"], queryResult["errorCode"])
            self.priveConnection.close()
            sys.exit(0)

        del queryResult["errorCode"]

        nameHeader = "Name" + " "*8
        visibilityHeader = "Visibility "
        sizeHeader = "Size (KB)" + " "*8
        idHeader = "ID"
        print nameHeader + sizeHeader + visibilityHeader + idHeader

        for key in queryResult:
            name = queryResult[key]["name"]
            visibility = queryResult[key]["visibility"]
            size = queryResult[key]["size"]/1000.0
            fileid = queryResult[key]["id"]

            nameFormated = spacesFormatting(name, len(nameHeader))
            sizeFormated = spacesFormatting(str(size), len(sizeHeader))
            visibilityFormated = spacesFormatting(visibility, len(visibilityHeader))

            print nameFormated + sizeFormated + visibilityFormated + fileid

        self.priveConnection.close()
        sys.exit(0)

    def listUser(self, user):
        pass

    def newPasswd(self, new_passwd):
        pass

    def deleteUser(self):
        pass

parser = argparse.ArgumentParser(description="Communicate with a Prive Server")
parser.add_argument("--pcf", nargs=1, default=["priveConfigFile.pcf"], metavar="<pcf path>",
                    help="Path of prive configuration file from server")
parser.add_argument("--uploadPublic", nargs=1, metavar="<file path>",
                    help="Uploads a public file")
parser.add_argument("--uploadHidden", nargs=1, metavar="<file path>",
                    help="Uploads a hidden file")
parser.add_argument("--uploadPrivate", nargs=1, metavar="<file path>",
                    help="Uploads a private file")
parser.add_argument("--download", nargs=1, metavar="<id>",
                    help="Downloads the file with the id <id>. Ids can be found using the --list argument")
parser.add_argument("--delete", nargs=1, metavar="<id>",
                    help="Deletes the file with the id <id>. Ids can be found using the --list argument")
parser.add_argument("--list",
                    help="List all files with its corresponding ids", action="store_true")
parser.add_argument("--listUser", nargs=1,
                    help="List files of a user")
parser.add_argument("--newpasswd", nargs=1, metavar="<new passwd>",
                    help="Changes the password of the user")
parser.add_argument("--deleteUser",
                    help="Deletes the user", action="store_true")
parser.add_argument("--register",
                    help="Registers the user", action="store_true")
parser.add_argument("user", nargs=1,
                    help="User to login with")
parser.add_argument("passwd", nargs=1,
                    help="Password to login with")

args, leftovers = parser.parse_known_args()

prvConnect = PRVConnect(args.user[0], args.passwd[0], args.pcf[0], args.register)
if args.uploadPublic is not None:
    prvConnect.uploadPublic(args.uploadPublic[0])
elif args.uploadHidden is not None:
    prvConnect.uploadHidden(args.uploadHidden[0])
elif args.uploadPrivate is not None:
    prvConnect.uploadPrivate(args.uploadPrivate[0])
elif args.download is not None:
    prvConnect.download(args.download[0])
elif args.delete is not None:
    prvConnect.delete(args.delete[0])
elif args.list is not False:
    prvConnect.list()
elif args.listUser is not None:
    prvConnect.listUser(args.listUser[0])
elif args.newpasswd is not None:
    prvConnect.newPasswd(args.newpasswd[0])
elif args.deleteUser is not False:
    prvConnect.deleteUser()
else:
    parser.print_help()
    prvConnect.priveConnection.close()
    sys.exit(0)
