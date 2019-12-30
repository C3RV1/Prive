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

        self.user = user[0]

        if passwd is not None:
            self.loginInit(passwd[0], register)
            return
        else:
            self.notLoginInit()

    def notLoginInit(self):
        self.loggedin = False

    def loginInit(self, passwd, register):
        self.loggedin = True

        if register is True:
            registerResult = self.priveConnection.createUser(self.user, passwd)
            if registerResult["errorCode"] != "successful":
                print "Error registering"
                print "Error {}".format(registerResult["msg"])
            else:
                print "User registered correctly"
            self.priveConnection.close()
            sys.exit(0)

        loginResult = self.priveConnection.login(self.user, passwd)
        if loginResult["errorCode"] != "successful":
            print "Error logging in"
            print "Error {}".format(loginResult["msg"])
            self.priveConnection.close()
            sys.exit(0)

    def uploadPublic(self, path):
        if not self.loggedin:
            print "Error: You need to be logged in to upload files"
            print "Specify a password to login and upload files"
            self.priveConnection.close()
            sys.exit(0)

        if not os.path.isfile(path):
            print "File not found"
            sys.exit(0)
        f = open(path, "rb")
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
        if not self.loggedin:
            print "Error: You need to be logged in to upload files"
            print "Specify a password to login and upload files"
            self.priveConnection.close()
            sys.exit(0)

        if not os.path.isfile(path):
            print "File not found"
            sys.exit(0)
        f = open(path, "rb")
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
        if not self.loggedin:
            print "Error: You need to be logged in to upload files"
            print "Specify a password to login and upload files"
            self.priveConnection.close()
            sys.exit(0)

        if not os.path.isfile(path):
            print "File not found"
            sys.exit(0)
        f = open(path, "rb")
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

    def download(self, id, outputPath):
        fileList = self.priveConnection.getFiles(self.user)
        if fileList["errorCode"] != "successful":
            print "Error getting file list"
            print "Error: {} ({})".format(fileList["msg"], fileList["errorCode"])
            self.priveConnection.close()
            sys.exit(0)

        del fileList["errorCode"]

        if not id in fileList.keys():
            print "File not found"
            self.priveConnection.close()
            sys.exit(0)

        getFileRequest = self.priveConnection.getFile(fileList[id], user=self.user)
        if getFileRequest["errorCode"] != "successful":
            print "Error downloading file"
            print "Error: {} ({})".format(getFileRequest["msg"], getFileRequest["errorCode"])
            self.priveConnection.close()
            sys.exit(0)

        if outputPath is None:
            print getFileRequest["file"]
            self.priveConnection.close()
            sys.exit(0)

        outputPath = outputPath[0]

        if os.path.isfile(outputPath):
            print "File {} already exists".format(outputPath)
            self.priveConnection.close()
            sys.exit(0)

        outputFile = open(outputPath, "wb")
        outputFile.write(getFileRequest["file"])
        outputFile.close()
        print "Saved successfully"
        self.priveConnection.close()
        sys.exit(0)

    def delete(self, id, quiet):
        if not self.loggedin:
            print "Error: You need to be logged in to delete files"
            print "Specify a password to login and delete files"
            self.priveConnection.close()
            sys.exit(0)

        fileList = self.priveConnection.getFiles(self.user)
        if fileList["errorCode"] != "successful":
            print "Error getting file list"
            print "Error: {} ({})".format(fileList["msg"], fileList["errorCode"])
            self.priveConnection.close()
            sys.exit(0)

        del fileList["errorCode"]

        if not id in fileList.keys():
            print "File not found"
            self.priveConnection.close()
            sys.exit(0)

        if not quiet:
            areYouSure = raw_input("Are you sure you want to delete this file? (s/N): ")
            if areYouSure.lower() != "s":
                print "Aborting operation"
                self.priveConnection.close()
                sys.exit(0)
            print "Deletion confirmed"

        deleteFileRequest = self.priveConnection.deleteFile(fileList[id])
        if deleteFileRequest["errorCode"] != "successful":
            print "Error deleting file"
            print "Error: {} ({})".format(deleteFileRequest["msg"], deleteFileRequest["errorCode"])
            self.priveConnection.close()
            sys.exit(0)

        print "File deleted successfully"
        self.priveConnection.close()
        sys.exit(0)

    def list(self):
        queryResult = self.priveConnection.getFiles(self.user)
        if queryResult["errorCode"] != "successful":
            print "Error getting file list"
            print "Error: {} ({})".format(queryResult["msg"], queryResult["errorCode"])
            self.priveConnection.close()
            sys.exit(0)

        del queryResult["errorCode"]

        nameHeader = "Name" + " "*20
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

    def newPasswd(self, new_passwd):
        if not self.loggedin:
            print "Error: You need to be logged in to change the password of a user"
            print "Specify a password to login and change the password of a user"
            self.priveConnection.close()
            sys.exit(0)

        updateKeysResult = self.priveConnection.updateKeys(new_passwd)

        if updateKeysResult["errorCode"] != "successful":
            print "Error updating password"
            print "Error: {} ({})".format(updateKeysResult["msg"], updateKeysResult["errorCode"])
            self.priveConnection.close()
            sys.exit(0)

        print "Password updated successfully"
        self.priveConnection.close()
        sys.exit(0)

    def deleteUser(self, quiet):
        if not self.loggedin:
            print "Error: You need to be logged in to change the delete a user"
            print "Specify a password to login and change the delete a user"
            self.priveConnection.close()
            sys.exit(0)

        if not quiet:
            areYouSure = raw_input("Are you sure you want to delete the user {}? (s/N)".format(self.user))
            if areYouSure.lower() != "s":
                print "Aborting operation"
                self.priveConnection.close()
                sys.exit(0)

        deleteUserRequest = self.priveConnection.deleteUser()
        if deleteUserRequest["errorCode"] != "successful":
            print "Error deleting user"
            print "Error: {} ({})".format(deleteUserRequest["msg"], deleteUserRequest["errorCode"])
            self.priveConnection.close()
            sys.exit(0)
        print "User deleted successfully"
        self.priveConnection.close()
        sys.exit(0)

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
parser.add_argument("--newpasswd", nargs=1, metavar="<new passwd>",
                    help="Changes the password of the user")
parser.add_argument("--deleteUser",
                    help="Deletes the user", action="store_true")
parser.add_argument("--register",
                    help="Registers the user", action="store_true")
parser.add_argument("-u", nargs=1,
                    help="User used for the action",
                    metavar="<user>")
parser.add_argument("-p", nargs=1,
                    help="Password to login with",
                    metavar="<passwd>")
parser.add_argument("-o", nargs=1,
                    help="Output file in which to save the downloaded file. If not specified, it will be printed on screen.",
                    metavar="<output file>")
parser.add_argument("-q",
                    help="Quiet mode. Doesn't ask for confirmation when doing a dangerous action. DANGEROUS",
                    action="store_true")

args, leftovers = parser.parse_known_args()

if args.u is None:
    print "Missing user argument"
    print "Use prvconnect.py -h to see a list of all possible arguments"
    sys.exit(0)
prvConnect = PRVConnect(args.u, args.p, args.pcf[0], args.register)
if args.uploadPublic is not None:
    prvConnect.uploadPublic(args.uploadPublic[0])
elif args.uploadHidden is not None:
    prvConnect.uploadHidden(args.uploadHidden[0])
elif args.uploadPrivate is not None:
    prvConnect.uploadPrivate(args.uploadPrivate[0])
elif args.download is not None:
    prvConnect.download(args.download[0], args.o)
elif args.delete is not None:
    prvConnect.delete(args.delete[0], args.q)
elif args.list is not False:
    prvConnect.list()
elif args.newpasswd is not None:
    prvConnect.newPasswd(args.newpasswd[0])
elif args.deleteUser is not False:
    prvConnect.deleteUser(args.q)
else:
    parser.print_help()
    prvConnect.priveConnection.close()
    sys.exit(0)
