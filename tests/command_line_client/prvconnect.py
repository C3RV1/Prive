import PriveAPI.PriveAPI as PriveAPI
import argparse
import os
import sys
import json
from math import *


def name_to_more_long(name, chars):
    if len(name) <= chars - 3:
        return name
    else:
        return name[0:chars - 3] + "..."


def spaces_formatting(string, spaces):
    string = name_to_more_long(string, spaces)
    return string + " "*(spaces-len(string))


class PRVConnect:

    def __init__(self, user, passwd, pcf_path, register):
        # type: (str, str, str, str) -> None
        if not os.path.isfile(pcf_path):
            print("Prive configuration file not found (--pcf)")
            sys.exit(0)

        pcf_file = open(pcf_path, "r")
        pcf = pcf_file.read()
        pcf_file.close()

        try:
            config = json.loads(pcf)
        except:
            print("Error exporting prive configuration file (--pcf)")
            sys.exit(0)

        if "host" not in config.keys() or "rsa-key" not in config.keys():
            print("Missing keys in prive configuration file (--pcf)")
            sys.exit(0)

        if "key-size" not in config.keys():
            config["key-size"] = 2048

        if "port" not in config.keys():
            config["port"] = 4373

        if "pow-0es" not in config.keys():
            config["pow-0es"] = 5

        if "pow-iterations" not in config.keys():
            config["pow-iterations"] = 2

        if "file-send-chunks" not in config.keys():
            config["file-send-chunks"] = 65536

        try:
            self.prive_connection = PriveAPI.PriveAPIInstance(config["host"], config["rsa-key"].encode("ascii"),
                                                              key_size=config["key-size"],
                                                              server_port=config["port"],
                                                              proof_of_work0es=config["pow-0es"],
                                                              proof_of_work_iterations=config["pow-iterations"],
                                                              file_chunks_to_send=config["file-send-chunks"])
            self.prive_connection.connect()
        except Exception as exc:
            print("Error stablishing connection (prive connection)")
            print("Error {}".format(exc))
            sys.exit(0)

        self.user = user[0].encode("ascii")
        self.logged_in = False

        if passwd is not None:
            self.login_init(passwd[0], register)
            return
        else:
            self.not_login_init()

    def not_login_init(self):
        self.logged_in = False

    def login_init(self, passwd, register):
        self.logged_in = True

        if register is True:
            registerResult = self.prive_connection.create_user(self.user, passwd)
            if registerResult[b"errorCode"] != b"successful":
                print("Error registering")
                print("Error {}".format(registerResult[b"msg"]))
            else:
                print("User registered correctly")
            self.prive_connection.close()
            sys.exit(0)

        loginResult = self.prive_connection.login(self.user, passwd)
        if loginResult[b"errorCode"] != b"successful":
            print("Error logging in")
            print("Error {}".format(loginResult[b"msg"]))
            self.prive_connection.close()
            sys.exit(0)

    def upload_public(self, path):
        if not self.logged_in:
            print("Error: You need to be logged in to upload files")
            print("Specify a password to login and upload files")
            self.prive_connection.close()
            sys.exit(0)

        if not os.path.isfile(path):
            print("File not found")
            self.prive_connection.close()
            sys.exit(0)

        result = self.prive_connection.add_file(os.path.basename(path).encode("ascii"), path, b"Public",
                                                progress_function=self.progress_function)
        if result[b"errorCode"] != b"successful":
            print("Error uploading file")
            print("Error: {} ({})".format(result[b"msg"], result[b"errorCode"]))
        else:
            print("File Uploaded Successfully")
        self.prive_connection.close()
        sys.exit(0)

    def upload_hidden(self, path):
        if not self.logged_in:
            print("Error: You need to be logged in to upload files")
            print("Specify a password to login and upload files")
            self.prive_connection.close()
            sys.exit(0)

        if not os.path.isfile(path):
            print("File not found")
            sys.exit(0)

        result = self.prive_connection.add_file(os.path.basename(path).encode("ascii"), path, b"Hidden",
                                                progress_function=self.progress_function)
        if result[b"errorCode"] != b"successful":
            print("Error uploading file")
            print("Error: {} ({})".format(result[b"msg"], result[b"errorCode"]))
        else:
            print("File Uploaded Successfully")
        self.prive_connection.close()
        sys.exit(0)

    def upload_private(self, path):
        if not self.logged_in:
            print("Error: You need to be logged in to upload files")
            print("Specify a password to login and upload files")
            self.prive_connection.close()
            sys.exit(0)

        if not os.path.isfile(path):
            print("File not found")
            sys.exit(0)

        result = self.prive_connection.add_file(os.path.basename(path).encode("ascii"), path, b"Private",
                                                progress_function=self.progress_function)
        if result[b"errorCode"] != b"successful":
            print("Error uploading file")
            print("Error: {} ({})".format(result[b"msg"], result[b"errorCode"]))
        else:
            print("File Uploaded Successfully")
        self.prive_connection.close()
        sys.exit(0)

    def download(self, file_id, output_path):
        file_list = self.prive_connection.get_files(self.user)
        if file_list[b"errorCode"] != b"successful":
            print("Error getting file list")
            print("Error: {} ({})".format(file_list[b"msg"], file_list[b"errorCode"]))
            self.prive_connection.close()
            sys.exit(0)

        del file_list[b"errorCode"]

        if output_path is None:
            print("Output path not specified")
            self.prive_connection.close()
            sys.exit(0)

        output_path = output_path[0]

        if os.path.isfile(output_path):
            print("File {} already exists".format(output_path))
            self.prive_connection.close()
            sys.exit(0)

        if file_id not in file_list:
            file_list[file_id] = {}
            file_list[file_id][b"id"] = file_id
            file_list[file_id][b"visibility"] = b"Hidden"

        getFileRequest = self.prive_connection.get_file(file_id, file_list[file_id][b"visibility"], output_path,
                                                        user=self.user,
                                                        progress_function=self.progress_function)
        if getFileRequest[b"errorCode"] != b"successful":
            print("Error downloading file")
            print("Error: {} ({})".format(getFileRequest[b"msg"], getFileRequest[b"errorCode"]))
            self.prive_connection.close()
            sys.exit(0)

        print("Saved successfully")
        self.prive_connection.close()
        sys.exit(0)

    def delete(self, file_id, quiet):
        if not self.logged_in:
            print("Error: You need to be logged in to delete files")
            print("Specify a password to login and delete files")
            self.prive_connection.close()
            sys.exit(0)

        file_list = self.prive_connection.get_files(self.user)
        if file_list[b"errorCode"] != b"successful":
            print("Error getting file list")
            print("Error: {} ({})".format(file_list[b"msg"], file_list[b"errorCode"]))
            self.prive_connection.close()
            sys.exit(0)

        del file_list[b"errorCode"]

        file_id = file_id.encode("ascii")

        if file_id not in file_list.keys():
            print("File not found")
            self.prive_connection.close()
            sys.exit(0)

        if not quiet:
            areYouSure = input("Are you sure you want to delete this file? (s/N): ")
            if areYouSure.lower() != "s":
                print("Aborting operation")
                self.prive_connection.close()
                sys.exit(0)
            print("Deletion confirmed")

        deleteFileRequest = self.prive_connection.delete_file(file_id)
        if deleteFileRequest[b"errorCode"] != b"successful":
            print("Error deleting file")
            print("Error: {} ({})".format(deleteFileRequest[b"msg"], deleteFileRequest[b"errorCode"]))
            self.prive_connection.close()
            sys.exit(0)

        print("File deleted successfully")
        self.prive_connection.close()
        sys.exit(0)

    def list(self):
        query_result = self.prive_connection.get_files(self.user)
        if query_result[b"errorCode"] != b"successful":
            print("Error getting file list")
            print("Error: {} ({})".format(query_result[b"msg"], query_result[b"errorCode"]))
            self.prive_connection.close()
            sys.exit(0)

        del query_result[b"errorCode"]

        name_header = "Name" + " "*20
        visibility_header = "Visibility "
        size_header = "Size (KB)" + " "*8
        id_header = "ID"
        print(name_header + size_header + visibility_header + id_header)

        for key in query_result:
            name = query_result[key][b"name"].decode("ascii")
            visibility = query_result[key][b"visibility"].decode("ascii")
            size = query_result[key][b"size"]/1000.0
            fileid = query_result[key][b"id"].decode("ascii")

            name_formatted = spaces_formatting(name, len(name_header))
            size_formatted = spaces_formatting(str(size), len(size_header))
            visibility_formatted = spaces_formatting(visibility, len(visibility_header))

            print(name_formatted + size_formatted + visibility_formatted + fileid)

        self.prive_connection.close()
        sys.exit(0)

    def new_passwd(self, new_passwd):
        if not self.logged_in:
            print("Error: You need to be logged in to change the password of a user")
            print("Specify a password to login and change the password of a user")
            self.prive_connection.close()
            sys.exit(0)

        update_keys_result = self.prive_connection.update_keys(new_passwd)

        if update_keys_result[b"errorCode"] != b"successful":
            print("Error updating password")
            print("Error: {} ({})".format(update_keys_result[b"msg"], update_keys_result[b"errorCode"]))
            self.prive_connection.close()
            sys.exit(0)

        print("Password updated successfully")
        self.prive_connection.close()
        sys.exit(0)

    def delete_user(self, quiet):
        if not self.logged_in:
            print("Error: You need to be logged in to delete a user")
            print("Specify a password to login and delete a user")
            self.prive_connection.close()
            sys.exit(0)

        if not quiet:
            areYouSure = input("Are you sure you want to delete the user {}? (s/N)".format(self.user))
            if areYouSure.lower() != "s":
                print("Aborting operation")
                self.prive_connection.close()
                sys.exit(0)

        deleteUserRequest = self.prive_connection.delete_user()
        if deleteUserRequest[b"errorCode"] != b"successful":
            print("Error deleting user")
            print("Error: {} ({})".format(deleteUserRequest[b"msg"], deleteUserRequest[b"errorCode"]))
            self.prive_connection.close()
            sys.exit(0)
        print("User deleted successfully")
        self.prive_connection.close()
        sys.exit(0)

    @staticmethod
    def progress_function(current_value, max_value, function):
        progressPercentage = float(current_value) / float(max_value)
        characters = 50
        blockCharacters = chr(219)*int(round(progressPercentage*characters))
        dashCharacters = "-"*(50-int(round(progressPercentage*characters)))
        if function == 0:
            sys.stdout.write("Uploading:   {}{} {:.2f}% {:.2f}KB / {:.2f}KB\r".format(blockCharacters,
                                                                                      dashCharacters,
                                                                                      progressPercentage * 100,
                                                                                      current_value / 1000,
                                                                                      max_value / 1000))
            if progressPercentage >= 1:
                sys.stdout.write("\n")
        elif function == 1:
            sys.stdout.write("Encrypting:  {}{} {:.2f}% {:.2f}KB / {:.2f}KB\r".format(blockCharacters,
                                                                                      dashCharacters,
                                                                                      progressPercentage * 100,
                                                                                      current_value / 1000,
                                                                                      max_value / 1000))
            if progressPercentage >= 1:
                sys.stdout.write("\n")
        elif function == 2:
            sys.stdout.write("Downloading: {}{} {:.2f}% {:.2f}KB / {:.2f}KB\r".format(blockCharacters,
                                                                                      dashCharacters,
                                                                                      progressPercentage * 100,
                                                                                      current_value / 1000,
                                                                                      max_value / 1000))
            if progressPercentage >= 1:
                sys.stdout.write("\n")
        elif function == 3:
            sys.stdout.write("Decrypting:  {}{} {:.2f}% {:.2f}KB / {:.2f}KB\r".format(blockCharacters,
                                                                                      dashCharacters,
                                                                                      progressPercentage * 100,
                                                                                      current_value / 1000,
                                                                                      max_value / 1000))
            if progressPercentage >= 1:
                sys.stdout.write("\n")


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
                    help="Output file in which to save the downloaded file." +
                         "If not specified, it will be printed on screen.",
                    metavar="<output file>")
parser.add_argument("-q",
                    help="Quiet mode. Doesn't ask for confirmation when doing a dangerous action. DANGEROUS",
                    action="store_true")

args, leftovers = parser.parse_known_args()

if args.u is None:
    print("Missing user argument")
    print("Use prvconnect.py -h to see a list of all possible arguments")
    sys.exit(0)
prv_connect = PRVConnect(args.u, args.p, args.pcf[0], args.register)
if args.uploadPublic is not None:
    prv_connect.upload_public(args.uploadPublic[0])
elif args.uploadHidden is not None:
    prv_connect.upload_hidden(args.uploadHidden[0])
elif args.uploadPrivate is not None:
    prv_connect.upload_private(args.uploadPrivate[0])
elif args.download is not None:
    prv_connect.download(args.download[0], args.o)
elif args.delete is not None:
    prv_connect.delete(args.delete[0], args.q)
elif args.list is not False:
    prv_connect.list()
elif args.newpasswd is not None:
    prv_connect.new_passwd(args.newpasswd[0])
elif args.deleteUser is not False:
    prv_connect.delete_user(args.q)
else:
    parser.print_help()
    prv_connect.prive_connection.close()
    sys.exit(0)
