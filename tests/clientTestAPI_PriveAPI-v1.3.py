from tests.guiTest import PriveAPI as PriveAPI
import PriveAPI_ErrorCodes as PriveAPI_eC
import math

def register(priveConnection):
    # type: (PriveAPI.PriveAPIInstance) -> None
    while True:
        userName = raw_input("User Name: ")
        password = raw_input("Password: ")
        createUsrRes = priveConnection.create_user(userName, password)
        if createUsrRes == PriveAPI_eC.create_user.userAlreadyExists:
            print "User Already Exists"
        elif createUsrRes == PriveAPI_eC.create_user.invalidNameCharacters:
            print "Name Contains Invalid Characters -> /\\:\"?*<>|."
        elif createUsrRes == PriveAPI_eC.create_user.successful:
            print "User Created Successfully"
            break
        else:
            print "Unhandled Error"
            break

def login(priveConnection):
    # type: (PriveAPI.PriveAPIInstance) -> None
    while True:
        userName = raw_input("User Name: ")
        password = raw_input("Password: ")
        loginResult = priveConnection.login(userName, password)
        if loginResult[0] == PriveAPI_eC.login.userNotFound:
            print "User Not Found"
        elif loginResult[0] == PriveAPI_eC.login.incorrectPassword:
            print "Incorrect Password"
        elif loginResult[0] == PriveAPI_eC.login.accountLocked:
            print "Account Locked. Wait {0} seconds before trying again".format(math.ceil(loginResult[1]))
        elif loginResult[0] == PriveAPI_eC.login.successful:
            print "Logged In Successfully"
            break
        else:
            print "Unhandled Error"
            break
        continueTrying = raw_input("Exit Login (Yes, no): ")

        if not (continueTrying == "no" or continueTrying == "n"):
            break

def menu(priveConnection):
    # type: (PriveAPI.PriveAPIInstance) -> None
    while True:
        if priveConnection.logged_in is True:
            print "Logged in as {0}".format(priveConnection.logged_in_user)
        print "1. Register"
        print "2. Login"
        if priveConnection.logged_in is True:
            print "3. Delete User"
            print "4. Logout"
            print "5. Update Keys"
            print "6. Exit"
        else:
            print "3. Exit"
        option = input("Option: ")
        if option == 1:
            register(priveConnection)
        elif option == 2:
            login(priveConnection)
        elif option == 3:
            if priveConnection.logged_in is True:
                are_you_sure = raw_input("Are you sure? [y/N]")
                if are_you_sure == "y" or are_you_sure == "Y":
                    opResult = priveConnection.delete_user()
                    if opResult == PriveAPI_eC.delete_user.successful:
                        print "User deleted successfully"
                    else:
                        print "Error deleting user"
                        print "Error Code: {0}".format(opResult)
            else:
                break
        elif option == 4 and priveConnection.logged_in is True:
            priveConnection.logout()
        elif option == 5 and priveConnection.logged_in is True:
            print "Updating Keys..."
            result = priveConnection.update_keys()
            if result == PriveAPI_eC.update_keys.successful:
                print "Keys Updated Sucessfully"
            else:
                print "Error updating keys"
                print "Error Code: {0}".format(result)
        elif option == 6 and priveConnection.logged_in is True:
            break
        else:
            print "Option not accepted"


if __name__ == "__main__":
    priveConnection = PriveAPI.PriveAPIInstance("127.0.0.1", serverPublicKeyFile="serverPublicKey.pk", keySize=2048)
    menu(priveConnection)
    priveConnection.close()
