import PriveAPI
import math

def register(priveConnection):
    # type: (PriveAPI.PriveAPIInstance) -> None
    while True:
        userName = raw_input("User Name: ")
        password = raw_input("Password: ")
        createUsrRes = priveConnection.createUser(userName, password)
        if createUsrRes == "usrAlreadyExists":
            print "User Already Exists"
        elif createUsrRes == "invalidName":
            print "Name Contains Invalid Characters -> /\\:\"?*<>|."
        elif createUsrRes == "successful":
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
        if loginResult[0] == "usrNotFound":
            print "User Not Found"
        elif loginResult[0] == "incorrect":
            print "Incorrect Password"
        elif loginResult[0] == "accountLocked":
            print "Account Locked. Wait {0} seconds before trying again".format(math.ceil(loginResult[1]))
        elif loginResult[0] == "successful":
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
        if priveConnection.loggedIn == True:
            print "Logged in as {0}".format(priveConnection.loggedInUser)
        print "1. Register"
        print "2. Login"
        print "3. Exit"
        option = input("Option: ")
        if option == 1:
            register(priveConnection)
        elif option == 2:
            login(priveConnection)
        elif option == 3:
            break
        else:
            print "Option not accepted"


if __name__ == "__main__":
    priveConnection = PriveAPI.PriveAPIInstance("127.0.0.1", serverPublicKeyFile="../serverPublicKey.pk")
    menu(priveConnection)
    priveConnection.close()