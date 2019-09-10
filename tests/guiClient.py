from Tkinter import *
import PriveAPI

class ValidatingEntry(Entry):
    # base class for validating entry widgets

    def __init__(self, master, value="", **kw):
        apply(Entry.__init__, (self, master), kw)
        self.__value = value
        self.__variable = StringVar()
        self.__variable.set(value)
        self.__variable.trace("w", self.__callback)
        self.config(textvariable=self.__variable)

    def __callback(self, *dummy):
        value = self.__variable.get()
        newvalue = self.validate(value)
        if newvalue is None:
            self.__variable.set(self.__value)
        elif newvalue != value:
            self.__value = newvalue
            self.__variable.set(self.newvalue)
        else:
            self.__value = value

    def validate(self, value):
        # override: return value, new value, or None if invalid
        return value

class MaxLengthEntry(ValidatingEntry):

    def __init__(self, master, value="", maxlength=None, **kw):
        self.maxlength = maxlength
        apply(ValidatingEntry.__init__, (self, master), kw)

    def validate(self, value):
        if self.maxlength is None or len(value) <= self.maxlength:
            return value
        return None # new value too long

class App:
    def __init__(self):
        self.priveConnection = PriveAPI.PriveAPIInstance("127.0.0.1")

        self.frames = {}
        self.loginFrameWidgets = {}
        self.loggedInFrameWidgets = {}

        self.mainWindowGeometries = {"loginFrame": "400x200",
                                     "loggedInFrame": "400x200"}

    def run(self):
        self.mainWindow = Tk()

        self.mainWindow.geometry("400x200")

        self.mainWindow.protocol("WM_DELETE_WINDOW", self.onClose)

        self.loggedInFrame()

        self.loginFrame()

        self.setActiveFrame("loginFrame")

        self.mainWindow.mainloop()

    def setActiveFrame(self, keyToActivate):
        if keyToActivate not in self.frames.keys():
            raise KeyError

        for key in self.frames.keys():
            self.frames[key].place_forget()
            self.frames[key].grid_forget()

        self.frames[keyToActivate].place(relx=0.5, rely=0.5, anchor="center")
        self.mainWindow.geometry(self.mainWindowGeometries[keyToActivate])

    def loginFrame(self):
        self.frames["loginFrame"] = Frame(self.mainWindow)
        self.frames["loginFrame"].place(relx=0.5, rely=0.5, anchor="center")

        self.loginFrameWidgets["welcomeText"] = Label(self.frames["loginFrame"], text="Welcome to Prive File Upload",
                                                      font=("Arial", 16), fg="blue")
        self.loginFrameWidgets["welcomeText"].pack()

        blankLine = Label(self.frames["loginFrame"], text="", font=("Arial", 8))
        blankLine.pack()

        self.loginFrameWidgets["loginButton"] = Button(self.frames["loginFrame"], text="Sign in", font=("Arial", 16),
                                                       command=self.login)
        self.loginFrameWidgets["loginButton"].pack()

        self.loginFrameWidgets["registerButton"] = Button(self.frames["loginFrame"], text="Register", font=("Arial", 16),
                                                          command=self.register)
        self.loginFrameWidgets["registerButton"].pack()
        self.frames["loginFrame"].place_forget()

    def loggedInFrame(self):
        self.frames["loggedInFrame"] = Frame(self.mainWindow)
        self.frames["loggedInFrame"].place(relx=0.5, rely=0.5, anchor="center")

        self.loggedInFrameWidgets["loggedInText"] = Label(self.frames["loggedInFrame"], text="Logged in as User",
                                                          font=("Arial", 16), fg="blue")
        self.loggedInFrameWidgets["loggedInText"].grid(row=0, column=0, columnspan=3)

        blankLine = Label(self.frames["loggedInFrame"], text="", font=("Arial", 8))
        blankLine.grid(row=1, column=0)

        self.loggedInFrameWidgets["uploadFileButton"] = Button(self.frames["loggedInFrame"], text="Upload file",
                                                               font=("Arial", 16))
        self.loggedInFrameWidgets["uploadFileButton"].grid(row=2, column=0)

        self.loggedInFrameWidgets["downloadFileButton"] = Button(self.frames["loggedInFrame"], text="Download file",
                                                                 font=("Arial", 16))
        self.loggedInFrameWidgets["downloadFileButton"].grid(row=2, column=1)

        self.loggedInFrameWidgets["deleteFileButton"] = Button(self.frames["loggedInFrame"], text="Delete file",
                                                               font=("Arial", 16))
        self.loggedInFrameWidgets["deleteFileButton"].grid(row=3, column=0)

        self.loggedInFrameWidgets["settingButton"] = Button(self.frames["loggedInFrame"], text="Settings",
                                                            font=("Arial", 16))
        self.loggedInFrameWidgets["settingButton"].grid(row=3, column=1)

        self.loggedInFrameWidgets["logoutButton"] = Button(self.frames["loggedInFrame"], text="Logout",
                                                           font=("Arial", 16), command=self.logout, width=20)
        self.loggedInFrameWidgets["logoutButton"].grid(row=4, column=0, columnspan=2)
        self.frames["loggedInFrame"].place_forget()

    def login(self):
        loginToplevel = Toplevel(self.mainWindow)
        loginToplevel.grab_set()
        loginToplevel.title("Sign in")
        loginToplevel.geometry("250x150")

        usernameLabel = Label(loginToplevel, text="Username: ", font=("Arial", 14))
        usernameLabel.grid(row=0, column=0)
        usernameEntry = Entry(loginToplevel)
        usernameEntry.grid(row=0, column=1)

        passwordLabel = Label(loginToplevel, text="Password: ", font=("Arial", 14))
        passwordLabel.grid(row=1, column=0)
        passwordEntry = Entry(loginToplevel)
        passwordEntry.grid(row=1, column=1)

        submitButton = Button(loginToplevel, text="Submit", font=("Arial", 14), fg="blue",
                              command=lambda: self.doLogin(loginToplevel, usernameEntry, passwordEntry, errorLabel))
        submitButton.grid(row=2, column=1)

        errorLabel = Label(loginToplevel, text="", font=("Arial", 10))
        errorLabel.grid(row=3, column=0, columnspan=3)

    def register(self):
        registerTopLevel = Toplevel(self.mainWindow)
        registerTopLevel.grab_set()
        registerTopLevel.title("Register")
        registerTopLevel.geometry("300x150")

        usernameLabel = Label(registerTopLevel, text="Username: ", font=("Arial", 14))
        usernameLabel.grid(row=0, column=0)
        usernameEntry = Entry(registerTopLevel)
        usernameEntry.grid(row=0, column=1)

        passwordLabel = Label(registerTopLevel, text="Password: ", font=("Arial", 14))
        passwordLabel.grid(row=1, column=0)
        passwordEntry = MaxLengthEntry(registerTopLevel, maxlength=16)
        passwordEntry.grid(row=1, column=1)

        confirmPasswordLabel = Label(registerTopLevel, text="Confirm password: ", font=("Arial", 14))
        confirmPasswordLabel.grid(row=2, column=0)
        confirmPasswordEntry = MaxLengthEntry(registerTopLevel, maxlength=16)
        confirmPasswordEntry.grid(row=2, column=1)

        submitButton = Button(registerTopLevel, text="Submit", font=("Arial", 14), fg="blue",
                              command=lambda: self.doRegister(registerTopLevel, usernameEntry, passwordEntry,
                                                              confirmPasswordEntry, errorLabel))
        submitButton.grid(row=3, column=1)

        errorLabel = Label(registerTopLevel, text="", font=("Arial", 10))
        errorLabel.grid(row=4, column=0, columnspan=3)

    def doLogin(self, loginTopLevel, usernameEntry, passwordEntry, errorLabel):
        # type: (Toplevel, Entry, Entry, Label) -> None
        queryResult = self.priveConnection.login(usernameEntry.get(), passwordEntry.get())
        if queryResult["errorCode"] == "successful" and self.priveConnection.loggedIn:
            loginTopLevel.destroy()
            self.loggedInFrameWidgets["loggedInText"].config(text="Logged in as " + self.priveConnection.loggedInUser)
            self.setActiveFrame("loggedInFrame")
        else:
            errorLabel.config(text="Error: {}".format(queryResult["msg"]), fg="red")

    def doRegister(self, registerToplevel, usernameEntry, passwordEntry, confirmPasswordEntry, errorLabel):
        if passwordEntry.get() != confirmPasswordEntry.get():
            errorLabel.config(text="Error: Password doesn't match", fg="red")
            return
        queryResult = self.priveConnection.createUser(usernameEntry.get(), passwordEntry.get())
        if queryResult["errorCode"] == "successful":
            errorLabel.config(text="Register successful", fg="green")
        else:
            errorLabel.config(text="Error: {}".format(queryResult["msg"]), fg="red")

    def logout(self):
        self.priveConnection.logout()
        self.setActiveFrame("loginFrame")

    def onClose(self):
        self.priveConnection.close()
        self.mainWindow.destroy()

if __name__ == "__main__":
    appInstance = App()
    appInstance.run()
