from Tkinter import *
import ttk
import tkFileDialog
import PriveAPI.PriveAPI
import os
import json
from customTkinter import *


class App:
    def __init__(self):
        if not os.path.isfile("priveConfigFile.pcf"):
            sys.exit(1)

        clientConfigFile = open("priveConfigFile.pcf", "r")
        clientConfig = clientConfigFile.read()
        clientConfigFile.close()

        try:
            config = json.loads(clientConfig)
        except:
            sys.exit(2)

        if not "host" in config.keys() or not "rsa-key" in config.keys():
            sys.exit(3)

        if not "key-size" in config.keys():
            config["key-size"] = 2048

        if not "port" in config.keys():
            config["port"] = 4373

        try:
            self.priveConnection = PriveAPI.PriveAPIInstance(config["host"], config["rsa-key"], keySize=config["key-size"],
                                                             serverPort=config["port"])
        except:
            sys.exit(3)

        self.frames = {}
        self.loginFrameWidgets = {}
        self.loggedInFrameWidgets = {}

        self.mainWindowGeometries = {"loginFrame": "400x200",
                                     "loggedInFrame": "400x200"}

    def run(self):
        self.mainWindow = Tk(className="Prive File Upload")

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
                                                               font=("Arial", 16), command=self.uploadFile)
        self.loggedInFrameWidgets["uploadFileButton"].grid(row=2, column=0)

        self.loggedInFrameWidgets["downloadFileButton"] = Button(self.frames["loggedInFrame"], text="Download file",
                                                                 font=("Arial", 16), command=self.downloadFile)
        self.loggedInFrameWidgets["downloadFileButton"].grid(row=2, column=1)

        self.loggedInFrameWidgets["deleteFileButton"] = Button(self.frames["loggedInFrame"], text="Delete file",
                                                               font=("Arial", 16), command=self.deleteFile)
        self.loggedInFrameWidgets["deleteFileButton"].grid(row=3, column=0)

        self.loggedInFrameWidgets["settingButton"] = Button(self.frames["loggedInFrame"], text="Settings",
                                                            font=("Arial", 16), command=self.settings)
        self.loggedInFrameWidgets["settingButton"].grid(row=3, column=1)

        self.loggedInFrameWidgets["logoutButton"] = Button(self.frames["loggedInFrame"], text="Logout",
                                                           font=("Arial", 16), command=self.logout, width=20)
        self.loggedInFrameWidgets["logoutButton"].grid(row=4, column=0, columnspan=2)
        self.frames["loggedInFrame"].place_forget()

    def login(self):
        loginToplevel = Toplevel(self.mainWindow)
        loginToplevel.grab_set()
        loginToplevel.title("Sign in")
        loginToplevel.geometry("250x100")

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
        registerTopLevel.geometry("300x130")

        usernameLabel = Label(registerTopLevel, text="Username: ", font=("Arial", 14))
        usernameLabel.grid(row=0, column=0)
        usernameEntry = Entry(registerTopLevel)
        usernameEntry.grid(row=0, column=1)

        passwordLabel = Label(registerTopLevel, text="Password: ", font=("Arial", 14))
        passwordLabel.grid(row=1, column=0)
        passwordEntry = MaxLengthEntry(registerTopLevel, maxlength=31)
        passwordEntry.grid(row=1, column=1)

        confirmPasswordLabel = Label(registerTopLevel, text="Confirm password: ", font=("Arial", 14))
        confirmPasswordLabel.grid(row=2, column=0)
        confirmPasswordEntry = MaxLengthEntry(registerTopLevel, maxlength=31)
        confirmPasswordEntry.grid(row=2, column=1)

        submitButton = Button(registerTopLevel, text="Submit", font=("Arial", 14), fg="blue",
                              command=lambda: self.doRegister(registerTopLevel, usernameEntry, passwordEntry,
                                                              confirmPasswordEntry, errorLabel))
        submitButton.grid(row=3, column=1)

        errorLabel = Label(registerTopLevel, text="", font=("Arial", 10))
        errorLabel.grid(row=4, column=0, columnspan=3)

    def uploadFile(self):
        uploadFileToplevel = Toplevel(self.mainWindow)
        uploadFileToplevel.grab_set()
        uploadFileToplevel.title("Upload file")
        uploadFileToplevel.geometry("350x120")

        pathLabel = Label(uploadFileToplevel, text="Path: ", font=("Arial", 14))
        pathLabel.grid(row=0, column=0)
        pathEntry = Entry(uploadFileToplevel, font=("Arial", 14))
        pathEntry.grid(row=0, column=1)
        pathButton = Button(uploadFileToplevel, text="...", font=("Arial", 14),
                            command=lambda: self.setPathButton(pathEntry))
        pathButton.grid(row=0, column=2, sticky=W)

        visibilityMenu = ttk.Combobox(uploadFileToplevel, font=("Arial", 14), state="readonly",
                                      values=["Public", "Hidden", "Private"])
        visibilityMenu.current(0)
        visibilityMenu.grid(row=1, column=1)

        uploadButton = Button(uploadFileToplevel, text="Upload", font=("Arial", 14),
                              command=lambda: self.doUploadFile(uploadFileToplevel, visibilityMenu, pathEntry,
                                                                errorLabel))
        uploadButton.grid(row=2, column=1)

        errorLabel = Label(uploadFileToplevel, text="", font=("Arial", 12))
        errorLabel.grid(row=3, column=0, columnspan=4)

    def nameToMoreLong(self, name, chars):
        if len(name) <= chars-3:
            return name
        else:
            return name[0:chars-3] + "..."

    def downloadFile(self):
        downloadFileToplevel = Toplevel(self.mainWindow)
        downloadFileToplevel.grab_set()
        downloadFileToplevel.title("Download file")

        scrollableFileList = VerticalScrolledFrame(downloadFileToplevel)
        scrollableFileList.grid(row=0, column=0)

        nameLabel2 = Label(scrollableFileList.interior, text="Filename", font=("Arial", 11))
        nameLabel2.grid(row=0, column=0, sticky=W)
        sizeLabel2 = Label(scrollableFileList.interior, text="Size", font=("Arial", 11))
        sizeLabel2.grid(row=0, column=1, sticky=W)
        visibilityLabel2 = Label(scrollableFileList.interior, text="Visibility", font=("Arial", 11))
        visibilityLabel2.grid(row=0, column=2, sticky=W)

        queryResult = self.priveConnection.getFiles()
        if queryResult["errorCode"] != "successful":
            downloadFileToplevel.destroy()
            return

        del queryResult["errorCode"]
        currentRow = 1

        errorLabel = None

        sizes = 0

        for key in queryResult.keys():
            nameLabel = Label(scrollableFileList.interior, text=self.nameToMoreLong(queryResult[key]["name"], 30),
                              font=("Arial", 10))
            nameLabel.grid(row=currentRow, column=0, sticky=W)
            sizeLabel = Label(scrollableFileList.interior, text=(self.nameToMoreLong(str(queryResult[key]["size"]/1000),
                                                                                     9) + "KB"), font=("Arial", 10))
            sizeLabel.grid(row=currentRow, column=1, sticky=W)

            visibilityLabel = Label(scrollableFileList.interior,
                                    text=self.nameToMoreLong(queryResult[key]["visibility"], 10), font=("Arial", 10))
            visibilityLabel.grid(row=currentRow, column=2, sticky=W)

            downloadButton = Button(scrollableFileList.interior, text="Download",
                                    command=lambda key=key: self.doDownloadFile(queryResult[key]["id"],
                                                                        errorLabel, queryResult), font=("Arial", 10))
            downloadButton.grid(row=currentRow, column=3, sticky=W)
            currentRow += 1
            sizes += queryResult[key]["size"]

        downloadFileToplevel.geometry(str(int(scrollableFileList.canvas.winfo_reqwidth())) + "x" +
                                      str(int(scrollableFileList.canvas.winfo_reqheight()) + 60))

        sizeLabel = Label(downloadFileToplevel, text=(str(sizes/1000.0) + "KB"), font=("Arial", 10))
        sizeLabel.grid(row=1, column=0, columnspan=3)

        errorLabel = Label(downloadFileToplevel, text="", font=("Arial", 10))
        errorLabel.grid(row=2, column=0, columnspan=3)

    def deleteFile(self):
        deleteFileTopelevel = Toplevel(self.mainWindow)
        deleteFileTopelevel.grab_set()
        deleteFileTopelevel.title("Delete file")

        scrollableFileList = VerticalScrolledFrame(deleteFileTopelevel)
        scrollableFileList.grid(row=0, column=0)

        nameLabel2 = Label(scrollableFileList.interior, text="Filename", font=("Arial", 11))
        nameLabel2.grid(row=0, column=0, sticky=W)
        sizeLabel2 = Label(scrollableFileList.interior, text="Size", font=("Arial", 11))
        sizeLabel2.grid(row=0, column=1, sticky=W)
        visibilityLabel2 = Label(scrollableFileList.interior, text="Visibility", font=("Arial", 11))
        visibilityLabel2.grid(row=0, column=2, sticky=W)

        queryResult = self.priveConnection.getFiles()
        if queryResult["errorCode"] != "successful":
            deleteFileTopelevel.destroy()
            return

        del queryResult["errorCode"]

        currentRow = 1
        sizes = 0
        errorLabel = None

        nameLabel = {}
        sizeLabel = {}
        visibilityLabel = {}
        deleteButton = {}

        for key in queryResult.keys():
            nameLabel[key] = Label(scrollableFileList.interior, text=self.nameToMoreLong(queryResult[key]["name"], 30),
                              font=("Arial", 10))
            nameLabel[key].grid(row=currentRow, column=0, sticky=W)
            sizeLabel[key] = Label(scrollableFileList.interior,
                              text=(self.nameToMoreLong(str(queryResult[key]["size"] / 1000),
                                                        9) + "KB"), font=("Arial", 10))
            sizeLabel[key].grid(row=currentRow, column=1, sticky=W)

            visibilityLabel[key] = Label(scrollableFileList.interior,
                                    text=self.nameToMoreLong(queryResult[key]["visibility"], 10), font=("Arial", 10))
            visibilityLabel[key].grid(row=currentRow, column=2, sticky=W)

            deleteButton[key] = Button(scrollableFileList.interior, text="Delete",
                                    command=lambda key=key: self.doDeleteFile(queryResult[key]["id"],
                                                                              errorLabel,
                                                                              queryResult,
                                                                              nameLabel,
                                                                              sizeLabel,
                                                                              visibilityLabel,
                                                                              deleteButton),
                                    font=("Arial", 10))
            deleteButton[key].grid(row=currentRow, column=3, sticky=W)
            currentRow += 1
            sizes += queryResult[key]["size"]

        deleteFileTopelevel.geometry(str(int(scrollableFileList.canvas.winfo_reqwidth())) + "x" +
                                     str(int(scrollableFileList.canvas.winfo_reqheight()) + 60))

        sizeLabel3 = Label(deleteFileTopelevel, text=(str(sizes / 1000.0) + "KB"), font=("Arial", 10))
        sizeLabel3.grid(row=1, column=0, columnspan=3)

        errorLabel = Label(deleteFileTopelevel, text="", font=("Arial", 10))
        errorLabel.grid(row=2, column=0, columnspan=3)

    def settings(self):
        settingsToplevel = Toplevel(self.mainWindow)
        settingsToplevel.geometry("400x200")
        settingsToplevel.title("Settings")
        settingsToplevel.grab_set()

        centralFrame = Frame(settingsToplevel)
        centralFrame.place(relx=0.5, rely=0.5, anchor="center")

        settingsLabel = Label(centralFrame, text="Settings", font=("Arial", 16))
        settingsLabel.grid(row=0, column=0, columnspan=2)

        empty = Label(centralFrame, text=" ", font=("Arial", 12))
        empty.grid(row=1, column=0)

        changePasswordButton = Button(centralFrame, text="Change password", font=("Arial", 14),
                                      command=lambda: self.changePassword(settingsToplevel))
        changePasswordButton.grid(row=2, column=0, columnspan=2)

        deleteUser = Button(centralFrame, text="Delete User", font=("Arial", 14), fg="red",
                            command=lambda: self.deleteUser(settingsToplevel))
        deleteUser.grid(row=3, column=0, columnspan=2)

        about = Button(centralFrame, text="About", font=("Arial", 14),
                       command=lambda: self.about(settingsToplevel))
        about.grid(row=4, column=0, columnspan=2)

    def about(self, settingsToplevel):
        aboutToplevel = Toplevel(settingsToplevel)
        aboutToplevel.grab_set()
        aboutLabel1 = Label(aboutToplevel, text="Prive by Alex Cervilla Murga", font=("Arial", 12))
        aboutLabel1.grid(row=0, column=0)
        aboutLabel2 = Label(aboutToplevel, text="GUIClient by Alex Cervilla Murga", font=("Arial", 12))
        aboutLabel2.grid(row=1, column=0)
        aboutLabel3 = Label(aboutToplevel, text="", font=("Arial", 8))
        aboutLabel3.grid(row=2, column=0)
        aboutLabel4 = Label(aboutToplevel, text="Prive is a secure online drive", font=("Arial", 12))
        aboutLabel4.grid(row=3, column=0)
        aboutLabel5 = Label(aboutToplevel, text="In development 23 Apr 2019 - Present", font=("Arial", 12))
        aboutLabel5.grid(row=4, column=0)

    def changePassword(self, settingsToplevel):
        changePasswordToplevel = Toplevel(settingsToplevel)
        changePasswordToplevel.title("Change password")

        warningLabel = Label(changePasswordToplevel,
                             text="WARNING: all your private files won't be accessible again.",
                             font=("Arial", 14), fg="red")
        warningLabel.grid(row=0, column=0, columnspan=3)
        warningLabel2 = Label(changePasswordToplevel,
                              text= "To fix this download them, delete them from the server",
                              font=("Arial", 14), fg="red")
        warningLabel2.grid(row=1, column=0, columnspan=3)
        warningLabel3 = Label(changePasswordToplevel,
                              text="and upload them after changing your password",
                              font=("Arial", 14), fg="red")
        warningLabel3.grid(row=2, column=0, columnspan=3)

        currentPasswordLabel = Label(changePasswordToplevel, text="Actual password: ", font=("Arial", 12))
        currentPasswordLabel.grid(row=3, column=0, sticky=W)
        currentPasswordEntry = MaxLengthEntry(changePasswordToplevel, font=("Arial", 12), maxlength=31)
        currentPasswordEntry.grid(row=3, column=1)

        newPasswordLabel = Label(changePasswordToplevel, text="New Password: ", font=("Arial", 12))
        newPasswordLabel.grid(row=4, column=0, sticky=W)
        newPasswordEntry = Entry(changePasswordToplevel, font=("Arial", 12))
        newPasswordEntry.grid(row=4, column=1)

        confirmNewPasswordLabel = Label(changePasswordToplevel, text="Confirm New Password: ", font=("Arial", 12))
        confirmNewPasswordLabel.grid(row=5, column=0, sticky=W)
        confirmNewPasswordEntry = MaxLengthEntry(changePasswordToplevel, font=("Arial", 12), maxlength=31)
        confirmNewPasswordEntry.grid(row=5, column=1)

        errorLabel = Label(changePasswordToplevel, text="", font=("Arial", 12))
        errorLabel.grid(row=6, column=0, columnspan=3)

        changePasswordButton = Button(changePasswordToplevel, text="Change Password", font=("Arial", 12), fg="blue",
                                      command=lambda: self.doChangePassword(changePasswordToplevel,
                                                                            currentPasswordEntry,
                                                                            newPasswordEntry,
                                                                            confirmNewPasswordEntry,
                                                                            errorLabel))
        changePasswordButton.grid(row=7, column=1)

    def deleteUser(self, settingsToplevel):
        deleteUserToplevel = Toplevel(settingsToplevel)
        deleteUserToplevel.grab_set()

        currentPasswordLabel = Label(deleteUserToplevel, text="Current password: ", font=("Arial", 12))
        currentPasswordLabel.grid(row=0, column=0)

        currentPasswordEntry = Entry(deleteUserToplevel, font=("Arial", 12))
        currentPasswordEntry.grid(row=0, column=1)

        warningLabel = Label(deleteUserToplevel, text="WARNING: If you click YES, all your files will be deleted!",
                             font=("Arial", 12), fg="red")
        warningLabel2 = Label(deleteUserToplevel, text="Be careful!", font=("Arial",12), fg="red")
        warningLabel.grid(row=1, column=0, columnspan=3)
        warningLabel2.grid(row=2, column=0, columnspan=3)

        yesButton = Button(deleteUserToplevel, text="YES", font=("Arial", 12), fg="black", bg="red",
                           command=lambda: self.doDeleteUser(settingsToplevel, deleteUserToplevel,
                                                             currentPasswordEntry))
        yesButton.grid(row=3, column=0)

        noButton = Button(deleteUserToplevel, text="No", font=("Arial", 12),
                          command=deleteUserToplevel.destroy)
        noButton.grid(row=3, column=1)

        deleteUserToplevel.update()
        deleteUserToplevel.geometry(str(deleteUserToplevel.winfo_width())+"x"+str(deleteUserToplevel.winfo_height()+10))

    def doDeleteUser(self, settingsToplevel, deleteUserToplevel, currentPasswordEntry):
        if currentPasswordEntry.get() != self.priveConnection.getLoggedInPasswd():
            wrongPasswdToplevel = Toplevel(deleteUserToplevel)
            wrongPasswdToplevel.grab_set()
            wrongPasswdLabel = Label(wrongPasswdToplevel, text="Wrong current password", font=("Arial", 12), fg="red")
            wrongPasswdLabel.grid(row=0, column=0)
            wrongPasswdToplevel.update()
            wrongPasswdToplevel.geometry(str(wrongPasswdToplevel.winfo_width())+"x"+str(wrongPasswdToplevel.winfo_height()+10))
            return

        result = self.priveConnection.deleteUser()
        if result["errorCode"] == "successful":
            self.setActiveFrame("loginFrame")
            deleteUserToplevel.destroy()
            settingsToplevel.destroy()
        else:
            errorToplevel = Toplevel(deleteUserToplevel)
            errorToplevel.grab_set()
            errorLabel = Label(errorToplevel, text="Error: {}".format(result["msg"]), font=("Arial", 12),
                               fg="red")
            errorLabel.grid(row=0, column=0)
            errorToplevel.update()
            errorToplevel.geometry(str(errorToplevel.winfo_width())+"x"+str(errorToplevel.winfo_height()+10))
            return

    def doChangePassword(self, changePasswordToplevel,
                         currentPasswordEntry, newPasswordEntry, confirmNewPasswordEntry, errorLabel):
        # type: (Toplevel, Entry, Entry, Entry, Label) -> None

        if currentPasswordEntry.get() != self.priveConnection.getLoggedInPasswd():
            errorLabel.config(text="Wrong password", fg="red")
            return
        if newPasswordEntry.get() != confirmNewPasswordEntry.get():
            errorLabel.config(text="New password doesn't match", fg="red")
            return

        errorLabel.config(text="Please wait...")
        changePasswordToplevel.update()
        queryResult = self.priveConnection.updateKeys(newPasswordEntry.get())

        if queryResult["errorCode"] == "successful":
            errorLabel.config(text="Password changed successfully")
            return
        errorLabel.config(text="Error {}".format(queryResult["msg"]))
        return



    def doDeleteFile(self, id, errorLabel, queryResults, nameLabels, sizeLabels, visibilityLabels, deleteButtons):
        areYouSureToplevel = Toplevel(self.mainWindow)
        areYouSureToplevel.grab_set()
        areYouSureToplevel.title("Are you sure?")

        areYouSureText = Label(areYouSureToplevel,
                               text="Are you sure you want to delete " + self.nameToMoreLong(queryResults[id]["name"],
                                                                                             30) + "?",
                               font=("Arial", 10))
        areYouSureText.grid(row=0, column=0, columnspan=2)

        yesButton = Button(areYouSureToplevel, text="Yes", font=("Arial", 10),
                           command=lambda: self.yesImSure(id, errorLabel, queryResults, areYouSureToplevel,
                                                          nameLabels, sizeLabels, visibilityLabels, deleteButtons))
        yesButton.grid(row=1, column=0)

        noButton = Button(areYouSureToplevel, text="No", font=("Arial", 10),
                          command=lambda: self.noImNotSure(errorLabel, areYouSureToplevel))
        noButton.grid(row=1, column=1)

        areYouSureToplevel.update()

        areYouSureToplevel.geometry(str(areYouSureText.winfo_width()+10) + "x75")

    def yesImSure(self, id, errorLabel, queryResults, areYouSureToplevel, nameLabels, sizeLabels, visibilityLabels,
                  deleteButtons):
        queryResult = self.priveConnection.deleteFile(queryResults[id])
        if queryResult["errorCode"] == "successful":
            nameLabels[id].destroy()
            sizeLabels[id].destroy()
            visibilityLabels[id].destroy()
            deleteButtons[id].destroy()
            del nameLabels[id]
            del sizeLabels[id]
            del visibilityLabels[id]
            del deleteButtons[id]

            currentRow = 1
            for key in nameLabels.keys():
                nameLabels[key].grid(row=currentRow, column=0)
                sizeLabels[key].grid(row=currentRow, column=1)
                visibilityLabels[key].grid(row=currentRow, column=2)
                deleteButtons[key].grid(row=currentRow, column=3)
                currentRow += 1

            errorLabel.config(text="Deleted successfully", fg="green")
            areYouSureToplevel.destroy()
            return

        errorLabel.config(text="Error {}".format(queryResult["msg"]), fg="red")

        areYouSureToplevel.destroy()
        return

    def noImNotSure(self, errorLabel, areYouSureToplevel):
        errorLabel.config(text="Delete canceled", fg="black")
        areYouSureToplevel.destroy()

    def doDownloadFile(self, id, errorLabel, queryResults):
        queryResult = self.priveConnection.getFile(queryResults[id])
        if queryResult["errorCode"] != "successful":
            errorLabel.config(text="Error: {}".format(queryResult["msg"]), fg="red")
            return
        saveLocation = tkFileDialog.asksaveasfilename()
        if saveLocation == "":
            errorLabel.config(text="Download cancelled", fg="black")
            return
        saveLocationFile = open(saveLocation, "w")
        saveLocationFile.write(queryResult["file"])
        saveLocationFile.close()
        errorLabel.config(text="Download successful", fg="green")
        return

    def doUploadFile(self, uploadFileTopLevel, visibility, pathEntry, errorLabel):
        # type: (Toplevel, ttk.Combobox, Entry, Label) -> None
        pathFile = pathEntry.get()
        uploadFileTopLevel.geometry("350x140")
        if not os.path.isfile(pathFile):
            errorLabel.config(text="File not found", fg="red")
            return
        errorLabel.config(text="Please wait...", fg="black")
        uploadFileTopLevel.update_idletasks()
        fileObject = open(pathEntry.get(), "rb")
        fileString = fileObject.read()
        try:
            queryResult = self.priveConnection.addFile(os.path.basename(pathFile), fileString,
                                                       visibility=visibility.get())
        except Exception as e:
            queryResult = {"errorCode": e.message}
        if queryResult["errorCode"] == "successful":
            errorLabel.config(text="File uploaded", fg="green")
        else:
            errorLabel.config(text="Error {}".format(queryResult["msg"]), fg="red")

    def setPathButton(self, pathEntry):
        # type: (Entry) -> None
        pathEntry.delete(0, END)
        pathEntry.insert(0, tkFileDialog.askopenfilename())

    def doLogin(self, loginTopLevel, usernameEntry, passwordEntry, errorLabel):
        # type: (Toplevel, Entry, Entry, Label) -> None
        try:
            queryResult = self.priveConnection.login(usernameEntry.get(), passwordEntry.get())
        except Exception as e:
            queryResult = {"errorCode": e.message}
        if queryResult["errorCode"] == "successful" and self.priveConnection.loggedIn:
            loginTopLevel.destroy()
            self.loggedInFrameWidgets["loggedInText"].config(text="Logged in as " + self.priveConnection.loggedInUser)
            self.setActiveFrame("loggedInFrame")
        else:
            errorLabel.config(text="Error: {}".format(queryResult["msg"]), fg="red")
            loginTopLevel.geometry("250x150")

    def doRegister(self, registerToplevel, usernameEntry, passwordEntry, confirmPasswordEntry, errorLabel):
        if passwordEntry.get() != confirmPasswordEntry.get():
            errorLabel.config(text="Error: Password doesn't match", fg="red")
            return
        registerToplevel.geometry("300x150")
        errorLabel.config(text="Please wait...", fg="black")
        registerToplevel.update()
        try:
            queryResult = self.priveConnection.createUser(usernameEntry.get(), passwordEntry.get())
        except Exception as e:
            queryResult = {"errorCode": e.message}
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
