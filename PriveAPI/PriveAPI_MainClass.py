import os

class MainClassBase:

    programName = "AppName"

    def __init__(self):
        os.chdir(os.path.split(os.path.abspath(str(__file__)))[0])
        self.programName = ""

    def main(self):
        pass