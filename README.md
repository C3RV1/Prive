# What is Prive?
Prive is an online drive where you can upload your files and access them remotely. Prive is designed for you to be able to upload files securely, without your privacy being in risk. If you upload a private file, it gets encrypted and neither the other users nor the server operator can read the contents.

Although the server operator can't read the contents of your file, it can delete files or users that are proven to be malicious.

# How to run locally

**Note: Prive must be run using Python 2.7**

First of all, download the source code from a stable release, stable pre-release or stable nighty from the Releases section and extract it. You should not download it from the master branch as it might be a work-in-progress with bugs, unfinished things or not running at all.

Next, you may run `python setup.py install` to install `PriveAPI`, `pycryptodome` and 'colorama'. All of them are modules used by the server and clients. We recommend installing all this modules on a virtualenv.

## To start the server

To start the server run `python init.py` in the `server` folder. You may want to modify the values in `config.py` to affect the behaviour of the server. The first time you start the server it will generate an rsa key pair and store the public key and the private key in `<DatabasePath>/publicKey.pk` and `<DatabasePath>/privateKey.skm` respectively. It will also generate a `prive configuration file(.pcf)`, which can be transferred to the users and used by any client to connect to the server. The default name of a `prive configuration file` is `priveConfigFile.pcf`. `<DatabasePath>` may be changed in `config.py` to any other path.

## To connect to the server

First of all, you must copy the `prive configuration file` to the folder of the client used by you to connect to the server. On most clients you can either specify the path of the `prive configuration file` or they will use the default name (`priveConfigFile.pcf`).

There are 2 official clients. You can find both of them under the `tests` folder. One of them is a GUI and can be found on the folder `guiClient` and the other one is a command line utility located in the `command_line_client` folder.
The GUI client is self explanatory when you boot it up. The help of the command line client can be accessed by executing `python prvconnect.py -h`.

# Finally
Any suggestion about how to improve the project would be very appreciated and helpful. This is a project in development since 23 Apr 2019.
