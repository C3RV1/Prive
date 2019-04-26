# Prive
Online service where you can save your rsa keys without risks.

# How to implement
You can implement it using the PriveAPI.py in the tests folder. There is also an example in clientTestAPI.py.

The class PriveAPIInstance is a connection to the server. The session key is automatically managed by this class.

The methods available to use are:
- Create User
- Login
- Delete User
- Keep Alive
- Update Keys (Work in progress)

# Prive API Constructor
The parameters it gets are:
- serverIP (int):             IP of the Prive Server
- serverPublicKeyFile (str):  Path of the server public key. The server provides it. The default value is ./serverPublicKey.pk
- serverPort (int):           Prive Port. The default value is 4373
- autoKeepAlive (bool):       If it is set to True, it sends automatically a keepalive message. The default value is True.

Creates a session key and connects with the server.

# Create User
The parameters it gets are:
- userName (str):             Name of the User
- password (str):             Password for the user

Generates RSA keypair for the user and encrypts it with the password. Then it is uploaded to the server.

# Login
The parameters it gets are:
- userName (str):             Name of the User
- password (str):             Password of the user

Logins as the user specified as userName. If the validation is successful, it sets loggedInSK to the RSAObj_ of the RSA Private Key. It also sets loggedInUser ans LoggedIn.

# Delete User
No parameters

Deletes the user if logged in. Better ask the user for a second thought.

# Keep Alive
No parameters

Sends a keep alive message. Not needed if autoKeepAlive is active.
