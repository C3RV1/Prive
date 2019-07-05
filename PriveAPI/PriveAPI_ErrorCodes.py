
class createUser:
    successful = "successful"
    userNotFound = "usrNotFound"
    invalidNameCharacters = "invalidName"
    userAlreadyExists = "usrAlreadyExists"
    invalidPrivateKey = "invalidSK"
    invalidPublicKey = "invalidPK"
    invalidValidationToken = "invalidVT"
    invalidValidationTokenEncrypted = "invalidVTEnc"

class login:
    successful = "successful"
    userNotFound = "usrNotFound"
    incorrectPassword = "incorrect"
    userDeletedWhilePerformingAction = "usrNotFound2"
    accountLocked = "accountLocked"

class deleteUser:
    notLoggedIn = "notLoggedIn"
    successful = "successful"
    userWithoutPK = "wtfHappenedToThePK"  # Should never be seen
    invalidSignatureCharacters = "invalidSignCh"
    userNotFound = "usrNotFound"
    invalidSignature = "invalidSign"
    faultyUserPK = "faultyPK"

class updateKeys:
    notLoggedIn = "notLoggedIn"
    successful = "successful"
    userNotFound = "usrNotFound"
    invalidSignatureCharacters = "invalidSignCh"
    invalidNewSK = "invalidNewSKAesB64"
    invalidNewPK = "invalidNewPK"
    userWithoutPK = "wtfHappenedToThePK"  # Should never be seen
    faultyUserPK = "faultyPK"
    invalidSignature = "invalidSign"

class getUserPK:
    successful = "successful"
    userNotFound = "usrNotFound"
    userWithoutPK = "wtfHappenedToThePK"  # Should never be seen
