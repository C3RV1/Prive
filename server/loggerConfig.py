spaces = 40


def nameAndMessage(name, message):
	# [NAME] + " "*(((40 - (len(name) + 2)) > 0) * (spaces - (len(name) + 2))) * message
	return "[" + name + "]" + " "*(((spaces - (len(name)+2)) > 0)*(spaces-(len(name)+2))) + message