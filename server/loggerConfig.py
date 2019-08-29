spaces = 40

def nameAndMessage(name, message):
	return "[" + name + "]" + " "*(((spaces - (len(name)+2)) > 0)*(spaces-(len(name)+2))) + message