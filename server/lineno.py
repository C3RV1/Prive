import inspect


def lineno():
    return inspect.currentframe().f_back.f_lineno
