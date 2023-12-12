import re


class ValidException(Exception):
    def __init__(self, message):
        super().__init__(message)


def usernameVaild(username):
    regex = re.compile(r'([A-Za-z0-9])+')
    if not re.fullmatch(regex, username):
        return False

    return True


def emailVaild(email):
    regex = re.compile(r"[^@]+@[^@]+\.[^@]+")
    if not re.fullmatch(regex, email):
        return False

    return True


def passwordVaild(password):
    if len(password) < 7:
        return False

    regex = re.compile(r'([A-Z]+[a-z]+[0-9]+[!@#$%^&*()_+*/=~])+')
    if not re.fullmatch(regex, password):
        return False

    return True
