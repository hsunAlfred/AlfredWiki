from abc import ABCMeta, abstractmethod


class loginSignupResult:
    ok = True
    message = "Success."
    user_obj = None
    code = 200

    def setFail(self, message, code):
        self.ok = False
        self.message = message
        self.code = code


class loginSignupBase(metaclass=ABCMeta):
    def __init__(self):
        self.lsr = loginSignupResult()

    @abstractmethod
    def decryptBody(self):
        pass
    
    @abstractmethod
    def oauthSet(self):
        pass

    @abstractmethod
    def process(self):
        pass
