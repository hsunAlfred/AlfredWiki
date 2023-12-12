class loginSignupResult:
    ok = True
    message = "Success."
    user_obj = None
    code = 200

    def setFail(self, message, code):
        self.ok = False
        self.message = message
        self.code = code
