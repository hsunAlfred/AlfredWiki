from django.contrib import auth
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
import sys
from Member.utils.secure.secureTools import hmacsha, sessionDecrypted
from Member.utils.loginSignup.fieldVaild import emailVaild, ValidException
from Member.utils.loginSignup.loginSignup import loginSignupBase
from Member.models import UserSignupPlatform


class loginCheck(loginSignupBase):
    def decryptBody(self, body, login_private_key):
        try:
            userEmail_encrypt = body['userEmail']
            userEmail_decrypt = sessionDecrypted(
                userEmail_encrypt, login_private_key)

            pass_encrypt = body['pass']
            pass_decrypt = sessionDecrypted(pass_encrypt, login_private_key)

            if not userEmail_decrypt['status'] or not pass_decrypt['status']:
                raise

            self.userEmail_decrypt = userEmail_decrypt['info']
            self.isMail = False
            if emailVaild(self.userEmail_decrypt):
                self.isMail = True

            self.pass_decrypt = pass_decrypt['info']
        except ValidException as e:
            self.lsr.setFail(str(e), 400)
        except Exception as e:
            print(e)
            self.lsr.setFail('Invalid Parameter.', 400)
    
    def oauthSet(self, email, userid):
        self.userEmail_decrypt = email
        self.isMail = True
        self.pass_decrypt = hmacsha(email, userid)

    def process(self, loginby):
        try:
            if self.isMail:
                user_tmp = User.objects.get(
                    email=self.userEmail_decrypt
                )
            else:
                user_tmp = User.objects.get(
                    username=self.userEmail_decrypt
                )
            
            platform = "Google"
            try:
                usp = UserSignupPlatform.objects.get(User=user_tmp)
                platform = usp.Platform
            except ObjectDoesNotExist:
                platform = "Self"
            
            if loginby != platform:
                self.lsr.setFail("This account is registered by other method.", 401)
            else:
                username_tmp = user_tmp.username
                
                pass_hash = hmacsha(username_tmp, self.pass_decrypt)

                try:
                    user_obj = auth.authenticate(
                        username=username_tmp, password=pass_hash)

                    if user_obj is not None:
                        if not user_obj.is_active:
                            self.lsr.setFail("User not active.", 401)
                        else:
                            self.lsr.user_obj = user_obj
                    else:
                        self.lsr.setFail("Incorrect login info.", 401)
                except Exception as e:
                    exception_type, exception, exc_tb = sys.exc_info()
                    print(exception_type, exception, exc_tb)

                    self.lsr.setFail(str(e), 401)
        except Exception as e:
            print(e)
            self.lsr.setFail("User not exist.", 401)
