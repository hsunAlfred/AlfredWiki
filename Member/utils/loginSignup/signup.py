from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
from Member.utils.secure.secureTools import hmacsha, sessionDecrypted
from Member.utils.loginSignup.fieldVaild import usernameVaild, emailVaild, passwordVaild, ValidException
from Member.utils.loginSignup.loginSignup import loginSignupBase


class signupCheck(loginSignupBase):
    def decryptBody(self, body, signup_private_key):
        try:
            username_encrypt = body['username']
            username_decrypt = sessionDecrypted(
                username_encrypt, signup_private_key)

            email_encrypt = body['email']
            email_decrypt = sessionDecrypted(email_encrypt, signup_private_key)

            pass_encrypt = body['pass']
            pass_decrypt = sessionDecrypted(pass_encrypt, signup_private_key)

            if not username_decrypt['status'] or not email_decrypt['status'] or not pass_decrypt['status']:
                raise

            self.username_decrypt = username_decrypt['info']
            if not usernameVaild(self.username_decrypt):
                raise ValidException("Invalid username.")

            self.email_decrypt = email_decrypt['info']
            if not emailVaild(self.email_decrypt):
                raise ValidException("Invalid email.")

            self.pass_decrypt = pass_decrypt['info']
            if not passwordVaild(self.pass_decrypt):
                raise ValidException("Invalid password.")

            self.pass_hash = hmacsha(self.username_decrypt, self.pass_decrypt)
        except ValidException as e:
            self.lsr.setFail(str(e), 400)
        except Exception as e:
            self.lsr.setFail('Invalid Parameter.', 400)

    def process(self):
        try:
            User.objects.get(username=self.username_decrypt)

            self.lsr.setFail('Username has been registered.', 400)
        except ObjectDoesNotExist as e:
            print('Username OK')

            try:
                User.objects.get(email=self.email_decrypt)

                self.lsr.setFail('Email has been registered.', 400)
            except ObjectDoesNotExist as e:
                print('Email OK')
            except Exception as e:
                print('Email', e)

                self.lsr.setFail('Invalid Parameter.', 400)
        except Exception as e:
            print('Username', e)

            self.lsr.setFail('Invalid Parameter.', 400)

        if not self.lsr.ok:
            return self.lsr

        try:
            user = User.objects.create_user(
                username=self.username_decrypt, email=self.email_decrypt, password=self.pass_hash)
            user.save()
        except Exception as e:
            self.lsr.setFail('Sign up fail.', 400)
