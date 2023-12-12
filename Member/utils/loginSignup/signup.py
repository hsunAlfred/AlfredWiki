from django.contrib import auth
from django.contrib.auth.models import User
from django.core.exceptions import ObjectDoesNotExist
import sys
from Member.utils.secure.secureTools import hmacsha, sessionDecrypted
from Member.utils.loginSignup.fieldVaild import usernameVaild, emailVaild, passwordVaild, ValidException
from Member.utils.loginSignup.resultObj import loginSignupResult


def signupCheck(body, signup_private_key) -> loginSignupResult:
    lsr = loginSignupResult()

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

        username_decrypt = username_decrypt['info']
        if not usernameVaild(username_decrypt):
            raise ValidException("Invalid username.")

        email_decrypt = email_decrypt['info']
        if not emailVaild(email_decrypt):
            raise ValidException("Invalid email.")

        pass_decrypt = pass_decrypt['info']
        if not passwordVaild(pass_decrypt):
            raise ValidException("Invalid password.")

        pass_hash = hmacsha(username_decrypt, pass_decrypt)
    except ValidException as e:
        lsr.setFail(str(e), 400)
    except:
        lsr.setFail('Invalid Parameter.', 400)

    if not lsr.ok:
        return lsr

    try:
        User.objects.get(username=username_decrypt)

        lsr.setFail('Username has been registered.', 400)
    except ObjectDoesNotExist as e:
        print('Username OK')

        try:
            User.objects.get(email=email_decrypt)

            lsr.setFail('Email has been registered.', 400)
        except ObjectDoesNotExist as e:
            print('Email OK')
        except Exception as e:
            print('Email', e)

            lsr.setFail('Invalid Parameter.', 400)
    except Exception as e:
        print('Username', e)

        lsr.setFail('Invalid Parameter.', 400)

    if not lsr.ok:
        return lsr

    try:
        user = User.objects.create_user(
            username=username_decrypt, email=email_decrypt, password=pass_hash)
        user.save()
    except Exception as e:
        lsr.setFail('Sign up fail.', 400)

    return lsr
