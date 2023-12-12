from django.contrib import auth
from django.contrib.auth.models import User
import sys
from Member.utils.secure.secureTools import hmacsha, sessionDecrypted
from Member.utils.loginSignup.fieldVaild import emailVaild, ValidException
from Member.utils.loginSignup.resultObj import loginSignupResult


def loginCheck(body, login_private_key) -> loginSignupResult:
    lsr = loginSignupResult()

    try:
        userEmail_encrypt = body['userEmail']
        userEmail_decrypt = sessionDecrypted(
            userEmail_encrypt, login_private_key)

        pass_encrypt = body['pass']
        pass_decrypt = sessionDecrypted(pass_encrypt, login_private_key)

        if not userEmail_decrypt['status'] or not pass_decrypt['status']:
            raise

        userEmail_decrypt = userEmail_decrypt['info']
        isMail = False
        if emailVaild(userEmail_decrypt):
            isMail = True

        pass_decrypt = pass_decrypt['info']
    except ValidException as e:
        lsr.setFail(str(e), 400)
    except Exception as e:
        print(e)
        lsr.setFail('Invalid Parameter.', 400)

    if not lsr.ok:
        return lsr

    try:
        if isMail:
            username_tmp = User.objects.get(
                email=userEmail_decrypt
            ).username
        else:
            username_tmp = User.objects.get(
                username=userEmail_decrypt
            ).username

        pass_hash = hmacsha(username_tmp, pass_decrypt)

        try:
            user_obj = auth.authenticate(
                username=username_tmp, password=pass_hash)

            if user_obj is not None:
                if not user_obj.is_active:
                    lsr.setFail("User not active.", 401)
                else:
                    lsr.user_obj = user_obj
            else:
                lsr.setFail("Incorrect login info.", 401)
        except Exception as e:
            exception_type, exception, exc_tb = sys.exc_info()
            print(exception_type, exception, exc_tb)

            lsr.setFail(str(e), 401)
    except Exception as e:
        print(e)
        lsr.setFail("User not exist.", 401)

    return lsr
