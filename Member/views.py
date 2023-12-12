from django.shortcuts import render
from django.contrib import auth
from django.contrib.auth.models import User

from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from Member.utils.identify.google import startValid, callbackHandler, testSession, revokeAccess
from Member.utils.secure.secureTools import hmacsha, session_decrypted, session_key_generate
from AlfredWiki.settings import DEBUG
import json
import re
import sys

# Create your views here.


def login(request):
    # login page
    if request.method not in ['GET', 'POST']:
        return JsonResponse({'ok': False, 'message': 'Method Not Allowed.'}, status=405)

    if request.method == 'GET':
        session_public_key, session_private_key = session_key_generate()
        request.session['login_public_key'] = session_public_key
        request.session['login_private_key'] = session_private_key
        context = {
            "spk_client": session_public_key,
        }
        return render(request, 'member/login.html', context=context)

    # call api to login
    try:
        body = json.loads(request.body)

        email_encrypt = body['email']
        email_decrypt = session_decrypted(
            email_encrypt, request.session['login_private_key'])

        pass_encrypt = body['pass']
        pass_decrypt = session_decrypted(
            pass_encrypt, request.session['login_private_key'])

        if not email_decrypt['status'] or not pass_decrypt['status']:
            raise

        email_decrypt = email_decrypt['info']
        regex = re.compile(
            r'([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+')
        if not re.fullmatch(regex, email_decrypt):
            raise

        pass_decrypt = pass_decrypt['info']

        pass_hash = hmacsha(email_decrypt, pass_decrypt)
        print(pass_hash)
    except:
        return JsonResponse({'ok': False, 'message': 'Invalid Parameter.'}, status=400)

    ok = True
    message = "Success."
    try:
        user_tmp = User.objects.filter(email=email_decrypt).username

        try:
            user_obj = auth.authenticate(username=user_tmp, password=pass_hash)

            if user_obj is not None:
                if user_obj.is_active:
                    auth.login(request, user_obj)
            else:
                ok = False
                message = "Fail."
        except Exception as e:
            exception_type, exception, exc_tb = sys.exc_info()
            print(exception_type, exception, exc_tb)

            ok = False
            message = str(e)
    except:
        ok = False
        message = "User not exist."

    return JsonResponse({'ok': ok, 'message': message}, status=200 if ok else 401)


def signup(request):
    # signup page
    return render(request, 'member/signup.html')


def google(request):
    # user choose login/signup with google
    obj = startValid()
    authorization_url = obj['authorization_url']
    request.session['state'] = obj['state']

    return HttpResponseRedirect(authorization_url)

# {
    # 'id': '111964431590889584337',
    # 'email': 'alfredchen346@gmail.com',
    # 'verified_email': True,
    # 'name': 'Alfred Chen',
    # 'given_name': 'Alfred',
    # 'family_name': 'Chen',
    # 'picture': 'https://lh3.googleusercontent.com/a/ACg8ocJHDDoUXrkf8Q5ihqW__jn9FTJ8z64dkB2UabUMB-rs=s96-c',
    # 'locale': 'zh-TW'
    # }


def google_callback(request):
    # google callback
    state = request.session['state']

    authorization_response = (
        "http://" if DEBUG else "https://") + request.get_host()+request.get_full_path()

    request.session['credentials'] = callbackHandler(
        state, authorization_response)

    return HttpResponseRedirect('/google/test/')


def googleTest(request):
    if 'credentials' not in request.session:
        return HttpResponseRedirect('/')

    obj = testSession(request.session['credentials'])

    print(obj['userInfos'])

    request.session['credentials'] = obj['credentials']

    return HttpResponse("'status':'ok', <a href='/google/revoke/'>revoke</a>")


def logout(request):
    # logout
    if 'credentials' in request.session:
        credentials = request.session['credentials']

        result = revokeAccess(credentials)

    try:
        del request.session['credentials']
    except:
        pass

    return HttpResponseRedirect('/member/login/')
