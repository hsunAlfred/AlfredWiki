from django.shortcuts import render
from django.contrib import auth
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from Member.utils.oauth2.google import startValid, callbackHandler, testSession, revokeAccess
from Member.utils.secure.secureTools import sessionKeyGenerate
from Member.utils.loginSignup.login import loginCheck
from Member.utils.loginSignup.signup import signupCheck

from AlfredWiki.settings import DEBUG
import json
from django.contrib.auth.decorators import login_required


# Create your views here.


def login(request):
    # login page
    if request.method not in ['GET', 'POST']:
        return JsonResponse({'ok': False, 'message': 'Method Not Allowed.'}, status=405)

    if request.user.is_authenticated:
        return HttpResponseRedirect("/")

    if request.method == 'GET':
        session_public_key, session_private_key = sessionKeyGenerate()
        request.session['login_public_key'] = session_public_key
        request.session['login_private_key'] = session_private_key
        context = {
            "spk_client": session_public_key,
        }
        return render(request, 'member/login.html', context=context)

    # call api to login
    body = json.loads(request.body)

    lc = loginCheck()

    lc.decryptBody(body, request.session['login_private_key'])
    if not lc.lsr.ok:
        return JsonResponse({'ok': lc.lsr.ok, 'message': lc.lsr.message}, status=lc.lsr.code)

    lc.process()

    if lc.lsr.ok:
        auth.login(request, lc.lsr.user_obj)

    return JsonResponse({'ok': lc.lsr.ok, 'message': lc.lsr.message}, status=lc.lsr.code)


def signup(request):
    # signup page
    if request.method not in ['GET', 'POST']:
        return JsonResponse({'ok': False, 'message': 'Method Not Allowed.'}, status=405)

    if request.user.is_authenticated:
        return HttpResponseRedirect("/")

    if request.method == 'GET':
        session_public_key, session_private_key = sessionKeyGenerate()
        request.session['signup_public_key'] = session_public_key
        request.session['signup_private_key'] = session_private_key
        context = {
            "spk_client": session_public_key,
        }
        return render(request, 'member/signup.html', context=context)

    body = json.loads(request.body)

    sc = signupCheck()
    sc.decryptBody(body, request.session['signup_private_key'])

    if not sc.lsr.ok:
        return JsonResponse({'ok': sc.lsr.ok, 'message': sc.lsr.message}, status=sc.lsr.code)

    sc.process()

    return JsonResponse({'ok': sc.lsr.ok, 'message': sc.lsr.message}, status=sc.lsr.code)


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

    auth.logout(request)

    return HttpResponseRedirect('/member/login/')


@login_required(login_url='/member/login/')
def index(request):
    return HttpResponse("<style>body{background:black} a{color:white}</style><a href='/member/logout/'>logout</a>")
