from django.shortcuts import render
from django.http import HttpResponseRedirect, JsonResponse, HttpResponse
from Member.utils.identify.google import startValid, callbackHandler, testSession, revokeAccess
from Member.utils.secure.secureTools import hmacsha, session_decrypted, session_key_generate
from AlfredWiki.settings import DEBUG
import json

# Create your views here.


def login(request):
    # login page
    if request.method not in ['GET', 'POST']:
        return JsonResponse({'ok': False, 'message': 'Method Not Allowed'})

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

        email = body['email']
        pass_encrypt = body['pass']
        pass_decrypt = session_decrypted(
            pass_encrypt, request.session['login_private_key'])

        print(email, pass_decrypt)
    except:
        return JsonResponse({'ok': False, 'message': 'Invalid Parameter'})


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
