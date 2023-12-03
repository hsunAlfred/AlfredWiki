from django.shortcuts import render
from django.http import HttpResponseRedirect, JsonResponse

# Create your views here.


def login(request):
    # login page
    return render(request, 'member/login.html')


def signup(request):
    # signup page
    return render(request, 'member/signup.html')


def google(request):
    # user choose login/signup with google
    return HttpResponseRedirect()

# {
    # 'id': '111964431590889584337', 
    # 'email': 'alfredchen346@gmail.com', 
    # 'verified_email': True, 
    # 'name': 'Alfred Chen', 
    # 'given_name': 'Alfred', 
    # 'family_name': 'Chen', 
    # 'picture': 'https://lh3.googleusercontent.com/a/ACg8ocJHDDoUXrkf8Q5ihqW__jn9FTJ8z64dkB2UabUMB-rs=s96-c', 
    # 'locale': 'zh-TW'
    #}

def google_callback(request):
    # google callback
    return HttpResponseRedirect()


def logout(request):
    # logout
    pass
