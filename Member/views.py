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


def google_callback(request):
    # google callback
    return HttpResponseRedirect()


def logout(request):
    # logout
    pass
