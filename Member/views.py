from django.shortcuts import render
from django.http import HttpResponseRedirect

# Create your views here.
def login(request):
     # login page
    return render('member/login.html')

def signup(request):
    # signup page
    return render('member/signup.html')

def google(request):
    # user choose login/signup with google
    return HttpResponseRedirect()

def google_callback(request):
    # google callback
    return HttpResponseRedirect()

def logout(request):
    # logout
    pass