from django.urls import path
from Member.views import login, signup, google, google_callback, logout

urlpatterns = [
    path('member/login/', login), # login page
    path('member/signup/', signup), # signup page
    path('member/google/', google), # user choose login/signup with google
    path('member/google/callback/', google_callback), # google callback
    path('member/logout/', logout), # logout
]