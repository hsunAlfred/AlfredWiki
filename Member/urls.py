from django.urls import path
from Member.views import login, signup, logout, index

urlpatterns = [
    path('member/login/', login),  # login page
    path('member/signup/', signup),  # signup page
    path('member/logout/', logout),  # logout
    path('', index),
]
