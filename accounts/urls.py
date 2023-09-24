from django.urls import path
from . import views

urlpatterns = [
    path("", views.account, name="account"),
    path("signup/", views.signup, name="signup"),
    path("signin/", views.signin, name="signin"),
    path("logout/", views.logout, name="signout"),
]
