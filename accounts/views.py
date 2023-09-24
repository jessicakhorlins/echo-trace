from django.shortcuts import render, redirect
from django.contrib import auth, messages
from django.contrib.auth.decorators import login_required
from django.contrib.auth.models import User


@login_required
def account(request):
    user = request.user
    template = "account.html"
    context = {
        "user": user,
    }

    return render(request, template, context)


def signin(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        user = auth.authenticate(
            username=username,
            password=password,
            backend="django.contrib.auth.backends.ModelBackend",
        )

        if user is not None:
            auth.login(request, user)
            messages.success(request, "Welcome " + user.first_name)
            return redirect("dashboard")
        else:
            messages.error(request, "Invalid credentials. Please try again.")
            return redirect("signin")
    else:
        template = "signin.html"
        return render(request, template)


@login_required
def logout(request):
    auth.logout(request)
    logout(request)
    messages.info(request, "You have logged out.")
    return redirect("signin")


def signup(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        password2 = request.POST["confirm-password"]

        if password != password2:
            messages.error(request, "Passwords do not match")
            return redirect("signup")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Account with username already exists")
            return redirect("signup")

        # create user
        user = User.objects.create(
            username=username,
        )
        user.set_password(password)
        user.save()

        # auto login
        user = auth.authenticate(
            username=username,
            password=password,
            backend="django.contrib.auth.backends.ModelBackend",
        )
        auth.login(request, user)
        return redirect("dashboard")

    else:
        template = "signup.html"
        return render(request, template)
