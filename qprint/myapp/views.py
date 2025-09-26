import random
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.contrib import messages


def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]
        confirm = request.POST["confirm"]

        # if not username.endswith("@cit.edu"):
        #     messages.error(request, "Email must end with @cit.edu")
        #     return render(request, "myapp/register.html")

        if password != confirm:
            messages.error(request, "Passwords do not match")
            return render(request, "myapp/register.html")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken")
            return render(request, "myapp/register.html")

        otp = str(random.randint(100000, 999999))

        send_mail(
            "Your QPrint Email Verification Code",
            f"Hello,\n\nYour QPrint verification code is: {otp}",
            "QPrint <freezey789@gmail.com>",  
            [username],
            fail_silently=False,
        )

        request.session["otp"] = otp
        request.session["username"] = username
        request.session["password"] = password

        return redirect("verify")

    return render(request, "myapp/register.html")

def verify(request):
    if request.method == "POST":
        entered_otp = request.POST["otp"]

        if entered_otp == request.session.get("otp"):
            User.objects.create_user(
                username=request.session["username"],
                password=request.session["password"]
            )
            messages.success(request, "Account created successfully! You can now log in.")
            return redirect("login")
        else:
            messages.error(request, "Invalid OTP. Try again.")

    return render(request, "myapp/verify.html")

def login_view(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect("/")  
        else:
            messages.error(request, "Invalid username or password")
    return render(request, "myapp/login.html")


def logout_view(request):
    logout(request)
    return redirect("login")
