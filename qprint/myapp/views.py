import random
import time
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login, logout
from django.core.mail import send_mail
from django.contrib import messages
from django.contrib.auth import authenticate, login as auth_login   # Django’s login renamed
from django.http import HttpResponseForbidden
from django.contrib.auth.decorators import login_required

# myapp/views.py

STAFF_EMAILS = [
    # "kurtgbasalo@gmail.com",
    "staff@example.com",
]

def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]
        password = request.POST["password"]
        confirm = request.POST["confirm_password"]

        # if not username.endswith("@cit.edu"):
        #     messages.error(request, "Email must end with @cit.edu")
        #     return render(request, "myapp/register.html")

        if password != confirm:
            messages.error(request, "Passwords do not match")
            return render(request, "myapp/register.html")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken")
            return render(request, "myapp/register.html")
        
        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already used")
            return render(request, "myapp/register.html")

        otp = str(random.randint(100000, 999999))

        send_mail(
            "Your QPrint Email Verification Code",
            f"Hello,\n\nYour QPrint verification code is: {otp}\n\nIf you didn't request this, ignore this email.",
            "QPrint <freezey789@gmail.com>",  
            [email],
            fail_silently=False,
        )

        request.session["otp"] = otp
        request.session["username"] = username
        request.session["email"] = email
        request.session["password"] = password

        return redirect("verify")

    return render(request, "myapp/register.html")

OTP_EXPIRE_SECONDS = 10 * 60   
RESEND_COOLDOWN_SECONDS = 60  

def _send_otp_email(email, otp):
    send_mail(
        "Your QPrint Email Verification Code",
        f"Hello,\n\nYour QPrint verification code is: {otp}\n\nIf you didn't request this, ignore this email.",
        "QPrint <freezey789@gmail.com>",  
        [email],
        fail_silently=False,
    )

def verify(request):
    if not (request.session.get("username") and request.session.get("email") and request.session.get("password")):
        messages.error(request, "No pending registration. Please register first.")
        return redirect("register")

    if request.GET.get("resend"):
        now_ts = time.time()
        last_sent = request.session.get("otp_last_sent", 0)
        elapsed = now_ts - last_sent
        if elapsed < RESEND_COOLDOWN_SECONDS:
            wait = int(RESEND_COOLDOWN_SECONDS - elapsed)
            messages.error(request, f"Please wait {wait} second(s) before resending.")
            return redirect("verify")

        new_otp = f"{random.randint(0, 999999):06d}"
        request.session["otp"] = new_otp
        request.session["otp_last_sent"] = now_ts
        request.session["otp_created"] = now_ts
        request.session.save()

        try:
            _send_otp_email(request.session["email"], new_otp)
            messages.success(request, "A new verification email has been sent.")
        except Exception as e:
            messages.error(request, f"Failed to send verification email: {e}")

        return redirect("verify")

    if request.method == "POST":
        entered_otp = (request.POST.get("otp") or "").strip()

        otp = request.session.get("otp")
        otp_created_ts = request.session.get("otp_created")

        if not otp:
            messages.error(request, "No verification code found. Please request a new code.")
            return redirect("verify")

        if otp_created_ts:
            if time.time() - otp_created_ts > OTP_EXPIRE_SECONDS:

                request.session.pop("otp", None)
                request.session.pop("otp_created", None)
                messages.error(request, "Verification code expired. Please request a new code.")
                return redirect("verify")

        if entered_otp == otp:
            username = request.session.get("username")
            email = request.session.get("email")
            password = request.session.get("password")

            if User.objects.filter(username=username).exists():
                messages.error(request, "Username already taken. Please register with a different username.")
                return redirect("register")
            if User.objects.filter(email=email).exists():
                messages.error(request, "Email already registered. Please login instead.")
                return redirect("login")

            User.objects.create_user(username=username, email=email, password=password)

            for k in ("username", "email", "password", "otp", "otp_last_sent", "otp_created"):
                request.session.pop(k, None)

            messages.success(request, "Account created successfully! You can now log in.")
            return redirect("login")
        else:
            messages.error(request, "Invalid verification code. Try again.")

    return render(request, "myapp/verify.html")



def login_view(request):   # keep your view name as is
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)

            # Determine user role by email
            if user.email in STAFF_EMAILS:
                return redirect("staff_dashboard")
            else:
                return redirect("student_dashboard")
        else:
            return render(request, 'myapp/login.html', {'error': 'Invalid credentials'})

    return render(request, 'myapp/login.html')

def logout_view(request):
    logout(request)
    return redirect("login")

@login_required
def staff_dashboard(request):
    if request.user.email not in STAFF_EMAILS:
        return HttpResponseForbidden("Access denied.")
    return render(request, "myapp/staff_dashboard.html")

@login_required
def student_dashboard(request):
    return render(request, "myapp/student_dashboard.html")
