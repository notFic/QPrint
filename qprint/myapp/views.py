import random
import time

from django.contrib.auth.decorators import login_required
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.core.mail import send_mail
from django.contrib import messages
from .supabase_client import get_supabase
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
import base64
from django.shortcuts import render
from django.http import HttpRequest, HttpResponse
from django.contrib import messages
from .decorators import no_cache_page
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError

def send_password_reset_email(request, email):
    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return False  

    
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))

    reset_link = request.build_absolute_uri(f'/reset-password/{uid}/{token}/')

    subject = "Password Reset Request"
    message = (
        f"Hello {user.username},\n\n"
        f"You requested a password reset for your QPrint account.\n\n"
        f"Click the link below to reset your password:\n{reset_link}\n\n"
        f"If you didn’t request this, please ignore this email."
    )

    send_mail(subject, message, settings.DEFAULT_FROM_EMAIL, [email])

    return True

def _send_otp_email(email, otp):
    send_mail(
        "Your QPrint Email Verification Code",
        f"Hello,\n\nYour QPrint verification code is: {otp}\n\nIf you didn't request this, ignore this email.",
        "QPrint <qprintapp@gmail.com>",  
        [email],
        fail_silently=False,
    )

def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]
        password = request.POST["password"]
        confirm = request.POST["confirm_password"]

        if not email.endswith("@gmail.com"):
            messages.error(request, "Email must end with @gmail.com")
            return render(request, "myapp/register.html", {
                "username": username,
                "email": email,
                "password": password,
                "confirm": confirm,
            })

        if password != confirm:
            messages.error(request, "Passwords do not match")
            return render(request, "myapp/register.html", {
                "username": username,
                "email": email,
                "password": password,
                "confirm": confirm,
            })
        
        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, e.messages[0])
            return render(request, "myapp/register.html", {
                "username": username,
                "email": email,
                "password": password,
                "confirm": confirm,
            })

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken")
            return render(request, "myapp/register.html", {
                "username": username,
                "email": email,
                "password": password,
                "confirm": confirm,
            })

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already used")
            return render(request, "myapp/register.html", {
                "username": username,
                "email": email,
                "password": password,
                "confirm": confirm,
            })

        otp = str(random.randint(100000, 999999))

        _send_otp_email(email, otp)

        request.session["otp"] = otp
        request.session["username"] = username
        request.session["email"] = email
        request.session["password"] = password
        request.session["otp_created"] = time.time()

        return redirect("verify")

    return render(request, "myapp/register.html")

OTP_EXPIRE_SECONDS = 10 * 60   
RESEND_COOLDOWN_SECONDS = 60  

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

            user = User.objects.create_user(username=username, email=email, password=password)

            try:
                supabase = get_supabase()
                profile_data = {
                    'django_user_id': user.id,
                    'username': username,
                    'email': email,
                    'created_at': 'now()'
                }
                response = supabase.table('profiles').insert(profile_data).execute()

                if hasattr(response, 'error') and response.error:
                    messages.warning(request, "Account created but Supabase sync had issues.")
                else:
                    messages.success(request, "Account created successfully")

            except Exception as e:
                print(f"Supabase integration error: {e}")
                messages.success(request, "Account created successfully! (Supabase sync failed)")

            for k in ("username", "email", "password", "otp", "otp_last_sent", "otp_created"):
                request.session.pop(k, None)

            return redirect("login")
        else:
            messages.error(request, "Invalid verification code. Try again.")

    return render(request, "myapp/verify.html")


def login(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        user = authenticate(request, username=username, password=password)

        if user is not None:
            auth_login(request, user)

            try:
                supabase = get_supabase()
                login_data = {
                    'user_id': user.id,
                    'login_time': 'now()'
                }
                supabase.table('login_activity').insert(login_data).execute()
            except Exception as e:
                print(f"Supabase activity logging error: {e}")

            if user.is_staff:
                return redirect('staff_dashboard')
            else:
                return redirect('student_dashboard')

        else:
            messages.error(request, "Invalid username or password")
            return render(request, "myapp/login.html", {
                "username": username
            })

    return render(request, "myapp/login.html")



def logout(request):
    if request.user.is_authenticated:
        try:
            supabase = get_supabase()
            logout_data = {
                'user_id': request.user.id,
                'logout_time': 'now()'
            }
            supabase.table('logout_activity').insert(logout_data).execute()
        except Exception as e:
            print(f"Supabase activity logging error: {e}")

        auth_logout(request)
        messages.success(request, "You have been logged out successfully.")
    else:
        messages.info(request, "You were not logged in.")

    return redirect("login")

def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email")
        if send_password_reset_email(request, email):
            return render(request, 'myapp/password_reset_sent.html')
    return render(request, 'myapp/forgot_password.html')


def reset_password(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        if request.method == "POST":
            new_password = request.POST.get("password")
            try:
                validate_password(new_password, user)
            except ValidationError as e:
                messages.error(request, e.messages[0])
                return render(request, 'myapp/reset_password_form.html', {'validlink': True})

            user.set_password(new_password)
            user.save()
            return redirect('login')  
        return render(request, 'myapp/reset_password_form.html', {'validlink': True})
    else:
        return render(request, 'myapp/reset_password_form.html', {'validlink': False})

@login_required(login_url='login')
def staff_dashboard(request):
    if not request.user.is_staff:
        return redirect('student_dashboard')
    return render(request, "myapp/staff_dashboard.html")


MAX_PREVIEW_SIZE = 10 * 1024 * 1024  # 10 MB

PRICING = {
    'bw': 1.00,  # ₱1.00 per page for Black & White
    'color': 5.00,  # ₱5.00 per page for Color
}


@login_required(login_url='login')
@no_cache_page
def student_dashboard(request: HttpRequest) -> HttpResponse:
    """
    Renders the dashboard and handles file upload, print customizations,
    cost calculation, and validation.
    """
    context = {
        'pdf_data': request.session.get('pdf_data'),
        'file_name': request.session.get('file_name'),
        'form_data': {},
    }

    if request.method == 'POST':
        action = request.POST.get('action')

        # --- File Upload Logic ---
        if 'print_file' in request.FILES:
            uploaded_file = request.FILES['print_file']
            if uploaded_file.name.lower().endswith('.pdf'):
                encoded_pdf = base64.b64encode(uploaded_file.read()).decode('utf-8')
                # Store file data in the session to persist it across reloads
                request.session['pdf_data'] = encoded_pdf
                request.session['file_name'] = uploaded_file.name
                # Redirect to clear the POST data and prevent re-submission issues
                return redirect('student_dashboard')
            else:
                messages.error(request, "Please upload a valid PDF file.")

        # Preserve user input across reloads
        context['form_data'] = {
            'pages': request.POST.get('pages'),
            'paper_size': request.POST.get('paper_size'),
            'color_option': request.POST.get('color_option'),
        }

        # --- Calculation and Validation Logic ---
        if action == 'calculate':
            pages_str = context['form_data']['pages']
            paper_size = context['form_data']['paper_size']
            color_option = context['form_data']['color_option']

            # Validation
            errors = False
            try:
                pages = int(pages_str)
                if pages <= 0:
                    messages.error(request, "Please enter a positive whole number of pages.")
                    errors = True
            except (ValueError, TypeError):
                messages.error(request, "Please enter a positive whole number of pages.")
                errors = True

            if not paper_size:
                messages.error(request, "Please select a paper size.")
                errors = True

            if not color_option:
                messages.error(request, "Please select a color option.")
                errors = True

            # If no errors, calculate the cost
            if not errors:
                base_price = PRICING.get(color_option, 0)
                total_cost = base_price * pages
                context['total_cost'] = f"{total_cost:.2f}"  # Format to two decimal places

    # On a GET request, clear any old session data
    elif request.method == 'GET':
        request.session.pop('pdf_data', None)
        request.session.pop('file_name', None)

    return render(request, 'myapp/student_dashboard.html', context)
