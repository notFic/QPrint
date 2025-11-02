import random
import time

from django.http import JsonResponse
from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.core.mail import send_mail
from django.contrib import messages
from django.conf import settings
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth.decorators import login_required
from django.core.exceptions import ValidationError
from django.http import HttpRequest, HttpResponse
from django.views.decorators.cache import never_cache
import os
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from io import BytesIO
import uuid
import base64
import PyPDF2
from io import BytesIO
from django.shortcuts import render, redirect
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.conf import settings

supabase = settings.SUPABASE_CLIENT
bucket = settings.SUPABASE_BUCKET

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

    email_message = Mail(
        from_email="qprintapp@gmail.com",  # Your verified SendGrid sender
        to_emails=email,
        subject=subject,
        plain_text_content=message,
    )

    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        sg.send(email_message)
        return True
    except Exception as e:
        print(f"SendGrid error: {e}")
        return False


def _send_otp_email(email, otp):
    message = Mail(
        from_email="qprintapp@gmail.com",
        to_emails=email,
        subject="Your QPrint Verification Code",
        plain_text_content=f"Hello,\n\nYour OTP is: {otp}\n\nIf you didn’t request this, ignore this email.",
    )
    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        sg.send(message)
    except Exception as e:
        print(f"SendGrid error: {e}")


def register(request):
    if request.method == "POST":
        username = request.POST["username"]
        email = request.POST["email"]
        password = request.POST["password"]
        confirm = request.POST["confirm_password"]

        if not email.endswith("@gmail.com"):
            messages.error(request, "Email must end with @gmail.com")
            return render(request, "subtemplates/register.html", {
                "username": username,
                "email": email,
                "password": password,
                "confirm": confirm,
            })

        if password != confirm:
            messages.error(request, "Passwords do not match")
            return render(request, "subtemplates/register.html", {
                "username": username,
                "email": email,
                "password": password,
                "confirm": confirm,
            })

        try:
            validate_password(password)
        except ValidationError as e:
            messages.error(request, e.messages[0])
            return render(request, "subtemplates/register.html", {
                "username": username,
                "email": email,
                "password": password,
                "confirm": confirm,
            })

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken")
            return render(request, "subtemplates/register.html", {
                "username": username,
                "email": email,
                "password": password,
                "confirm": confirm,
            })

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already used")
            return render(request, "subtemplates/register.html", {
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

    return render(request, "subtemplates/register.html")


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
                supabase = settings.SUPABASE_CLIENT
                profile_data = {
                    'django_user_id': user.id,
                    'username': username,
                    'email': email,
                    'created_at': 'now()'
                }
                response = supabase.table('profiles').insert(profile_data)

                if hasattr(response, 'error') and response.error:
                    messages.warning(request, "Account created but Supabase sync had issues.")
                else:
                    messages.success(request, "Account created successfully")

            except Exception as e:
                print(f"Supabase integration error: {e}")
                messages.success(request, f"Account created successfully! (Supabase sync failed: {e})")

            for k in ("username", "email", "password", "otp", "otp_last_sent", "otp_created"):
                request.session.pop(k, None)

            return redirect("login")
        else:
            messages.error(request, "Invalid verification code. Try again.")

    return render(request, "subtemplates/verify.html")


def login(request):
    if request.method == "POST":
        username = request.POST["username"]
        password = request.POST["password"]

        user = authenticate(request, username=username, password=password)

        if user is not None:
            auth_login(request, user)

            try:
                supabase = settings.SUPABASE_CLIENT
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
            return render(request, "subtemplates/login.html", {
                "username": username
            })

    return render(request, "subtemplates/login.html")


def logout(request):
    if request.user.is_authenticated:
        try:
            supabase = settings.SUPABASE_CLIENT
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
            return render(request, 'subtemplates/password_reset_sent.html')
    return render(request, 'subtemplates/forgot_password.html')


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
                return render(request, 'subtemplates/reset_password_form.html',{'validlink': True})

            user.set_password(new_password)
            user.save()
            return redirect('login')
        return render(request, 'subtemplates/reset_password_form.html', {'validlink': True})
    else:
        return render(request, 'subtemplates/reset_password_form.html', {'validlink': False})

# --- Dashboards with PrintJob / Invoice integration ---
@login_required(login_url='login')
def staff_dashboard(request):
    if not request.user.is_staff:
        return redirect('student_dashboard')

    # print_jobs = PrintJob.objects.all().order_by('-submitted_at')
    # invoices = Invoice.objects.all().order_by('-created_at')
    # pending_count = PrintJob.objects.filter(status='Pending').count()
    # pending_invoices_count = Invoice.objects.filter(status='Pending').count()

    context = {
        'user': request.user,
        # 'print_jobs': print_jobs,
        # 'invoices': invoices,
        # 'pending_count': pending_count,
        # 'pending_invoices_count': pending_invoices_count,
    }

    return render(request, 'subtemplates/staff_dashboard.html', context)

MAX_PREVIEW_SIZE = 10 * 1024 * 1024  # 10 MB

PRICING = {
    'bw': 1.00,  # ₱1.00 per page for Black & White
    'color': 5.00,  # ₱5.00 per page for Color
}
@login_required(login_url='login')
@never_cache
def student_dashboard(request: HttpRequest) -> HttpResponse:
    context = {
        'pdf_data': request.session.get('pdf_data'),
        'file_name': request.session.get('file_name'),
        'total_pages': request.session.get('total_pages'),
        'form_data': {},
        'total_cost': None,
    }

    # === FETCH JOBS FROM SUPABASE ===
    jobs_resp = supabase.table('print_jobs')\
        .select('*')\
        .eq('user_id', request.user.id)\
        .order('submitted_at', desc=True)\
        .execute()
    jobs = jobs_resp.data or []
    context.update({
        'print_jobs': jobs,
        'latest_job': jobs[0] if jobs else None,
    })

    if request.method == 'POST':
        action = request.POST.get('action')

        # --- MANUAL UPLOAD: Preview only (no Supabase) ---
        if 'print_file' in request.FILES:
            file = request.FILES['print_file']
            if not file.name.lower().endswith('.pdf'):
                messages.error(request, "Only PDF files allowed.")
                return redirect('student_dashboard')

            # File size limit: 25 MB
            if file.size > 25 * 1024 * 1024:
                messages.error(request, "File size must be 25 MB or less.")
                return redirect('student_dashboard')

            # Count pages
            pdf_file = BytesIO(file.read())
            reader = PyPDF2.PdfReader(pdf_file)
            page_count = len(reader.pages)

            # Save to session for preview
            pdf_file.seek(0)
            request.session['pdf_data'] = base64.b64encode(pdf_file.read()).decode()
            request.session['file_name'] = file.name
            request.session['total_pages'] = page_count

            messages.success(request, "File preview ready.")
            return redirect('student_dashboard')

        # --- CLEAR ALL ---
        if action == 'clear':
            for k in ['pdf_data', 'file_name', 'total_pages']:
                request.session.pop(k, None)
            return redirect('student_dashboard')

        # --- PRESERVE FORM ---
        context['form_data'] = {
            'pages': request.session.get('total_pages'),
            'paper_size': request.POST.get('paper_size'),
            'color_option': request.POST.get('color_option'),
        }

        # --- CALCULATE COST ---
        if action == 'calculate':
            pages = context['form_data']['pages']
            paper = context['form_data']['paper_size']
            color = context['form_data']['color_option']

            if not all([pages, paper, color]):
                messages.error(request, "Fill all fields.")
            else:
                price = PRICING.get(color, 0)
                total = price * int(pages)
                context['total_cost'] = f"{total:.2f}"

        # --- SUBMIT JOB: Upload to Supabase ---
        if action == 'submit_job':
            if not request.session.get('pdf_data'):
                messages.error(request, "Upload a file first.")
                return redirect('student_dashboard')

            # Reconstruct file from session
            pdf_data = base64.b64decode(request.session['pdf_data'])
            file_name = request.session['file_name']
            page_count = request.session['total_pages']

            # Upload to Supabase
            file_id = str(uuid.uuid4())
            path = f"{request.user.id}/{file_id}/{file_name}"
            supabase.storage.from_(bucket).upload(
                path, pdf_data, {'content-type': 'application/pdf'}
            )
            file_url = supabase.storage.from_(bucket).get_public_url(path)

            # Save job
            job_data = {
                'user_id': request.user.id,
                'username': request.user.username,
                'file_name': file_name,
                'file_url': file_url,
                'pages': page_count,
                'paper_size': context['form_data']['paper_size'],
                'color_option': context['form_data']['color_option'],
                'total_cost': context['total_cost'] or 0.0,
                'status': 'Pending',
                'submitted_at': 'now()'
            }
            supabase.table('print_jobs').insert(job_data).execute()

            messages.success(request, "Job submitted!")
            for k in ['pdf_data', 'file_name', 'total_pages']:
                request.session.pop(k, None)
            return redirect('student_dashboard')

        # --- CANCEL JOB ---
        if action == 'cancel_job':
            job_id = request.POST.get('job_id')
            job_resp = supabase.table('print_jobs')\
                .select('*')\
                .eq('id', job_id)\
                .eq('user_id', request.user.id)\
                .execute()
            job = job_resp.data[0] if job_resp.data else None

            if job and job['status'] == 'Pending':
                # Delete file
                path = '/'.join(job['file_url'].split('/')[-2:])
                supabase.storage.from_(bucket).remove([path])
                # Delete record
                supabase.table('print_jobs').delete().eq('id', job_id).execute()
                messages.success(request, "Job cancelled.")
            else:
                messages.error(request, "Cannot cancel.")
            return redirect('student_dashboard')

    else:
        if not request.session.get('pdf_data'):
            for k in ['pdf_data', 'file_name', 'total_pages']:
                request.session.pop(k, None)

    return render(request, 'subtemplates/student_dashboard.html', context)

# ──────── API for modal ─────────
def get_job_detail(request, job_id):
    resp = supabase.table('print_jobs').select('*').eq('id', str(job_id)).execute()
    if resp.data:
        return JsonResponse(resp.data[0])
    return JsonResponse({'error': 'Not found'}, status=404)