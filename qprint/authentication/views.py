import random
import time
from datetime import datetime, timedelta
import secrets
import os
import uuid
import base64
import PyPDF2
from io import BytesIO
import pytz
import time

from django.http import JsonResponse, HttpRequest, HttpResponse
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
from django.views.decorators.cache import never_cache
from sendgrid import SendGridAPIClient
from sendgrid.helpers.mail import Mail
from django.utils import timezone
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from reportlab.lib.units import inch

supabase = settings.SUPABASE_CLIENT
bucket = settings.SUPABASE_BUCKET

MAX_PREVIEW_SIZE = 25 * 1024 * 1024  # 25 MB

PRICING_CONFIG = {
    'paper_type': {
        'standard': 0.00,
        'colored': 5.00,
        'glossy': 10.00
    },
    'paper_size': {
        'A4': 0.00,
        'Letter': 0.00,
        'Long': 1.00
    },
    'color_option': {
        'bw': 1.00,
        'color': 2.00
    }
}


# ===== NEW HELPER FUNCTIONS =====
def get_unpaid_invoices(jobs):
    """Get truly unpaid invoices (excluding pending review, completed, ready, cancelled)"""
    unpaid = []
    for job in jobs:
        # Skip cancelled jobs
        if job.get('status') == 'Cancelled':
            continue

        # Skip jobs that are paid or payment is accepted
        if job.get('is_paid') or job.get('payment_status') in ['Accepted', 'Paid']:
            continue

        # Skip completed and ready jobs
        if job.get('status') in ['Completed', 'Ready', 'On Queue']:
            continue

        # Skip jobs pending verification (payment proof uploaded)
        if job.get('status') in ['Verifying', 'Pending Review']:
            continue

        unpaid.append(job)
    return unpaid


def calculate_price_breakdown(job):
    """Calculate price breakdown for a job (shared function)"""
    p_type = job.get('paper_type') or 'standard'
    p_size = job.get('paper_size') or 'A4'
    c_opt = job.get('color_option') or 'bw'
    pages = job.get('pages') or 0

    cost_pt = PRICING_CONFIG['paper_type'].get(p_type, 0.0)
    cost_ps = PRICING_CONFIG['paper_size'].get(p_size, 0.0)
    cost_co = PRICING_CONFIG['color_option'].get(c_opt, 0.0)

    type_labels = {'standard': 'Standard', 'colored': 'Colored', 'glossy': 'Glossy'}
    color_labels = {'bw': 'Black & White', 'color': 'Colored'}

    unit_price = cost_pt + cost_ps + cost_co
    total = unit_price * pages

    return {
        'paper_type': p_type,
        'paper_type_label': type_labels.get(p_type, p_type.title()),
        'paper_type_cost': cost_pt,
        'paper_size': p_size,
        'paper_size_label': p_size,
        'paper_size_cost': cost_ps,
        'color_option': c_opt,
        'color_label': color_labels.get(c_opt, c_opt.title()),
        'color_cost': cost_co,
        'pages': pages,
        'unit_price': unit_price,
        'total': total,
        'formula': f'({cost_pt} + {cost_ps} + {cost_co}) × {pages}'
    }


# ===== END NEW HELPER FUNCTIONS =====

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
        f"If you didn't request this, please ignore this email."
    )

    email_message = Mail(
        from_email="qprintapp@gmail.com",
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
        plain_text_content=f"Hello,\n\nYour OTP is: {otp}\n\nIf you didn't request this, ignore this email.",
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


@login_required
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

        storage = messages.get_messages(request)
        storage.used = True

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
                return render(request, 'subtemplates/reset_password_form.html', {'validlink': True})

            user.set_password(new_password)
            user.save()
            return redirect('login')
        return render(request, 'subtemplates/reset_password_form.html', {'validlink': True})
    else:
        return render(request, 'subtemplates/reset_password_form.html', {'validlink': False})


@login_required(login_url='login')
def staff_dashboard(request):
    if not request.user.is_staff:
        return redirect('student_dashboard')

    update_overdue_invoices()

    jobs_resp = supabase.table('print_jobs') \
        .select('*') \
        .neq('status', 'Completed') \
        .eq('show_in_active', True) \
        .order('submitted_at', desc=True) \
        .execute()


    jobs = jobs_resp.data or []

    # Extract only date parts for display
    for job in jobs:
        for date_field in ['submitted_at', 'invoice_date', 'due_date']:
            date_str = job.get(date_field)
            if date_str:
                try:
                    if 'T' in date_str:
                        date_part = date_str.split('T')[0]
                        job[date_field] = date_part
                    elif ' ' in date_str:
                        date_part = date_str.split(' ')[0]
                        job[date_field] = date_part
                    else:
                        if len(date_str) >= 10:
                            job[date_field] = date_str[:10]
                except:
                    pass

    active_sorts = request.GET.getlist('sort')

    if not active_sorts:
        active_sorts = ['newest']

    # Sort by date strings (YYYY-MM-DD format)
    if 'oldest' in active_sorts:
        jobs.sort(key=lambda x: x.get('submitted_at') or '', reverse=False)
    elif 'newest' in active_sorts:
        jobs.sort(key=lambda x: x.get('submitted_at') or '', reverse=True)
    else:
        jobs.sort(key=lambda x: x.get('submitted_at') or '', reverse=True)

    if 'user_az' in active_sorts:
        jobs.sort(key=lambda x: x['username'].lower())

    if 'largest_job' in active_sorts:
        jobs.sort(key=lambda x: x['pages'], reverse=True)
    if 'smallest_job' in active_sorts:
        jobs.sort(key=lambda x: x['pages'])
    if 'color_only' in active_sorts:
        jobs.sort(key=lambda x: (x['color_option'] != 'color'))
    if 'paper_glossy' in active_sorts:
        jobs.sort(key=lambda x: (x.get('paper_type') != 'glossy'))

    if 'unpaid' in active_sorts:
        jobs.sort(key=lambda x: (x['status'] not in ['Unpaid', 'Overdue']))
    if 'ready_print' in active_sorts:
        jobs.sort(key=lambda x: (x['payment_status'] != 'Accepted'))
    if 'pending_payment' in active_sorts:
        jobs.sort(key=lambda x: (x['payment_status'] != 'Pending Review'))

    sort_labels = {
        'newest': 'Newest First', 'oldest': 'Oldest First',
        'pending_payment': 'Pending Review', 'ready_print': 'Ready to Print',
        'unpaid': 'Unpaid / Overdue', 'paper_glossy': 'Glossy Paper',
        'color_only': 'Color Jobs', 'smallest_job': 'Smallest First',
        'largest_job': 'Largest First', 'user_az': 'User A-Z'
    }

    active_filters = []
    for sort_key in active_sorts:
        if sort_key == 'newest' and len(active_sorts) == 1:
            continue

        if sort_key in sort_labels:
            remaining_sorts = [s for s in active_sorts if s != sort_key]
            if remaining_sorts:
                query_string = "&".join([f"sort={s}" for s in remaining_sorts])
                remove_url = f"?{query_string}"
            else:
                remove_url = request.path

            active_filters.append({
                'label': sort_labels[sort_key],
                'remove_url': remove_url
            })

    context = {
        'user': request.user,
        'print_jobs': jobs,
        'current_sorts': active_sorts,
        'active_filters': active_filters,
    }

    return render(request, 'subtemplates/staff_dashboard.html', context)


@login_required
def staff_delete_job(request):
    if request.method == "POST" and request.user.is_staff:
        job_id = request.POST.get("job_id")

        
        job_resp = supabase.table('print_jobs').select('*').eq('id', job_id).execute()

        if not job_resp.data:
            messages.error(request, "Job not found.")
            return redirect('staff_dashboard')

        job = job_resp.data[0]

        
        if job.get('is_paid') is True or job.get('status') == 'Completed':
            messages.error(request, "Cannot remove a Paid or Completed job. Archive it instead.")
            return redirect('staff_dashboard')

        
        supabase.table('print_jobs').update({
            'show_in_active': False  
        }).eq('id', job_id).execute()

        messages.success(request, f"Job '{job.get('file_name')}' has been removed.")

    return redirect('staff_dashboard')


@login_required(login_url='login')
@never_cache
def student_dashboard(request: HttpRequest) -> HttpResponse:
    update_overdue_invoices(request.user.id)

    context = {
        'pdf_data': request.session.get('pdf_data'),
        'file_name': request.session.get('file_name'),
        'total_pages': request.session.get('total_pages'),
        'form_data': {},

        # Alerts
        'history_msg': request.session.pop('history_msg', None),
        'cancel_msg': request.session.pop('cancel_msg', None),
        'submission_msg': request.session.pop('submission_msg', None),
    }

    # Fetch jobs - Only show jobs that should appear in active view
    jobs_resp = supabase.table('print_jobs') \
        .select('*') \
        .eq('user_id', request.user.id) \
        .neq('status', 'Completed') \
        .eq('show_in_active', True) \
        .order('submitted_at', desc=True) \
        .execute()


    jobs = jobs_resp.data or []

    # Extract just the date part from all date fields
    for job in jobs:
        for date_field in ['submitted_at', 'invoice_date', 'due_date']:
            date_str = job.get(date_field)
            if date_str:
                try:
                    # Parse the date string
                    if 'T' in date_str:
                        # ISO format: "2025-12-09T15:48:00+08:00" or "2025-12-09T07:48:00Z"
                        date_part = date_str.split('T')[0]
                        job[date_field] = date_part
                    elif ' ' in date_str:
                        # Space-separated: "2025-12-09 15:48:00"
                        date_part = date_str.split(' ')[0]
                        job[date_field] = date_part
                    else:
                        # Already just a date or unknown format
                        # Try to get first 10 chars (YYYY-MM-DD)
                        if len(date_str) >= 10:
                            job[date_field] = date_str[:10]
                except Exception as e:
                    print(f"Error extracting date from {date_field}: {e}")
                    # If extraction fails, leave as-is

    # FIXED: Use get_unpaid_invoices() instead of old logic
    unpaid_invoices = get_unpaid_invoices(jobs)
    overdue_invoices = [job for job in jobs if job.get('status') == 'Overdue']

    # Get latest job
    latest_job = jobs[0] if jobs else None

    context.update({
        'print_jobs': jobs,
        'latest_job': latest_job,
        'unpaid_invoices': unpaid_invoices,
        'overdue_invoices': overdue_invoices,
    })

    if request.method == 'POST':
        action = request.POST.get('action')

        # --- MANUAL UPLOAD ---
        if 'print_file' in request.FILES:
            file = request.FILES['print_file']
            if not file.name.lower().endswith('.pdf'):
                messages.error(request, "Only PDF files allowed.")
                return redirect('student_dashboard')

            if file.size > MAX_PREVIEW_SIZE:
                messages.error(request, "File size must be 25 MB or less.")
                return redirect('student_dashboard')

            pdf_file = BytesIO(file.read())
            reader = PyPDF2.PdfReader(pdf_file)
            page_count = len(reader.pages)

            pdf_file.seek(0)
            request.session['pdf_data'] = base64.b64encode(pdf_file.read()).decode()
            request.session['file_name'] = file.name
            request.session['total_pages'] = page_count
            request.session['submission_msg'] = "✓ File preview ready"
            return redirect('student_dashboard')

        # --- CLEAR ---
        if action == 'clear':
            for k in ['pdf_data', 'file_name', 'total_pages']:
                request.session.pop(k, None)
            return redirect('student_dashboard')

        # --- SUBMIT JOB ---
        if action == 'submit_job':
            if not request.session.get('pdf_data'):
                messages.error(request, "Upload a file first.")
                return redirect('student_dashboard')

            if context['overdue_invoices']:
                messages.error(request, "You have overdue invoices.")
                return redirect('student_dashboard')

            pdf_data = base64.b64decode(request.session['pdf_data'])
            file_name = request.session['file_name']
            page_count = request.session['total_pages']
            total_cost_str = request.POST.get('calculated_total_cost')
            total_cost = float(total_cost_str) if total_cost_str else 0.0

            p_type = request.POST.get('paper_type')
            p_size = request.POST.get('paper_size')
            pr_type = request.POST.get('color_option')

            file_id = str(uuid.uuid4())
            path = f"{request.user.id}/{file_id}/{file_name}"
            supabase.storage.from_(bucket).upload(path, pdf_data, {'content-type': 'application/pdf'})
            file_url = supabase.storage.from_(bucket).get_public_url(path)

            invoice_number = generate_invoice_number()

            ph_tz = pytz.timezone('Asia/Manila')
            now_ph = datetime.now(ph_tz)

            due_date = now_ph + timedelta(hours=24)

            job_data = {
                'user_id': request.user.id,
                'username': request.user.username,
                'file_name': file_name,
                'file_url': file_url,
                'pages': page_count,
                'paper_type': p_type,
                'paper_size': p_size,
                'color_option': pr_type,
                'total_cost': f"{total_cost:.2f}",
                'status': 'Unpaid',
                'payment_status': 'Unpaid',
                'invoice_number': invoice_number,
                'invoice_date': now_ph.isoformat(),
                'due_date': due_date.isoformat(),
                'submitted_at': now_ph.isoformat(),
                'is_paid': False,
                'show_in_active': True,  # NEW: Show in active jobs by default
            }
            supabase.table('print_jobs').insert(job_data).execute()

            request.session['history_msg'] = f"Job '{file_name}' submitted! Invoice #{invoice_number} created."

            for k in ['pdf_data', 'file_name', 'total_pages']:
                request.session.pop(k, None)
            return redirect('student_dashboard')

        # --- CANCEL JOB ---
        if action == 'cancel_job':
            job_id = request.POST.get('job_id')
            job_resp = supabase.table('print_jobs').select('*').eq('id', job_id).eq('user_id',
                                                                                    request.user.id).execute()
            job = job_resp.data[0] if job_resp.data else None

            if job and job['status'] in ['Unpaid', 'Pending Review', 'Overdue', 'Verifying']:
                # Delete file from storage
                try:
                    path_parts = job['file_url'].split('/')[-3:]
                    file_path = "/".join(path_parts)
                    supabase.storage.from_(bucket).remove([file_path])
                except Exception as e:
                    print(f"Error deleting file: {e}")

                # Update job status to Cancelled
                supabase.table('print_jobs').update({'status': 'Cancelled'}).eq('id', job_id).execute()
                request.session['cancel_msg'] = f"Cancelled '{job['file_name']}' successfully."

                # Also update payment status if it's overdue
                if job['status'] == 'Overdue':
                    supabase.table('print_jobs').update({
                        'payment_status': 'Cancelled',
                        'is_paid': False
                    }).eq('id', job_id).execute()
            else:
                messages.error(request,
                               f"Cannot cancel this job. Current status: {job['status'] if job else 'Unknown'}")
            return redirect('student_dashboard')

        # --- UPLOAD PROOF ---
        if action == 'upload_payment_proof_modal':
            job_id = request.POST.get('job_id')
            img = request.FILES.get("payment_proof")

            if img:
                proof_id = str(uuid.uuid4())
                proof_path = f"{request.user.id}/{proof_id}/{img.name}"
                supabase.storage.from_(bucket).upload(proof_path, img.read(), {"content-type": img.content_type})
                proof_url = supabase.storage.from_(bucket).get_public_url(proof_path)

                supabase.table("print_jobs").update({
                    "payment_proof_url": proof_url,
                    "payment_status": "Verifying",
                    "status": "Verifying",
                }).eq("id", job_id).execute()
            return redirect("student_dashboard")

    else:
        if not request.session.get('pdf_data'):
            for k in ['pdf_data', 'file_name', 'total_pages']:
                request.session.pop(k, None)

    return render(request, 'subtemplates/student_dashboard.html', context)


def get_job_detail(request, job_id):
    resp = supabase.table('print_jobs').select('*').eq('id', str(job_id)).execute()
    if resp.data:
        job = resp.data[0]

        # Extract only the date part (no time)
        if job.get('invoice_date'):
            try:
                dt = datetime.fromisoformat(job['invoice_date'])  # No replace needed
                job['invoice_date_formatted'] = dt.strftime("%b %d, %Y")  # Removed %H:%M
            except:
                job['invoice_date_formatted'] = job['invoice_date'][:10]  # Just show YYYY-MM-DD

        if job.get('due_date'):
            try:
                dt = datetime.fromisoformat(job['due_date'])  # No replace needed
                job['due_date_formatted'] = dt.strftime("%b %d, %Y")  # Removed %H:%M
            except:
                job['due_date_formatted'] = job['due_date'][:10]  # Just show YYYY-MM-DD

        if job.get('submitted_at'):
            try:
                dt = datetime.fromisoformat(job['submitted_at'])  # No replace needed
                job['submitted_at_formatted'] = dt.strftime("%b %d, %Y")  # Removed %H:%M
            except:
                job['submitted_at_formatted'] = job['submitted_at'][:10]  # Just show YYYY-MM-DD

        # Use the shared price breakdown function
        breakdown = calculate_price_breakdown(job)
        job.update(breakdown)

        return JsonResponse(job)
    return JsonResponse({'error': 'Not found'}, status=404)


# INVOICE MANAGEMENT VIEWS
@login_required
def view_invoice(request, job_id):
    job_resp = supabase.table('print_jobs') \
        .select('*') \
        .eq('id', job_id) \
        .eq('user_id', request.user.id) \
        .execute()  # NO filter for show_in_active

    if not job_resp.data:
        messages.error(request, "Invoice not found")
        return redirect('student_dashboard')

    job = job_resp.data[0]

    # Extract only date parts for display
    for date_field in ['submitted_at', 'invoice_date', 'due_date']:
        date_str = job.get(date_field)
        if date_str:
            try:
                if 'T' in date_str:
                    date_part = date_str.split('T')[0]
                    job[date_field] = date_part
                elif ' ' in date_str:
                    date_part = date_str.split(' ')[0]
                    job[date_field] = date_part
                else:
                    if len(date_str) >= 10:
                        job[date_field] = date_str[:10]
            except:
                pass

    can_print, print_message = check_print_eligibility(job)

    context = {
        'invoice': job,
        'now': datetime.now(),
        'can_print': can_print,
        'print_message': print_message,
        'is_overdue': job.get('status') == 'Overdue'
    }
    return render(request, 'subtemplates/invoice_detail.html', context)


@login_required
def invoice_list(request):
    invoices_resp = supabase.table('print_jobs') \
        .select('*') \
        .eq('user_id', request.user.id) \
        .order('invoice_date', desc=True) \
        .execute()  # NO filter for show_in_active - show ALL invoices

    invoices = invoices_resp.data or []

    # Extract just the date part from all date fields
    for invoice in invoices:
        for date_field in ['invoice_date', 'due_date', 'submitted_at']:
            date_str = invoice.get(date_field)
            if date_str:
                try:
                    # Parse the date string
                    if 'T' in date_str:
                        date_part = date_str.split('T')[0]
                        invoice[date_field] = date_part
                    elif ' ' in date_str:
                        date_part = date_str.split(' ')[0]
                        invoice[date_field] = date_part
                    else:
                        if len(date_str) >= 10:
                            invoice[date_field] = date_str[:10]
                except Exception as e:
                    print(f"Error extracting date from {date_field}: {e}")

    # FIXED: Use get_unpaid_invoices() for accurate statistics
    stats = {
        'total': len(invoices),
        'paid': len([inv for inv in invoices if inv.get('is_paid')]),
        'unpaid': len(get_unpaid_invoices(invoices)),
        'overdue': len([inv for inv in invoices if inv.get('status') == 'Overdue']),
        'rejected': len([inv for inv in invoices if inv.get('payment_status') == 'Rejected']),
    }

    context = {
        'invoices': invoices,
        'stats': stats
    }
    return render(request, 'subtemplates/invoice_list.html', context)


@login_required
def staff_update_payment(request):
    if request.method == "POST" and request.user.is_staff:
        job_id = request.POST.get("job_id")
        action = request.POST.get("action")

        # Acceptance logic
        if action == "accept":
            new_payment_status = "Accepted"
            is_paid = True
            job_status = "On Queue"

            # Rejection logic
        elif action == "reject":
            new_payment_status = "Rejected"
            is_paid = False
            job_status = "Unpaid"

        else:
            messages.error(request, "Invalid action.")
            return redirect("staff_dashboard")

        supabase.table("print_jobs").update({
            "payment_status": new_payment_status,
            "is_paid": is_paid,
            "status": job_status
        }).eq("id", job_id).execute()

        return redirect("staff_dashboard")


@login_required
def staff_confirm_job(request):
    if request.method == "POST" and request.user.is_staff:
        job_id = request.POST.get("job_id")

        # --- 1. SPAM PREVENTION (30 Seconds) ---
        cooldown_key = f"notify_cooldown_{job_id}"
        last_sent = request.session.get(cooldown_key, 0)
        current_time = time.time()

        if current_time - last_sent < 30:
            remaining = int(30 - (current_time - last_sent))
            messages.warning(request, f"Please wait {remaining}s before sending another email.")
            return redirect("staff_dashboard")

        # Fetch Data
        job_resp = supabase.table("print_jobs").select("*").eq("id", job_id).execute()
        if not job_resp.data:
            messages.error(request, "Job not found.")
            return redirect("staff_dashboard")

        job = job_resp.data[0]

        if job["payment_status"] != "Accepted" or not job.get("is_paid"):
            messages.error(request, "Cannot confirm. Payment has not been accepted.")
            return redirect("staff_dashboard")

        # Check valid status
        if job["status"] not in ["Pending", "On Queue", "Ready"]:
            messages.error(request, "Job must be 'On Queue' or 'Ready' to notify user.")
            return redirect("staff_dashboard")

        # --- 2. GET EMAIL ---
        student_email = None
        try:
            student_user = User.objects.get(id=job['user_id'])
            student_email = student_user.email
        except User.DoesNotExist:
            print("Student user not found.")

        # --- 3. EXECUTE ---
        if job["status"] == "Ready":
            if student_email:
                send_ready_email(student_email, job['file_name'], is_reminder=True)

            messages.success(request, "Reminder email sent.")
            request.session[cooldown_key] = current_time

        else:
            supabase.table("print_jobs").update({"status": "Ready"}).eq("id", job_id).execute()

            if student_email:
                send_ready_email(student_email, job['file_name'], is_reminder=False)

            messages.success(request, "Job Ready. Email sent.")
            request.session[cooldown_key] = current_time

        return redirect("staff_dashboard")


@login_required
def check_print_status(request, job_id):
    """API endpoint to check if a job can be printed"""
    job_resp = supabase.table('print_jobs') \
        .select('*') \
        .eq('id', job_id) \
        .eq('user_id', request.user.id) \
        .execute()

    if not job_resp.data:
        return JsonResponse({'error': 'Job not found'}, status=404)

    job = job_resp.data[0]
    can_print, message = check_print_eligibility(job)

    return JsonResponse({
        'can_print': can_print,
        'message': message,
        'status': job.get('status'),
        'is_paid': job.get('is_paid')
    })


@login_required
def student_delete_job(request):
    """Allows student to remove a job from active jobs ONLY if it is Cancelled"""
    if request.method == "POST":
        job_id = request.POST.get("job_id")

        # 1. Fetch Job
        job_resp = supabase.table('print_jobs') \
            .select('*') \
            .eq('id', job_id) \
            .eq('user_id', request.user.id) \
            .execute()

        if job_resp.data:
            job = job_resp.data[0]

            # 2. STRICT CHECK: Must be 'Cancelled'
            if job.get('status') == 'Cancelled':
                # Hide from active jobs but keep in database
                supabase.table('print_jobs').update({
                    'show_in_active': False  # Hide from active view
                }).eq('id', job_id).execute()

                request.session['cancel_msg'] = f"Removed '{job['file_name']}' from active jobs. It will still appear in your invoices."
            else:
                messages.error(request, "Only cancelled jobs can be removed from active jobs.")

    return redirect('student_dashboard')


# --- Invoice System Functions ---
def generate_invoice_number():
    date_part = datetime.now().strftime("%Y%m%d")
    random_part = secrets.token_hex(3).upper()
    return f"INV-{date_part}-{random_part}"


def check_print_eligibility(job):
    if job.get('is_paid') == False:
        return False, "Invoice unpaid - please complete payment first"
    elif job.get('status') == 'Verifying':
        return False, "Payment pending review"
    elif job.get('status') == 'Cancelled':
        return False, "Job was cancelled"
    elif job.get('status') == 'Overdue':
        return False, "Payment overdue - please contact support"
    return True, "Eligible for printing"


@login_required
def staff_complete_job(request):
    if request.method == "POST" and request.user.is_staff:
        job_id = request.POST.get("job_id")
        action = request.POST.get("action")

        job_resp = supabase.table("print_jobs").select("status").eq("id", job_id).execute()
        if not job_resp.data:
            messages.error(request, "Job not found.")
            return redirect("staff_dashboard")

        job = job_resp.data[0]

        if action == "mark_completed":
            new_status = "Completed"
        elif action == "unmark_completed":
            new_status = "Ready"
        else:
            return redirect("staff_dashboard")

        supabase.table("print_jobs").update({"status": new_status}).eq("id", job_id).execute()

        return redirect(request.META.get('HTTP_REFERER', 'staff_dashboard'))

    return redirect("staff_dashboard")


def update_overdue_invoices(user_id=None):
    now = timezone.now().isoformat()
    query = supabase.table('print_jobs') \
        .update({'status': 'Overdue'}) \
        .eq('is_paid', False) \
        .lt('due_date', now) \
        .eq('status', 'Unpaid')

    if user_id:
        query = query.eq('user_id', user_id)

    query.execute()


@login_required
def print_job_history(request):
    jobs_resp = supabase.table('print_jobs') \
        .select('*') \
        .eq('user_id', request.user.id) \
        .eq('status', 'Completed') \
        .order('submitted_at', desc=True) \
        .execute()

    completed_jobs = jobs_resp.data or []

    # Extract just the date part
    for job in completed_jobs:
        for date_field in ['submitted_at', 'invoice_date', 'due_date']:
            date_str = job.get(date_field)
            if date_str:
                try:
                    if 'T' in date_str:
                        date_part = date_str.split('T')[0]
                        job[date_field] = date_part
                    elif ' ' in date_str:
                        date_part = date_str.split(' ')[0]
                        job[date_field] = date_part
                    else:
                        if len(date_str) >= 10:
                            job[date_field] = date_str[:10]
                except:
                    pass

    return render(request, 'subtemplates/print_job_history.html', {
        'completed_jobs': completed_jobs
    })


@login_required
def staff_job_history(request):
    if not request.user.is_staff:
        return redirect('student_dashboard')
    jobs_resp = supabase.table('print_jobs') \
        .select('*') \
        .eq('status', 'Completed') \
        .order('submitted_at', desc=True) \
        .execute()

    completed_jobs = jobs_resp.data or []

    # Extract just the date part
    for job in completed_jobs:
        for date_field in ['submitted_at', 'invoice_date', 'due_date']:
            date_str = job.get(date_field)
            if date_str:
                try:
                    if 'T' in date_str:
                        date_part = date_str.split('T')[0]
                        job[date_field] = date_part
                    elif ' ' in date_str:
                        date_part = date_str.split(' ')[0]
                        job[date_field] = date_part
                    else:
                        if len(date_str) >= 10:
                            job[date_field] = date_str[:10]
                except:
                    pass

    return render(request, 'subtemplates/staff_job_history.html', {
        'completed_jobs': completed_jobs
    })


def send_ready_email(email, filename, is_reminder=False):
    subject = "Reminder: Your Print Job is Ready!" if is_reminder else "Your Print Job is Ready!"

    body = (
        f"Hello,\n\n"
        f"Good news! Your document '{filename}' is printed and ready for pickup.\n"
        f"Please head to the printing station to collect it.\n\n"
        f"Thank you for using QPrint."
    )

    message = Mail(
        from_email="qprintapp@gmail.com",
        to_emails=email,
        subject=subject,
        plain_text_content=body,
    )

    try:
        sg = SendGridAPIClient(os.getenv("SENDGRID_API_KEY"))
        sg.send(message)
    except Exception as e:
        print(f"SendGrid error: {e}")

@login_required
def download_receipt(request, job_id):
    # Get the invoice/job
    job_resp = supabase.table('print_jobs') \
        .select('*') \
        .eq('id', job_id) \
        .eq('user_id', request.user.id) \
        .execute()

    if not job_resp.data:
        return HttpResponse("Receipt not found", status=404)

    job = job_resp.data[0]

    # Create PDF
    buffer = BytesIO()
    p = canvas.Canvas(buffer, pagesize=letter)
    width, height = letter

    # Title
    p.setFont("Helvetica-Bold", 24)
    p.drawString(1 * inch, height - 1 * inch, "QPRINT RECEIPT")

    # Invoice Number
    p.setFont("Helvetica", 12)
    p.drawString(1 * inch, height - 1.5 * inch, f"Invoice: {job.get('invoice_number', 'N/A')}")
    p.drawString(1 * inch, height - 1.75 * inch, f"Date: {job.get('invoice_date', '')[:10]}")
    p.drawString(1 * inch, height - 2 * inch, f"Status: {job.get('status', 'N/A')}")

    # Job Details
    p.setFont("Helvetica-Bold", 14)
    p.drawString(1 * inch, height - 2.5 * inch, "Job Details:")
    p.setFont("Helvetica", 12)

    y = height - 2.75 * inch
    details = [
        f"Document: {job.get('file_name', 'N/A')}",
        f"Pages: {job.get('pages', 0)}",
        f"Paper: {job.get('paper_size', 'N/A')} ({job.get('paper_type', 'Standard')})",
        f"Color: {'Color' if job.get('color_option') == 'color' else 'Black & White'}",
    ]

    for detail in details:
        p.drawString(1.2 * inch, y, detail)
        y -= 0.25 * inch

    # Payment Info
    p.setFont("Helvetica-Bold", 14)
    p.drawString(1 * inch, y - 0.25 * inch, "Payment Information:")
    p.setFont("Helvetica", 12)

    y -= 0.5 * inch
    payment_details = [
        f"Payment Status: {job.get('payment_status', 'N/A')}",
        f"Total Amount: ₱{job.get('total_cost', '0.00')}",
        f"Paid: {'Yes' if job.get('is_paid') else 'No'}",
    ]

    for detail in payment_details:
        p.drawString(1.2 * inch, y, detail)
        y -= 0.25 * inch

    # Footer
    p.setFont("Helvetica-Oblique", 10)
    p.drawString(1 * inch, 0.5 * inch, "Thank you for using QPrint!")
    p.drawString(1 * inch, 0.25 * inch, "Generated: " + datetime.now().strftime("%Y-%m-%d %H:%M"))

    p.showPage()
    p.save()

    buffer.seek(0)

    # Create response
    response = HttpResponse(buffer, content_type='application/pdf')
    response[
        'Content-Disposition'] = f'attachment; filename="QPrint_Receipt_{job.get("invoice_number", "receipt")}.pdf"'

    return response
