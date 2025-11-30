from datetime import datetime, timedelta
import pytz
from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth.decorators import login_required

supabase = settings.SUPABASE_CLIENT
bucket = settings.SUPABASE_BUCKET


@login_required(login_url='login')
def revenue_dashboard(request):
    if not request.user.is_staff:
        return redirect('student_dashboard')

    jobs_resp = supabase.table('print_jobs') \
        .select('*') \
        .eq('status', 'Completed') \
        .execute()

    jobs = jobs_resp.data or []

    ph_tz = pytz.timezone('Asia/Manila')
    now_ph = datetime.now(ph_tz)

    start_of_today = now_ph.replace(hour=0, minute=0, second=0, microsecond=0)

    start_of_week = start_of_today - timedelta(days=start_of_today.weekday())

    start_of_month = start_of_today.replace(day=1)

    total_revenue = 0.0
    revenue_today = 0.0
    revenue_week = 0.0
    revenue_month = 0.0

    for job in jobs:
        try:
            cost = float(job.get('total_cost', 0))
            submitted_at_str = job.get('submitted_at')

            if submitted_at_str:
                dt_obj = datetime.fromisoformat(submitted_at_str.replace('Z', '+00:00'))

                job_time_ph = dt_obj.astimezone(ph_tz)

                total_revenue += cost

                if job_time_ph >= start_of_today:
                    revenue_today += cost

                if job_time_ph >= start_of_week:
                    revenue_week += cost

                if job_time_ph >= start_of_month:
                    revenue_month += cost

        except (ValueError, TypeError):
            continue

    total_jobs = len(jobs)

    def format_revenue(value):
        return f"₱{value:,.2f}" if value > 0 else "No Revenue Recorded"

    context = {
        'total_revenue': format_revenue(total_revenue),
        'total_jobs': total_jobs,
        'revenue_today': format_revenue(revenue_today),
        'revenue_week': format_revenue(revenue_week),
        'revenue_month': format_revenue(revenue_month),
    }

    return render(request, 'subtemplates/revenue_dashboard.html', context)