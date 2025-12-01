from datetime import datetime, timedelta
from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.conf import settings


supabase = settings.SUPABASE_CLIENT
bucket = settings.SUPABASE_BUCKET

@login_required(login_url='login')
def revenue_dashboard(request):
    if not request.user.is_staff:
        return redirect('student_dashboard')

    jobs_resp = supabase.table('print_jobs') \
        .select('*') \
        .in_('status', ['Completed']) \
        .execute()

    jobs = jobs_resp.data or []

    total_revenue = sum(float(job.get('total_cost', 0)) for job in jobs)
    total_jobs = len(jobs)

    today_str = datetime.now().strftime('%Y-%m-%d')
    revenue_today = sum(
        float(job.get('total_cost', 0))
        for job in jobs
        if job.get('submitted_at', '').startswith(today_str)
    )

    today = datetime.now()
    start_of_week = today - timedelta(days=today.weekday())
    revenue_week = sum(
        float(job.get('total_cost', 0))
        for job in jobs
        if job.get('submitted_at') and datetime.fromisoformat(job['submitted_at'].split('T')[0]) >= start_of_week
    )

    start_of_month = today.replace(day=1)
    revenue_month = sum(
        float(job.get('total_cost', 0))
        for job in jobs
        if job.get('submitted_at') and datetime.fromisoformat(job['submitted_at'].split('T')[0]) >= start_of_month
    )

    def format_revenue(value):
        return f"${value:.2f}" if value > 0 else "No Revenue Recorded"

    context = {
        'total_revenue': format_revenue(total_revenue),
        'total_jobs': total_jobs,
        'revenue_today': format_revenue(revenue_today),
        'revenue_week': format_revenue(revenue_week),
        'revenue_month': format_revenue(revenue_month),
    }

    return render(request, 'subtemplates/revenue_dashboard.html', context)
