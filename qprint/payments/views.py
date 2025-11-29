from datetime import datetime
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
        .in_('status', ['Ready', 'Paid']) \
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

    context = {
        'total_revenue': f"{total_revenue:.2f}",
        'total_jobs': total_jobs,
        'revenue_today': f"{revenue_today:.2f}",
    }

    return render(request, 'subtemplates/revenue_dashboard.html', context)
