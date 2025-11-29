from datetime import datetime
from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.conf import settings


supabase = settings.SUPABASE_CLIENT
bucket = settings.SUPABASE_BUCKET

@login_required
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

    revenue_by_color = {}
    for job in jobs:
        color = job.get('color_option', 'Unknown')
        revenue_by_color[color] = revenue_by_color.get(color, 0) + float(job.get('total_cost', 0))

    revenue_by_paper = {}
    for job in jobs:
        paper = job.get('paper_size', 'Unknown')
        revenue_by_paper[paper] = revenue_by_paper.get(paper, 0) + float(job.get('total_cost', 0))

    revenue_by_day = {}
    for job in jobs:
        submitted = job.get('submitted_at')
        if submitted:
            try:
                date_obj = datetime.fromisoformat(submitted.split('T')[0])
                day_str = date_obj.strftime('%Y-%m-%d')
            except Exception:
                day_str = submitted
            revenue_by_day[day_str] = revenue_by_day.get(day_str, 0) + float(job.get('total_cost', 0))

    context = {
        'total_revenue': f"{total_revenue:.2f}",
        'total_jobs': total_jobs,
        'revenue_by_color': revenue_by_color,
        'revenue_by_paper': revenue_by_paper,
        'revenue_by_day': revenue_by_day,
        'jobs': jobs,
    }

    return render(request, 'subtemplates/revenue_dashboard.html', context)
