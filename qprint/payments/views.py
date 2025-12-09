from datetime import datetime, timedelta
from dateutil.relativedelta import relativedelta
import pytz
from django.shortcuts import render, redirect
from django.conf import settings
from django.contrib.auth.decorators import login_required

supabase = settings.SUPABASE_CLIENT


@login_required(login_url='login')
def analytics_dashboard(request):
    """Combined analytics dashboard with weekly/monthly views"""
    if not request.user.is_staff:
        return redirect('student_dashboard')

    # Get timezone
    ph_tz = pytz.timezone('Asia/Manila')
    now_ph = datetime.now(ph_tz)

    # Get period type and offset from query parameters
    period_type = request.GET.get('period', 'weekly')  # 'weekly' or 'monthly'

    try:
        period_offset = int(request.GET.get('offset', 0))  # 0 = current period
    except ValueError:
        period_offset = 0

    # Calculate date range based on period type
    if period_type == 'weekly':
        # Weekly period (Monday to Sunday)
        target_date = now_ph + timedelta(weeks=period_offset)
        start_of_period = target_date - timedelta(days=target_date.weekday())  # Monday
        end_of_period = start_of_period + timedelta(days=6)  # Sunday

        # For monthly comparison
        prev_start_date = start_of_period - timedelta(weeks=1)
        prev_end_date = end_of_period - timedelta(weeks=1)

        # Period label
        period_label = f"Week {start_of_period.isocalendar()[1]}"
        period_range = f"{start_of_period.strftime('%b %d')} - {end_of_period.strftime('%b %d')}"

        # Chart labels (days of week)
        chart_labels = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']

    else:  # monthly
        # Monthly period
        target_date = now_ph + relativedelta(months=period_offset)
        start_of_period = target_date.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

        # Get last day of month
        if target_date.month == 12:
            end_of_period = target_date.replace(year=target_date.year + 1, month=1, day=1) - timedelta(days=1)
        else:
            end_of_period = target_date.replace(month=target_date.month + 1, day=1) - timedelta(days=1)

        end_of_period = end_of_period.replace(hour=23, minute=59, second=59, microsecond=999999)

        # For monthly comparison
        prev_start_date = start_of_period - relativedelta(months=1)
        prev_end_date = end_of_period - relativedelta(months=1)

        # Period label
        period_label = start_of_period.strftime('%B %Y')
        period_range = f"{start_of_period.strftime('%b %d')} - {end_of_period.strftime('%b %d')}"

        # Chart labels (weeks of month)
        chart_labels = ['Week 1', 'Week 2', 'Week 3', 'Week 4', 'Week 5']

    # Adjust to get full time range
    start_date = start_of_period.replace(hour=0, minute=0, second=0, microsecond=0)
    end_date = end_of_period.replace(hour=23, minute=59, second=59, microsecond=999999)

    # Query print jobs from this period
    jobs_resp = supabase.table('print_jobs') \
        .select('*') \
        .gte('submitted_at', start_date.isoformat()) \
        .lte('submitted_at', end_date.isoformat()) \
        .execute()

    jobs = jobs_resp.data or []

    # Initialize data structures
    if period_type == 'weekly':
        # For weekly: daily breakdown
        daily_data = {day: {'jobs': 0, 'revenue': 0.0} for day in chart_labels}

        for job in jobs:
            submitted_at_str = job.get('submitted_at')
            if submitted_at_str:
                try:
                    # Extract date
                    if 'T' in submitted_at_str:
                        date_part = submitted_at_str.split('T')[0]
                        dt_obj = datetime.fromisoformat(date_part)
                    elif ' ' in submitted_at_str:
                        date_part = submitted_at_str.split(' ')[0]
                        dt_obj = datetime.fromisoformat(date_part)
                    else:
                        dt_obj = datetime.fromisoformat(submitted_at_str[:10])

                    # Get day of week (0=Monday, 6=Sunday)
                    day_index = dt_obj.weekday()
                    day_name = chart_labels[day_index]

                    # Count job
                    daily_data[day_name]['jobs'] += 1

                    # Add revenue if paid
                    if job.get('is_paid') or job.get('payment_status') == 'Accepted':
                        try:
                            cost = float(job.get('total_cost', 0))
                            daily_data[day_name]['revenue'] += cost
                        except (ValueError, TypeError):
                            pass

                except Exception as e:
                    print(f"Error processing job date: {e}")

        # Prepare chart data
        jobs_data = [daily_data[day]['jobs'] for day in chart_labels]
        revenue_data = [daily_data[day]['revenue'] for day in chart_labels]

    else:  # monthly
        # For monthly: weekly breakdown
        weekly_data = {week: {'jobs': 0, 'revenue': 0.0} for week in chart_labels}

        for job in jobs:
            submitted_at_str = job.get('submitted_at')
            if submitted_at_str:
                try:
                    # Extract date
                    if 'T' in submitted_at_str:
                        date_part = submitted_at_str.split('T')[0]
                        dt_obj = datetime.fromisoformat(date_part)
                    elif ' ' in submitted_at_str:
                        date_part = submitted_at_str.split(' ')[0]
                        dt_obj = datetime.fromisoformat(date_part)
                    else:
                        dt_obj = datetime.fromisoformat(submitted_at_str[:10])

                    # Determine which week of the month
                    day_of_month = dt_obj.day
                    week_number = (day_of_month - 1) // 7
                    if week_number > 4:  # Handle 5th week
                        week_number = 4

                    week_label = chart_labels[week_number]

                    # Count job
                    weekly_data[week_label]['jobs'] += 1

                    # Add revenue if paid
                    if job.get('is_paid') or job.get('payment_status') == 'Accepted':
                        try:
                            cost = float(job.get('total_cost', 0))
                            weekly_data[week_label]['revenue'] += cost
                        except (ValueError, TypeError):
                            pass

                except Exception as e:
                    print(f"Error processing job date: {e}")

        # Prepare chart data
        jobs_data = [weekly_data[week]['jobs'] for week in chart_labels]
        revenue_data = [weekly_data[week]['revenue'] for week in chart_labels]

    # Calculate statistics
    total_jobs = sum(jobs_data)
    total_revenue = sum(revenue_data)

    # Find busiest period
    if total_jobs > 0:
        if period_type == 'weekly':
            busiest_index = jobs_data.index(max(jobs_data))
            busiest_period = chart_labels[busiest_index]
            busiest_count = jobs_data[busiest_index]
            busiest_revenue = revenue_data[busiest_index]
        else:
            busiest_index = jobs_data.index(max(jobs_data))
            busiest_period = f"Week {busiest_index + 1}"
            busiest_count = jobs_data[busiest_index]
            busiest_revenue = revenue_data[busiest_index]
    else:
        busiest_period = "No data"
        busiest_count = 0
        busiest_revenue = 0

    # Find least busy period
    if total_jobs > 0:
        if period_type == 'weekly':
            least_busy_index = jobs_data.index(min(jobs_data))
            least_busy_period = chart_labels[least_busy_index]
            least_busy_count = jobs_data[least_busy_index]
            least_busy_revenue = revenue_data[least_busy_index]
        else:
            least_busy_index = jobs_data.index(min(jobs_data))
            least_busy_period = f"Week {least_busy_index + 1}"
            least_busy_count = jobs_data[least_busy_index]
            least_busy_revenue = revenue_data[least_busy_index]
    else:
        least_busy_period = "No data"
        least_busy_count = 0
        least_busy_revenue = 0

    # Query jobs from previous period for comparison
    prev_jobs_resp = supabase.table('print_jobs') \
        .select('*') \
        .gte('submitted_at', prev_start_date.isoformat()) \
        .lte('submitted_at', prev_end_date.isoformat()) \
        .execute()

    prev_jobs = prev_jobs_resp.data or []

    # Calculate previous period revenue
    prev_revenue = 0.0
    for job in prev_jobs:
        if job.get('is_paid') or job.get('payment_status') == 'Accepted':
            try:
                prev_revenue += float(job.get('total_cost', 0))
            except (ValueError, TypeError):
                pass

    # Calculate revenue change
    if prev_revenue > 0:
        revenue_change = ((total_revenue - prev_revenue) / prev_revenue) * 100
    else:
        revenue_change = 0 if total_revenue == 0 else 100

    # Today's revenue
    start_of_today = now_ph.replace(hour=0, minute=0, second=0, microsecond=0)
    end_of_today = now_ph.replace(hour=23, minute=59, second=59, microsecond=999999)

    today_jobs_resp = supabase.table('print_jobs') \
        .select('*') \
        .gte('submitted_at', start_of_today.isoformat()) \
        .lte('submitted_at', end_of_today.isoformat()) \
        .execute()

    today_jobs = today_jobs_resp.data or []
    today_revenue = 0.0
    for job in today_jobs:
        if job.get('is_paid') or job.get('payment_status') == 'Accepted':
            try:
                today_revenue += float(job.get('total_cost', 0))
            except (ValueError, TypeError):
                pass

    # This month's revenue
    start_of_month = now_ph.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    end_of_month = end_of_today  # Use today as end for current month

    month_jobs_resp = supabase.table('print_jobs') \
        .select('*') \
        .gte('submitted_at', start_of_month.isoformat()) \
        .lte('submitted_at', end_of_month.isoformat()) \
        .execute()

    month_jobs = month_jobs_resp.data or []
    month_revenue = 0.0
    for job in month_jobs:
        if job.get('is_paid') or job.get('payment_status') == 'Accepted':
            try:
                month_revenue += float(job.get('total_cost', 0))
            except (ValueError, TypeError):
                pass

    # Formatting helper
    def format_revenue(value):
        return f"₱{value:,.2f}" if value > 0 else "₱0.00"

    def format_change(value):
        if value > 0:
            return f"+{value:.1f}%"
        elif value < 0:
            return f"{value:.1f}%"
        else:
            return "0%"

    context = {
        # Chart data
        'chart_labels': chart_labels,
        'jobs_data': jobs_data,
        'revenue_data': revenue_data,

        # Period info
        'period_type': period_type,
        'period_label': period_label,
        'period_range': period_range,
        'period_offset': period_offset,
        'start_date': start_date.strftime('%B %d, %Y'),
        'end_date': end_date.strftime('%B %d, %Y'),
        'current_year': start_date.year,

        # Statistics
        'total_jobs': total_jobs,
        'total_revenue': format_revenue(total_revenue),
        'raw_total_revenue': total_revenue,
        'revenue_change': format_change(revenue_change),
        'revenue_change_raw': revenue_change,

        # Busiest/Least busy
        'busiest_period': busiest_period,
        'busiest_count': busiest_count,
        'busiest_revenue': format_revenue(busiest_revenue),
        'least_busy_period': least_busy_period,
        'least_busy_count': least_busy_count,
        'least_busy_revenue': format_revenue(least_busy_revenue),

        # Quick stats
        'today_revenue': format_revenue(today_revenue),
        'month_revenue': format_revenue(month_revenue),

        # Navigation
        'prev_offset': period_offset - 1,
        'next_offset': period_offset + 1,
        'is_current_period': period_offset == 0,
    }

    return render(request, 'subtemplates/analytics_dashboard.html', context)