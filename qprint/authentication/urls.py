from . import views
from django.urls import path, include

urlpatterns = [
    path("", views.register, name="register_root"),
    path("register/", views.register, name="register"),
    path("login/", views.login, name="login"),
    path("verify/", views.verify, name="verify"),
    path("logout/", views.logout, name="logout"),
    path("staff_dashboard/", views.staff_dashboard, name="staff_dashboard"),
    path("student_dashboard/", views.student_dashboard, name="student_dashboard"),
    path('reset-password/<uidb64>/<token>/', views.reset_password, name='reset_password'),
    path('forgot-password/', views.forgot_password, name='forgot_password'),
    path('api/job/<uuid:job_id>/', views.get_job_detail, name='job_detail'),
    path("staff/update-payment/", views.staff_update_payment, name="staff_update_payment"),
    path("staff/confirm-job/", views.staff_confirm_job, name="staff_confirm_job"),
    path('payments/', include('qprint.payments.urls')),
    path('staff/delete-job/', views.staff_delete_job, name='staff_delete_job'),
    path('student/delete-job/', views.student_delete_job, name='student_delete_job'),
    path('staff-complete-job/', views.staff_complete_job, name='staff_complete_job'),
    path('history/', views.print_job_history, name='print_job_history'),
    path('staff/history/', views.staff_job_history, name='staff_job_history'),

    # Invoice URLs
    path("invoices/", views.invoice_list, name="invoice_list"),
    path("invoices/<uuid:job_id>/", views.view_invoice, name="view_invoice"),
    path("api/check-print-status/<uuid:job_id>/", views.check_print_status, name="check_print_status"),
    path('receipt/<uuid:job_id>/', views.download_receipt, name='download_receipt'),
]