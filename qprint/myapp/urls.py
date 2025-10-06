from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path("", views.register, name="register_root"),
    path("register/", views.register, name="register"),
    path('login/', auth_views.LoginView.as_view(template_name='login.html'), name='login'),
    path("verify/", views.verify, name="verify"),
    path('logout/', auth_views.LogoutView.as_view(next_page='/login/'), name='logout'),
    path("staff_dashboard/", views.staff_dashboard, name="staff_dashboard"),
    path("student-dashboard/", views.student_dashboard, name="student_dashboard"),
]