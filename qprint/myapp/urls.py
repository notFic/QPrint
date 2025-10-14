from django.urls import path
from . import views

urlpatterns = [
    path("", views.register, name="register_root"), 
    path("register/", views.register, name="register"), 
    path("login/", views.login, name="login"),
    path("verify/", views.verify, name="verify"),
    path("logout/", views.logout, name="logout"),
    path("staff_dashboard/", views.staff_dashboard, name="staff_dashboard"),
    path("student_dashboard/", views.student_dashboard, name="student_dashboard"),
]