from django.urls import path
from . import views

urlpatterns = [
    path('revenue_dashboard/', views.revenue_dashboard, name='revenue_dashboard'),
]