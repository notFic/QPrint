from django.db import models
from django.contrib.auth.models import User

class PrintJob(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    username = models.CharField(max_length=150)
    file_name = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)
    status = models.TextField(
        choices=[
            ('Pending', 'Pending'),
            ('Completed', 'Completed'),
            ('Cancelled', 'Cancelled'),
            ('Failed', 'Failed')
        ],
        default='Pending'
    )
    action = models.TextField(
        choices=[
            ('Cancel', 'Cancel'),
            ('Retry', 'Retry'),
            ('None', 'None')
        ],
        default='None'
    )

    def __str__(self):
        return f"{self.file_name} ({self.status})"

class Invoice(models.Model):
    student = models.ForeignKey(User, on_delete=models.CASCADE)
    print_job = models.ForeignKey(PrintJob, on_delete=models.SET_NULL, null=True, blank=True)
    amount = models.DecimalField(max_digits=8, decimal_places=2)
    status = models.TextField(
        choices=[
            ('Pending', 'Pending'),
            ('Paid', 'Paid'),
            ('Cancelled', 'Cancelled')
        ],
        default='Pending'
    )
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Invoice #{self.id} - {self.student.username} ({self.status})"
