from django.contrib.auth.models import AbstractUser
from django.db import models

# Create your models here.


class User(AbstractUser):
    otp = models.IntegerField(default=0)
    is_no_verified = models.BooleanField(default=False)
    is_email_verified = models.BooleanField(default=False)
    is_manufacturer = models.BooleanField(default=False)
    is_pharmacy = models.BooleanField(default=False)
    node_address = models.CharField(max_length=255, blank=True)
    phone_no = models.CharField(max_length=13)
