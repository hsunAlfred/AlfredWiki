from django.db import models
from django.contrib.auth.models import User

# Create your models here.


class UserSignupPlatform(models.Model):
    User = models.OneToOneField(
        User,
        on_delete=models.CASCADE
    )

    Platform_Choice = [
        ("Self", "Self"),
        ("Google", "Google"),
    ]
    Platform = models.CharField(
        "Platform", max_length=10, choices=Platform_Choice)
    
    GoogleUserID = models.CharField("GoogleUserID", max_length=50, null=True, blank=True)

    class Meta:
        ordering = ['User__username', 'Platform']

    def __str__(self):
        return f"{self.User.username} | {self.Platform}"
