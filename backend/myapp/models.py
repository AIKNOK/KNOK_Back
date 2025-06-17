from django.db import models
from django.contrib.auth.models import User

class Resume(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)  # 사용자당 1개만 업로드
    file_url = models.URLField()  # S3에 저장된 이력서의 URL
    uploaded_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.user.username}의 이력서"
