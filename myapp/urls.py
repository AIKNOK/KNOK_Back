from django.urls import path
from .views import (
    signup,
    confirm_email,
    login,
    ResumeUploadView,
    ResumeDeleteView,
)

urlpatterns = [
    path('signup/', signup, name='signup'),
    path('confirm-email/', confirm_email, name='confirm_email'),
    path('login/', login, name='login'),
    path('resume/upload/', ResumeUploadView.as_view(), name='resume-upload'),
    path('resume/delete/', ResumeDeleteView.as_view(), name='resume-delete'),
]
