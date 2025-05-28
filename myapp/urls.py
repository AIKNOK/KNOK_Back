from django.urls import path
from .views import analyze_voice_api
from .views import (
    signup,
    confirm_email,
    login,
    logout_view,
    ResumeUploadView,
    ResumeDeleteView,
    receive_posture_count,
)

urlpatterns = [
    path('signup/', signup, name='signup'),
    path('confirm-email/', confirm_email, name='confirm_email'),
    path('login/', login, name='login'),
    path('logout/', logout_view, name='logout'),
    path('resume/upload/', ResumeUploadView.as_view(), name='resume-upload'),
    path('resume/delete/', ResumeDeleteView.as_view(), name='resume-delete'),
    path('analyze/', analyze_voice_api),
    path('posture/', receive_posture_count, name='posture'),
]
