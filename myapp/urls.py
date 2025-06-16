from django.urls import path
from .views import save_transcribed_text
from . import views 
from .views import (
    signup,
    confirm_email,
    login,
    logout_view,
    ResumeUploadView,
    ResumeDeleteView,
    get_resume_view,
    generate_resume_questions,
    analyze_voice_api,
    receive_posture_count,
    decide_followup_question,
    AudioUploadView,
    get_resume_text,
    FullVideoUploadView,
    extract_bad_posture_clips,
    get_all_questions_view,
    generate_feedback_report,
)

urlpatterns = [
    # 🧑 사용자 인증 관련
    path('signup/', views.signup, name='signup'),
    path('confirm-email/', views.confirm_email, name='confirm_email'),
    path('login/', views.login, name='login'),
    path('logout/', views.logout_view, name='logout'),

    # 📄 이력서 관련
    path('resume/upload/', views.ResumeUploadView.as_view(), name='resume_upload_resume'),
    path('resume/delete/', views.ResumeDeleteView.as_view(), name='resume_delete'),
    path('resume/', views.get_resume_view, name='resume_get'),
    path('generate-resume-questions/', views.generate_resume_questions, name='generate_resume_questions'),
    path('get-resume-text/', views.get_resume_text, name='get_resume_text'),
    path('get_all_questions', views.get_all_questions_view, name='get_all_questions'),

    # 🎤 면접 관련
    path('posture/', views.receive_posture_count, name='posture'),
    path('posture/segments', views.receive_posture_count),
    path('analyze-voice/', views.analyze_voice_api, name='analyze_voice'),
    path('audio/upload/', views.AudioUploadView.as_view(), name='upload_audio_and_text'),
    path('video/upload/', views.FullVideoUploadView.as_view(), name='upload-full-video'),
    path("video/extract-clips/", views.extract_bad_posture_clips),
    path("save_transcribed_text/", views.save_transcribed_text, name="save_transcribed_text"),
    path('questions/audio/', views.get_ordered_question_audio, name='get_ordered_question_audio'),
    path('transcript/', views.save_transcribed_text, name='save_transcribed_text'),

    # ✅ 피드백 리포트 & 꼬리 질문
    path('interview/feedback/generate/', views.generate_feedback_report, name='generate_feedback'),
    path('followup/check/', views.decide_followup_question, name='followup_check'),
]