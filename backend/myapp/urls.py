from django.urls import path
from . import views 
from .views import (
    decide_followup_question,
    generate_feedback_report,
    get_ordered_question_audio,
    download_feedback_zip,
    upload_feedback_pdf,
    get_feedback_history,
    send_to_slack,
    get_feedback_history,
    health_check,
    get_signed_pdf_url
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
    path('get_all_questions/', views.get_all_questions_view, name='get_all_questions'),

    # 🎤 면접 관련
    path('posture/', views.receive_posture_count, name='posture'),
    path('posture/segments', views.receive_posture_count),
    path('analyze-voice/', views.analyze_voice_api, name='analyze_voice'),
    path('audio/upload/', views.AudioUploadView.as_view(), name='upload_audio_and_text'),
    path('video/upload-question-clip/', views.upload_question_clip),
    path('video/extract-question-clip-segments/', views.extract_question_clip_segments),
    path("save_transcribed_text/", views.save_transcribed_text, name="save_transcribed_text"),
    path('questions/audio/', views.get_ordered_question_audio, name='get_ordered_question_audio'),
    path('transcript/', views.save_transcribed_text, name='save_transcribed_text'),

    # 피드백 다운로드
    path('download/feedback-zip/', download_feedback_zip, name='download-feedback-zip'),

    # 피드백 pdf S3에 업로드
    path('upload/pdf/', views.upload_feedback_pdf,  name='upload-feedback-pdf'),

    # ✅ 추가: 프론트에서 요청하는 경로에 맞춤
    path('interview/feedback/generate/', generate_feedback_report, name='generate_feedback'),

    # ✅ 피드백 리포트 & 꼬리 질문
    path('interview/feedback/generate/', views.generate_feedback_report, name='generate_feedback'),
    path('followup/check/', views.decide_followup_question, name='followup_check'),
    path('video/get-clips-and-segments/', views.get_clips_and_segments, name='get_clips_and_segments'),

    # history 조회
    path('feedback/history/', get_feedback_history, name='feedback_history'),
    path("get-signed-url/", get_signed_pdf_url),

    path("health/", health_check),

    # slack 문의
    path('contact/', send_to_slack, name='send_to_slack'),

    # ❓ 꼬리 질문 여부 판단
    path('followup/check/', decide_followup_question, name='followup_check'),

]
