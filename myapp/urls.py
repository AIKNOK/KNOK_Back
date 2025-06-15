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
    download_feedback_zip,
    send_to_slack,
)

urlpatterns = [
    # 🧑 사용자 인증 관련
    path('signup/', signup, name='signup'),
    path('confirm-email/', confirm_email, name='confirm_email'),
    path('login/', login, name='login'),
    path('logout/', logout_view, name='logout'),

    # 📄 이력서 관련 (업로드/삭제/조회/질문생성)
    path('resume/upload/', ResumeUploadView.as_view(), name='resume_upload_resume'),
    path('resume/delete/', ResumeDeleteView.as_view(), name='resume_delete'),
    path('resume/', get_resume_view, name='resume_get'),
    path('generate-resume-questions/', generate_resume_questions, name='generate_resume_questions'),
    path('get-resume-text/', get_resume_text, name='get_resume_text'),
    path('get_all_questions', get_all_questions_view, name='get_all_questions'),

    # 🎤 면접 관련 (자세, 음성 분석, STT 저장)
    path('posture/', receive_posture_count, name='posture'),
    path('posture/segments', receive_posture_count),
    path('analyze-voice/', analyze_voice_api, name='analyze_voice'),
    path('audio/upload/', AudioUploadView.as_view(), name='upload_audio_and_text'),
    path('video/upload/', FullVideoUploadView.as_view(), name='upload-full-video'),
    path("video/extract-clips/", extract_bad_posture_clips),
    path("save_transcribed_text/", save_transcribed_text, name="save_transcribed_text"),
    path('questions/audio/', views.get_interview_question_audio_list, name='get_interview_question_audio_list'),

    # 피드백 다운로드
    path('video/download-zip/', download_feedback_zip),
    
    # ✅ 추가: 프론트에서 요청하는 경로에 맞춤
    path('interview/feedback/generate/', generate_feedback_report, name='generate_feedback'),

    # slack 문의
    path('contact/', send_to_slack, name='send_to_slack'),

    # ❓ 꼬리 질문 여부 판단
    path('followup/check/', decide_followup_question, name='followup_check'),
]
