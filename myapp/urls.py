from django.urls import path
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

    # 🎤 면접 관련 (자세, 음성 분석, STT 저장)
    path('posture/', receive_posture_count, name='posture'),
    path('analyze-voice/', analyze_voice_api, name='analyze_voice'),
    path('audio/upload/', AudioUploadView.as_view(), name='upload_audio_and_text'),

    # ❓ 꼬리 질문 여부 판단
    path('followup/check/', decide_followup_question, name='followup_check'),
]
