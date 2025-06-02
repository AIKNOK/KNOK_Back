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
    receive_posture_count,
    # === 새로 추가 ===
    UploadAnswerView,                  # 질문별 녹음 업로드용 뷰 (아래 예시)
    generate_feedback_view,            # 인터뷰 피드백 생성용 뷰 (아래 예시)
    analyze_voice_api,
)

urlpatterns = [
    path('signup/', signup, name='signup'),
    path('confirm-email/', confirm_email, name='confirm_email'),
    path('login/', login, name='login'),
    path('logout/', logout_view, name='logout'),

    # 이력서(PDF) 업로드/삭제/조회
    path('resume/upload/', ResumeUploadView.as_view(), name='resume-upload'),
    path('resume/delete/', ResumeDeleteView.as_view(), name='resume-delete'),
    path('api/resume/', get_resume_view, name='get_resume'),

    # 이력서 기반 질문 생성 → 클라이언트 호출: POST /api/generate-resume-questions/
    path('api/generate-resume-questions/', generate_resume_questions, name='generate_resume_questions'),

    # 자세 수신 → 클라이언트 호출: POST /api/posture/
    path('posture/', receive_posture_count, name='posture'),

    # 질문 녹음+전사 업로드 → 클라이언트 호출: POST /api/upload/
    path('upload/', UploadAnswerView.as_view(), name='upload_answer'),

    # 인터뷰 피드백 생성 → 클라이언트 호출: POST /api/interview/feedback/generate/
    path('interview/feedback/generate/', generate_feedback_view, name='generate_feedback'),

    # 음성 분석용 (선택적) → 클라이언트 호출: POST /api/analyze/
    path('analyze/', analyze_voice_api, name='analyze_voice'),
]
