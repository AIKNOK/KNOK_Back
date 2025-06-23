from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import authentication_classes, permission_classes
from rest_framework import status
from pydub import AudioSegment
from myapp.utils.keyword_extractor import extract_resume_keywords
from myapp.utils.followup_logic import should_generate_followup
from myapp.authentication import CognitoJWTAuthentication


import requests
import re
import json
import boto3
import hmac
import hashlib
import base64
import tempfile
import librosa
import numpy as np
import parselmouth
import time
import PyPDF2
import moviepy.editor as mp
import subprocess
import os
import traceback

from django.conf import settings
from .models import Resume
from .serializers import ResumeSerializer
from django.http import JsonResponse
from pathlib import Path
from django.views.decorators.csrf import csrf_exempt
from django.http import FileResponse
from datetime import timedelta
from reportlab.pdfgen import canvas  # or your preferred PDF lib
from reportlab.lib.pagesizes import A4
from botocore.exceptions import ClientError
from django.views.decorators.http import require_GET
from django.views.decorators.http import require_http_methods


print("✅ [views.py] 파일 로드됨")

# 🔐 SECRET_HASH 계산 함수 (Cognito)
def get_secret_hash(username):
    message = username + settings.COGNITO_APP_CLIENT_ID
    digest = hmac.new(
        settings.COGNITO_APP_CLIENT_SECRET.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode()


# 📝 회원가입 API
@csrf_exempt
@api_view(['POST'])
def signup(request):
    email = request.data.get('email')
    password = request.data.get('password')

    client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)

    try:
        client.sign_up(
            ClientId=settings.COGNITO_APP_CLIENT_ID,
            SecretHash=get_secret_hash(email),
            Username=email,
            Password=password,
            UserAttributes=[{'Name': 'email', 'Value': email}],
        )
        return Response({'message': '회원가입 성공! 이메일 인증 필요'})
    except client.exceptions.UsernameExistsException:
        return Response({'error': '이미 존재하는 사용자입니다.'}, status=400)
    except Exception as e:
        return Response({'error': str(e)}, status=400)


# ✅ 이메일 인증 API
@api_view(['POST'])
def confirm_email(request):
    email = request.data.get('email')
    code = request.data.get('code')

    client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)

    try:
        client.confirm_sign_up(
            ClientId=settings.COGNITO_APP_CLIENT_ID,
            SecretHash=get_secret_hash(email),
            Username=email,
            ConfirmationCode=code
        )
        return Response({'message': '이메일 인증 완료'})
    except client.exceptions.CodeMismatchException:
        return Response({'error': '인증 코드가 틀렸습니다.'}, status=400)
    except client.exceptions.ExpiredCodeException:
        return Response({'error': '인증 코드가 만료되었습니다.'}, status=400)
    except Exception as e:
        return Response({'error': str(e)}, status=400)


# 🔑 로그인 API
@api_view(['POST'])
def login(request):
    print("📦 login 요청 데이터:", request.data)

    email = request.data.get('email')
    password = request.data.get('password')

    client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)

    try:
        response = client.initiate_auth(
            ClientId=settings.COGNITO_APP_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': get_secret_hash(email)
            }
        )

        auth_result = response['AuthenticationResult']
        id_token = auth_result['IdToken']
        access_token = auth_result['AccessToken']

        return Response({
            'message': '로그인되었습니다',
            'id_token': id_token,
            'access_token': access_token
        })

    except client.exceptions.NotAuthorizedException as e:
        print("❌ NotAuthorizedException:", str(e))
        return Response({'error': '아이디 또는 비밀번호 오류'}, status=400)

    except client.exceptions.UserNotConfirmedException as e:
        print("❌ UserNotConfirmedException:", str(e))
        return Response({'error': '이메일 인증이 필요합니다.'}, status=403)

    except client.exceptions.InvalidParameterException as e:
        print("❌ InvalidParameterException:", str(e))
        return Response({'error': '파라미터 오류. 설정 확인 필요.'}, status=400)

    except client.exceptions.SecretHashMismatchException as e:
        print("❌ SecretHashMismatchException:", str(e))
        return Response({'error': '시크릿 해시 오류. .env 또는 settings.py 확인 필요'}, status=400)

    except Exception as e:
        print("❌ Unknown error:", str(e))
        return Response({'error': str(e)}, status=400)
    

# 🚪 로그아웃 API
@api_view(['POST'])
@authentication_classes([])  # 인증 미적용
@permission_classes([])      # 권한 미적용
def logout_view(request):
    token = request.headers.get('Authorization')
    if not token:
        return Response({'error': 'Authorization 헤더가 없습니다.'}, status=400)

    token = token.replace('Bearer ', '')  # 토큰 앞에 'Bearer '가 붙어 있으면 제거

    client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)
    try:
        client.global_sign_out(
            AccessToken=token
        )
        return Response({'message': '로그아웃 되었습니다.'})
    except client.exceptions.NotAuthorizedException:
        return Response({'error': '유효하지 않은 토큰입니다.'}, status=401)
    except Exception as e:
        return Response({'error': str(e)}, status=400)

# 📤 이력서 업로드 API (S3 저장, DB 기록, 중복 업로드 차단)
class ResumeUploadView(APIView):
    authentication_classes = [CognitoJWTAuthentication]
    permission_classes = [IsAuthenticated]

    def post(self, request):
        print("📥 [ResumeUploadView] 업로드 요청 수신됨")
        # 1) 파일 유무 체크
        uploaded_file = request.FILES.get('resume')
        if not uploaded_file:
            print("❌ 파일 없음: request.FILES =", request.FILES)
            return Response({"error": "파일이 없습니다."}, status=400)

        # ✅ 2) 사용자 이메일 + 원본 파일명으로 S3 경로 구성
        if not request.user or not request.user.email:
            print("❌ 사용자 인증 실패: request.user =", request.user)
            return Response({"error": "인증된 사용자가 아닙니다."}, status=401)
        
        email_prefix = request.user.email.split('@')[0]
        original_filename = uploaded_file.name
        key = f"resumes/{email_prefix}/{original_filename}"
        print(f"📎 업로드 대상 key: {key}")

        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        try:
            s3.upload_fileobj(uploaded_file, settings.AWS_STORAGE_BUCKET_NAME, key)
            print("✅ S3 업로드 성공")
        except Exception as e:
            traceback.print_exc()
            return Response({"error": f"S3 업로드 실패: {str(e)}"}, status=500)

        file_url = f"https://{settings.AWS_S3_CUSTOM_DOMAIN}/{key}"
        print(f"🔗 저장된 파일 URL: {file_url}")

        # ✅ 3) DB에도 업데이트 (이전 것 덮어씀)
        resume_obj, created = Resume.objects.update_or_create(
            user=request.user,
            defaults={'file_url': file_url}
        )

        serializer = ResumeSerializer(resume_obj)
        return Response(serializer.data, status=201)


class ResumeDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        resume = Resume.objects.filter(user=request.user).first()
        if not resume:
            return Response({"error": "업로드된 이력서가 없습니다."}, status=404)

        # S3 객체 삭제
        s3_key = resume.file_url.split(f"{settings.AWS_S3_CUSTOM_DOMAIN}/")[-1]
        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )
        try:
            s3.delete_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=s3_key)
        except Exception as e:
            return Response({"error": f"S3 삭제 실패: {str(e)}"}, status=500)

        # DB 레코드 삭제
        resume.delete()
        return Response({"message": "이력서 삭제 완료"}, status=204)

# 🧾 이력서 조회 API (새로고침 시 프론트에서 조회)
@api_view(['GET'])
@authentication_classes([CognitoJWTAuthentication])
@permission_classes([IsAuthenticated])
def get_resume_view(request):
    print("📌 현재 로그인된 사용자:", request.user, type(request.user))

    if not request.user or not request.user.is_authenticated:
        return Response({'error': '인증된 사용자가 아닙니다.'}, status=401)

    try:
        resume = Resume.objects.filter(user=request.user).first()
        if not resume:
            return Response({'file_url': None}, status=200)

        return Response({'file_url': resume.file_url}, status=200)
    except Exception as e:
        traceback.print_exc()  # ✅ 이게 있어야 CloudWatch에 에러 줄 번호와 원인이 찍힘
        return Response({'error': '서버 오류', 'detail': str(e)}, status=500)

# 🧠 Claude에게 이력서 기반으로 질문 요청
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_resume_questions(request):
    user = request.user
    email_prefix = user.email.split('@')[0]
    difficulty = request.data.get("difficulty", "중간")
    print(f"💡 선택된 난이도: {difficulty}")

    bucket_in = settings.AWS_STORAGE_BUCKET_NAME  # 이력서가 있는 버킷
    bucket_out = 'resume-questions'               # 질문 저장용 버킷

    s3 = boto3.client(
    's3',
    aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
    region_name=settings.AWS_S3_REGION_NAME
    )

    # 🔍 이력서가 저장된 사용자 폴더 안의 PDF 파일 찾기
    prefix = f"resumes/{email_prefix}/"
    response = s3.list_objects_v2(Bucket=bucket_in, Prefix=prefix)
    pdf_files = sorted(
        [obj for obj in response.get('Contents', []) if obj['Key'].endswith('.pdf')],
        key=lambda x: x['LastModified'],
        reverse=True
    )

    if not pdf_files:
        return Response({"error": "PDF 파일이 존재하지 않습니다."}, status=404)

    # ✅ 최신 파일 선택
    key = pdf_files[0]['Key']

    # PDF 다운로드
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    s3.download_fileobj(bucket_in, key, temp_file)
    temp_file.close()

    # PDF 텍스트 추출
    with open(temp_file.name, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        text = "\n".join(page.extract_text() for page in reader.pages if page.extract_text())

    # Claude 프롬프트 생성
     # ✅ 난이도별 지침 설정
    difficulty_prompt = {
        "쉬움": "부담 없이 답할 수 있는 질문을 만들어주세요. 자기소개, 간단한 경험 중심으로 해주세요.",
        "중간": "기술, 프로젝트, 협업 상황에 대해 본인이 설명할 수 있는 수준의 구체적인 질문을 만들어주세요.",
        "어려움": "한 가지 주제에 깊이 있게 질문해주세요. 예: 기술 선택 이유, 문제 해결 전략, 아키텍처 설계 판단 등. 한 문장에 여러 질문을 넣지 마세요. 사고력을 요하는 질문이어야 합니다."
    }.get(difficulty, "")
    
    # ✅ Claude 프롬프트 생성 
    prompt = f"""
    당신은 AI 면접 질문 생성기입니다.

    다음은 이력서 내용입니다:
    {text}

    이력서를 바탕으로 해당 지원자가 실제 면접에서 받을 법한 면접 질문을 3개 작성해 주세요.
    형식은 아래와 같이 해주세요:

    - 이력서에 언급된 기술, 경험, 프로젝트, 직무 관련 내용에서만 질문을 추출하세요.
    - 자기소개, 기술 역량, 협업/갈등 해결, 문제 해결 방식 등을 중심으로 구성하세요.
    - 절대로 질문 앞에 숫자나 'Q1' 같은 접두어를 붙이지 마세요.
    - 질문만 한 줄씩 출력하세요.
    - 줄바꿈으로 각 질문을 구분하세요.

    난이도 지침:
    - {difficulty_prompt}
    
    예시 출력 형식:
    React 프로젝트에서 성능 최적화를 위해 어떤 방법을 사용하셨나요?
    협업 중 의견 충돌이 있었을 때 어떻게 해결하셨나요?
    본인의 기술 역량 중 가장 자신 있는 부분은 무엇인가요?
    지원하신 직무와 관련해 가장 자신 있는 기술 스택은 무엇인가요?
    해당 기술을 활용해 문제를 해결했던 경험을 말씀해 주세요.
    팀 프로젝트에서 본인이 맡았던 역할과 해결한 기술적 문제는 무엇이었나요?
    """

    # Claude 호출 (1차 질문 생성)
    client = boto3.client("bedrock-runtime", region_name="us-east-1")
    body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 512,
        "temperature": 0.7,
        "messages": [{"role": "user", "content": prompt}]
    }
    response = client.invoke_model(
        modelId="anthropic.claude-3-haiku-20240307-v1:0",
        contentType="application/json",
        accept="application/json",
        body=json.dumps(body)
    )
    result = json.loads(response['body'].read())
    content = result['content'][0]['text'] if result.get("content") else ""

    # 질문 분리 후 S3에 저장
    questions = [line for line in content.strip().split('\n') if line.strip()]
    print("🎤 Claude 생성 질문 (원본):", questions)

    # ✅ Claude 검증 프롬프트 (고정 질문 제외)
    verify_prompt = f"""
다음은 사용자의 이력서와 AI가 생성한 면접 질문 목록입니다.

이력서:
{text}

AI가 생성한 질문:
{chr(10).join(questions)}

요청:
- 아래 기준에 따라 질문이 이력서와 실제로 관련 있는지 판단해 주세요.
- "기술 스택", "업무 경험", "학습 내용", "프로젝트", "자격증", "직무 관심도" 등 이력서에 실제로 언급된 내용과 관련된 질문만 남겨 주세요.
- 관련 없는 질문은 제거하거나, 관련된 내용으로 수정해 주세요.
- 질문 앞에 숫자나 Q1 같은 접두어는 붙이지 마세요.
- 질문만 줄바꿈으로 구분해서 출력하세요.

"""
    verify_body = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 512,
        "temperature": 0.3,
        "messages": [{"role": "user", "content": verify_prompt}]
    }
    verify_response = client.invoke_model(
        modelId="anthropic.claude-3-haiku-20240307-v1:0",
        contentType="application/json",
        accept="application/json",
        body=json.dumps(verify_body)
    )
    verify_result = json.loads(verify_response['body'].read())
    verified_text = verify_result['content'][0]['text'] if verify_result.get("content") else ""
    verified_questions = [line.strip() for line in verified_text.strip().split('\n') if line.strip()]
    print("✅ Claude 검증 완료 질문:", verified_questions)

    # 고정 질문
    final_questions = ["간단히 자기소개 부탁드릴게요"] + verified_questions[:3]
    print("📦 최종 질문 (고정 + 검증된 질문):", final_questions)

    for idx, question in enumerate(final_questions, start=1):
        filename = f"{email_prefix}/questions{idx}.txt"
        s3.put_object(
            Bucket=bucket_out,
            Key=filename,
            Body=question.encode('utf-8'),
            ContentType='text/plain'
        )

    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return Response({'error': 'Authorization 헤더가 없습니다.'}, status=401)
    
    token = auth_header.replace('Bearer ', '', 1).strip()
    headers = {
        "Authorization": f"Bearer {token}"
    }
    try:
        tts_response = requests.post(
            "http://13.209.16.252:8002/api/generate-resume-question/",
            headers=headers,
            timeout=30
        )
        if tts_response.status_code != 200:
            print("❌ TTS 생성 실패:", tts_response.text)
        else:
            print("✅ TTS 생성 완료")
    except Exception as e:
        print("❗ TTS 호출 중 예외 발생:", e)

    return Response({"message": "질문 저장 완료", "questions": final_questions})



# Claude 3 호출 함수 추가



def get_claude_feedback(prompt: str) -> str:
    print(">> get_claude_feedback received:", prompt)
    
    client = boto3.client("bedrock-runtime", region_name="us-east-1")
    
    try:
        # Claude 3.7 Sonnet 모델 직접 호출 (온디맨드 방식)
        response = client.invoke_model(
            modelId="us.anthropic.claude-3-7-sonnet-20250219-v1:0",  # Claude 3.7 Sonnet 모델 ID
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 2048,
                "temperature": 0.0,
                "messages": [
                    {
                        "role": "user",
                        "content": [{"type": "text", "text": prompt}],
                    }
                ]
            }),
        )
    except ClientError as e:
        print(f"Claude API 호출 오류: {str(e)}")
        raise
    
    payload = json.loads(response["body"].read().decode("utf-8"))

    # 최신 Claude API는 content 배열을 반환
    if "content" in payload and len(payload["content"]) > 0:
        return payload["content"][0]["text"].strip()
    else:
        print("Claude 응답에 content 필드가 없습니다:", payload)
        return ""

#s3 에서 파일 가져오기
def download_multiple_audios_from_s3(bucket, prefix='audio/'):
    s3 = boto3.client('s3')
    response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    
    file_paths = []
    for obj in sorted(response.get('Contents', []), key=lambda x: x['Key']):
        key = obj['Key']
        if key.endswith('.wav'):
            temp = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
            s3.download_fileobj(bucket, key, temp)
            file_paths.append(temp.name)
    return file_paths

def merge_audio_files(file_paths):
    combined = AudioSegment.empty()
    for file_path in file_paths:
        audio = AudioSegment.from_wav(file_path)
        combined += audio
    output_path = tempfile.NamedTemporaryFile(delete=False, suffix=".wav").name
    combined.export(output_path, format="wav")
    return output_path

# 🔍 Pitch 분석 → 떨림 여부 판단
def analyze_pitch(file_path):
    y, sr = librosa.load(file_path, sr=None)
    pitches, magnitudes = librosa.piptrack(y=y, sr=sr)
    pitch_values = pitches[pitches > 0]
    pitch_std = np.std(pitch_values)
    return {
        'pitch_std': float(round(pitch_std, 2)),  # float32 → float 로 변환
        'voice_tremor': '감지됨' if pitch_std > 20 else '안정적'
    }

# ✅ 2. 말 속도 분석 
def upload_merged_audio_to_s3(file_path, bucket, key):
    s3 = boto3.client('s3',
                      aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                      region_name=settings.AWS_S3_REGION_NAME)
    s3.upload_file(file_path, bucket, key)

# ✅ 3. 침묵 비율 분석 (librosa 사용)
def analyze_silence_ratio(file_path):
    y, sr = librosa.load(file_path)
    intervals = librosa.effects.split(y, top_db=30)
    total_duration = librosa.get_duration(y=y, sr=sr)
    speech_duration = sum((end - start) for start, end in intervals) / sr
    silence_ratio = 1 - (speech_duration / total_duration)
    return round(silence_ratio, 2)

# ✅ 4. 감정 상태 추정 (parselmouth 사용)
def analyze_emotion(file_path):
    snd = parselmouth.Sound(file_path)
    pitch = snd.to_pitch()
    pitch_values = []

    for i in range(pitch.get_number_of_frames()):
        val = pitch.get_value_in_frame(i)
        if val is not None and val != 0:
            pitch_values.append(val)

    if not pitch_values:
        return "데이터 없음"

    stdev = np.std(pitch_values)

    if stdev < 20:
        return "침착함"
    elif stdev < 60:
        return "자신감 있음"
    else:
        return "긴장함"
    
# 점수 계산 함수
def calculate_score(chart: dict) -> float:
    weights = {
        "일관성": 0.20,
        "논리성": 0.20,
        "대처능력": 0.15,
        "구체성": 0.15,
        "말하기방식": 0.15,
        "면접태도": 0.15,
    }
    score = sum(chart[k] * weights[k] * 20 for k in chart)
    return round(score, 1)
    
# 📌 Claude 응답 파싱 및 점수 추가
def parse_claude_feedback_and_score(raw_text: str) -> dict:
    try:
        result = json.loads(raw_text)
        result['score'] = calculate_score(result['chart'])
        return result
    except Exception as e:
        return {
            "error": "Claude 응답 파싱 실패",
            "detail": str(e),
            "raw": raw_text
        }

# json 형태로 변환    
def parse_plain_feedback(text: str) -> dict:
    """
    raw_text (플레인) 을 summary/detail/chart 로 구조화해서 dict로 반환
    {
      "summary": str,
      "detail": { "일관성": "...", … },
      "chart": { "일관성": 4, … }
    }
    """
    feedback = {"summary": "", "detail": {}, "chart": {}}
    section = None
    buffer = []

    expected_keys = ["일관성", "논리성", "대처능력", "구체성", "말하기방식", "면접태도"]

    def save_section(sec, buf):
        content = "\n".join(buf).strip()
        if sec == "요약":
            feedback["summary"] = content
        elif sec in expected_keys:
            # "- 코멘트…" 과 "(점수: X점)" 을 분리
            lines = content.splitlines()
            comment_lines = [l for l in lines if not l.startswith("(점수")]
            score_line = next((l for l in lines if l.startswith("(점수")), "")
            # 코멘트 저장
            feedback["detail"][sec] = "\n".join(comment_lines).lstrip("- ").strip()
            # 점수 추출
            import re
            m = re.search(r"점수[^\d]*(\d+)", score_line)
            if m:
                feedback["chart"][sec] = int(m.group(1))

    # 파싱 시작
    for line in text.splitlines():
        if line.startswith("=== ") and line.endswith(" ==="):
            if section:
                save_section(section, buffer)
            section = line.strip("= ").strip()
            buffer = []
        else:
            buffer.append(line)
    if section:
        save_section(section, buffer)

    # 누락 항목은 0점 처리
    for key in expected_keys:
        feedback["detail"].setdefault(key, "")
        feedback["chart"].setdefault(key, 0)

    return feedback

# Claude 답변 사전 점검 (6개 다 했는지)
def validate_claude_feedback_format(text: str) -> dict:
    required_sections = ["일관성", "논리성", "대처능력", "구체성", "말하기방식", "면접태도"]
    missing_sections = []

    for section in required_sections:
        if f"=== {section} ===" not in text:
            missing_sections.append(section)

    return {
        "is_valid": len(missing_sections) == 0,
        "missing_sections": missing_sections
    }
  

def analyze_speech_rate_via_transcribe(transcribed_text, audio_path):
    y, sr = librosa.load(audio_path, sr=None)
    duration = librosa.get_duration(y=y, sr=sr)
    words = transcribed_text.strip().split()
    word_count = len(words)
    if duration == 0:
        return 0
    return round(word_count / duration, 2)  # 단어 수 ÷ 총 시간(초)

# [1] 음성 분석 API (전처리 + 분석만 수행)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def analyze_voice_api(request):
    start_time = time.time()

    upload_id    = request.data.get('upload_id') 
    posture_count = request.data.get('posture_count', 0)
    if not upload_id:
        return JsonResponse({'error': 'upload_id 필수'}, status=400)
    
    bucket = 'live-stt'
    email_prefix = request.user.email.split('@')[0]
    
    prefix = f"{email_prefix}/{upload_id}/wavs/"   # 여러 답변 오디오가 여기에 저장되어 있음

    try:
        # 1. 다중 오디오 다운로드 및 병합
        audio_files = download_multiple_audios_from_s3(bucket, prefix)
        if not audio_files:
            return JsonResponse({'error': '오디오 파일을 찾을 수 없습니다.'}, status=404)
        merged_audio_path = merge_audio_files(audio_files)

        # 🔍 병합된 오디오 길이 확인 로그 (디버깅용)
        y, sr = librosa.load(merged_audio_path)
        print("\u23f1 병합된 오디오 길이 (초):", librosa.get_duration(y=y, sr=sr))

        # ✅ Transcribe 분석 (STT 텍스트 추출)
        s3_key = "merged/merged_audio.wav"
        upload_merged_audio_to_s3(merged_audio_path, bucket, s3_key)
        transcribe_text = merge_texts_from_s3_folder(bucket, s3_key)
        # 2. 분석 시작
        pitch_result = analyze_pitch(merged_audio_path)
        speech_rate = analyze_speech_rate_via_transcribe(transcribe_text, merged_audio_path)
        silence_ratio = analyze_silence_ratio(merged_audio_path)
        emotion = analyze_emotion(merged_audio_path)

        result = {
            **pitch_result,
            'speech_rate': speech_rate,
            'silence_ratio': silence_ratio,
            'emotion': emotion,
            'posture_count': posture_count,
            'transcribe_text': transcribe_text
        }
        
        elapsed_time = round(time.time() - start_time, 2)

        return JsonResponse({
            'analysis': result,
            'response_time_seconds': elapsed_time
        }, json_dumps_params={'ensure_ascii': False})

    except Exception as e:
        print("🔥 analyze_voice_api 예외:\n", traceback.format_exc())
        return JsonResponse({'error': str(e)}, status=500)
 
# [2] 피드백 리포트 생성 API (STT 분석 결과 기반)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_feedback_report(request):
    user = request.user
    analysis = request.data.get("analysis", {})

    # merge_texts_from_s3_folder 호출하여 transcript 획득
    if not analysis.get('transcribe_text'):
        # email_prefix나 upload_id는 클라이언트에서 전달
        email_prefix = analysis.get('email_prefix', user.email.split("@")[0])
        upload_id = analysis.get('upload_id')
        transcribe_text = merge_texts_from_s3_folder(email_prefix, upload_id)
        analysis['transcribe_text'] = transcribe_text

    posture_counts: dict = analysis.get("posture_count", {})
    # posture_count = analysis.get("posture_count", 0)

    # 그 값들의 합을 실제 이벤트 횟수로 사용
    total_posture_events = sum(posture_counts.values())
		
		# 프롬프트 구성
    voice_desc = f"""
- 목소리 떨림: {analysis['voice_tremor']}
- Pitch 표준편차: {analysis['pitch_std']}
- 말 속도: {analysis['speech_rate']} 단어/초
- 침묵 비율: {analysis['silence_ratio'] * 100:.1f}%
- 감정 상태: {analysis['emotion']}
"""

    posture_desc = f"면접 중 총 {total_posture_events}회의 자세 흔들림이 감지되었습니다."
    transcribe_desc = analysis["transcribe_text"]

    prompt = f"""
당신은 AI 면접 코치입니다. 아래는 면접자의 분석 데이터입니다:

[전체 답변 결과]
{transcribe_desc}

[음성 분석 결과]
{voice_desc}

[자세 분석 결과]
{posture_desc}

위 데이터를 바탕으로 면접자의 답변을 다음 기준에 따라 피드백을 작성해주세요. 반드시 아래 형식을 따라 작성해주세요:

=== 요약 ===
[면접자 평가에 대한 전체적인 요약 1-2문장]

=== 일관성 ===
- [답변 전체에 흐름이 있고 앞뒤가 자연스럽게 연결되는지에 대한 피드백]
(점수: 0~5점 중 하나)

=== 논리성 ===
- [주장에 대해 명확한 이유와 근거가 있으며 논리적 흐름이 있는지에 대한 피드백]
(점수: 0~5점 중 하나)

=== 대처능력 ===
- [예상치 못한 질문에도 당황하지 않고 유연하게 답했는지에 대한 피드백]
(점수: 0~5점 중 하나)

=== 구체성 ===
- [추상적인 설명보다 구체적인 경험과 예시가 포함되어 있는지에 대한 피드백]
(점수: 0~5점 중 하나)

=== 말하기방식 ===
- [음성 분석 결과({voice_desc})를 바탕으로 목소리 떨림 여부와 말 속도(단어/초)에 대한 코멘트]
- [음성 분석 결과({voice_desc})를 바탕으로 침묵 비율(%)과 감정 상태에 대한 코멘트]
(점수: 0~5점 중 하나)

=== 면접태도 ===
- [자세 분석 결과({posture_desc})를 바탕으로 자세 흔들림 횟수와 그 빈도에 대한 해석을 포함한 코멘트]
(점수: 0~5점 중 하나)
"""
    # 로그 확인
    print("===== generate_feedback_report prompt =====")
    print(prompt)
    print("===== transcribe_desc =====")
    print(transcribe_desc)
    print("===== voice_desc =====")
    print(voice_desc)
    print("===== posture_desc =====")
    print(posture_desc)
    print("========================================")

    try:
        raw_text = get_claude_feedback(prompt)
    except ClientError as e:
        return Response(
            {"error": "AI 모델 호출 오류", "detail": str(e)},
            status=status.HTTP_400_BAD_REQUEST
        )
    except Exception as e:
        return Response(
            {"error": "예상치 못한 오류", "detail": str(e)},
            status=status.HTTP_500_INTERNAL_SERVER_ERROR
        )

    # 검증
    validation = validate_claude_feedback_format(raw_text)
    if not validation["is_valid"]:
        print("❌ Claude 응답에서 누락된 항목:", validation["missing_sections"])
    else:
        print("✅ 모든 항목 포함됨")

    # Claude 원본 응답 확인
    print("===== Claude 원본 응답 (raw_text) =====")
    print(raw_text)
    
    # 플레인 텍스트를 파싱해서 구조화된 dict로 변환
    feedback = parse_plain_feedback(raw_text)
    # feedback = parse_claude_feedback_and_score(raw_text)
    return Response(feedback)

    

def parse_claude_feedback_and_score(prompt: str) -> dict:
    """
    Claude API 호출 후 JSON 파싱 및 점수 계산을 수행합니다.
    실패 시 원시 응답과 함께 에러 메시지를 포함합니다.
    """

    feedback_raw = get_claude_feedback(prompt)

    try:
        feedback = json.loads(feedback_raw)
        feedback['score'] = calculate_score(feedback['chart'])
        return feedback
    except Exception as e:
        return {
            'error': 'Claude 응답 파싱 실패',
            'detail': str(e),
            'raw': feedback_raw
        }
    
#잘못된 자세 카운트
@api_view(['POST'])
def receive_posture_count(request):
    count = request.data.get('count')
    print(f"[백엔드 수신] 자세 count: {count}")
    return Response({"message": "count 수신 완료", "count": count})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def decide_followup_question(request):
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return Response({'error': 'Authorization 헤더가 없습니다.'}, status=401)
    
    token = auth_header.replace('Bearer ', '', 1).strip()
    headers = {
        "Authorization": f"Bearer {token}"
    }
    resume_text = request.data.get('resume_text')
    user_answer = request.data.get('user_answer')
    base_question_number = request.data.get('base_question_number')
    existing_question_numbers = request.data.get('existing_question_numbers', [])
    interview_id = request.data.get('interview_id')

    # 필수 값 검증
    if not all([resume_text, user_answer, base_question_number, interview_id]):
        return Response({'error': 'resume_text, user_answer, base_question_number, interview_id는 필수입니다.'}, status=400)

    # 1. 키워드 추출 및 follow-up 필요 여부 판단
    keywords = extract_resume_keywords(resume_text)
    should_generate = should_generate_followup(user_answer, keywords)
    matched_keywords = [kw for kw in keywords if kw in user_answer]

    if not should_generate:
        return Response({'followup': False, 'matched_keywords': matched_keywords})

    # 2. Claude 프롬프트 구성 및 질문 생성
    prompt = f"""
    사용자가 자기소개서에서 다음과 같은 키워드를 강조했습니다: {', '.join(keywords)}.
    이에 대해 다음과 같은 답변을 했습니다: "{user_answer}".
    특히 다음 키워드가 매칭되었습니다: {', '.join(matched_keywords)}.
    이 키워드를 바탕으로 follow-up 질문 1개만 자연스럽게 생성해주세요.
    질문은 면접관이 묻는 말투로 해주세요.
    """
    try:
        question = get_claude_followup_question(prompt).strip()
    except Exception as e:
        return Response({'error': 'Claude 호출 실패', 'detail': str(e)}, status=500)

    # 3. 새로운 follow-up 질문 번호 지정
    base_str = str(base_question_number)

    suffix_numbers = [
        int(q.split('-')[1])
        for q in existing_question_numbers
        if q.startswith(base_str + '-')
    ]
    next_suffix = max(suffix_numbers, default=0) + 1
    followup_question_number = f"{base_str}-{next_suffix}"

    # 4. S3에 질문 저장
    s3_client = boto3.client(
        "s3",
        aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY"),
    )

    followup_bucket = settings.AWS_FOLLOWUP_QUESTION_BUCKET_NAME
    s3_key = f"{interview_id}/{followup_question_number}.json"

    question_data = {
        "question_number": followup_question_number,
        "question": question
    }

    try:
        s3_client.put_object(
            Bucket=followup_bucket,
            Key=s3_key,
            Body=json.dumps(question_data).encode('utf-8'),
            ContentType='application/json'
        )
    except Exception as e:
        return Response({'error': 'S3 저장 실패', 'detail': str(e)}, status=500)


    sqs = boto3.client('sqs', region_name='ap-northeast-2')  # region은 실제 리전에 맞게 수정

    # SQS URL 정의
    QUEUE_URL = settings.AWS_SIMPLE_QUEUE_SERVICE

    email = request.user.email.split('@')[0]

    # SQS 메시지 구성 및 전달
    message = {
        "question_number": followup_question_number,
        "text": question,
        "headers" : headers
    }

    try:
        response = sqs.send_message(
            QueueUrl=QUEUE_URL,
            MessageBody=json.dumps(message),
            MessageGroupId=email,
            MessageDeduplicationId=f"{email}-{int(time.time() * 1000)}"
        )
        return Response({
            "message": "SQS에 요청 성공",
            "sqs_message_id": response['MessageId']
        }, status=200)

    except Exception as e:
        return Response({
            "error": "SQS 전송 중 예외 발생",
            "detail": str(e)
        }, status=500)



def get_claude_followup_question(prompt):

    client = boto3.client("bedrock-runtime", region_name="us-east-1")

    payload = {
        "anthropic_version": "bedrock-2023-05-31",
        "max_tokens": 512,
        "temperature": 0.7,
        "messages": [
            {
                "role": "user",
                "content": prompt
            }
        ]
    }

    response = client.invoke_model(
        modelId="anthropic.claude-3-haiku-20240307-v1:0",
        contentType="application/json",
        accept="application/json",
        body=json.dumps(payload)
     )

    result = json.loads(response["body"].read())
    return result["content"][0]["text"] if result.get("content") else "Claude 응답 없음"



class AudioUploadView(APIView):
    permission_classes = [IsAuthenticated]  # JWT 인증

    def post(self, request):
        email = request.data.get('email')
        question_id = request.data.get('question_id')
        transcript = request.data.get('transcript')

        # DB 저장 또는 파일로 저장
        print(f"[{email}] - 질문 {question_id}의 답변 전사 결과:")
        print(transcript)

        return Response({"message": "저장 완료!"})

@api_view(['POST'])
def save_transcribed_text(request):
    email = request.data.get("email")
    question_id = request.data.get("question_id")
    transcript = request.data.get("transcript")

    print("📨 Django 수신됨:")
    print("  - Email:", email)
    print("  - Question ID:", question_id)
    print("  - Transcript:", transcript[:100])  # 너무 길면 일부만 출력

    # 3) 즉시 응답
    return Response({
        "message": "음성 저장 완료 (텍스트는 잠시 후 생성됩니다)",
        "audio_path": request.data.get("audio_path"),
        "text_path": request.data.get("text_path")
    })

# 이력서를 불러와 텍스트 내용 추출 후 프론트엔드에 반환
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_resume_text(request):
    import PyPDF2
    import tempfile
    import boto3
    import requests

    try:
        # ✅ DB에서 이력서 레코드 가져오기
        resume = Resume.objects.get(user=request.user)
        file_url = resume.file_url
        key = file_url.split(f"{settings.AWS_S3_CUSTOM_DOMAIN}/")[-1]  # S3 key 추출

        # ✅ Presigned URL 생성
        s3 = boto3.client('s3',
                          aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                          aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                          region_name=settings.AWS_S3_REGION_NAME)

        url = s3.generate_presigned_url(
            ClientMethod='get_object',
            Params={'Bucket': settings.AWS_STORAGE_BUCKET_NAME, 'Key': key},
            ExpiresIn=60
        )

        # ✅ 다운로드 후 텍스트 추출
        r = requests.get(url)
        with tempfile.NamedTemporaryFile(delete=False, suffix=".pdf") as tmp:
            tmp.write(r.content)
            tmp.flush()

        with open(tmp.name, 'rb') as f:
            reader = PyPDF2.PdfReader(f)
            text = "\n".join(page.extract_text() for page in reader.pages if page.extract_text())

        return Response({'resume_text': text})

    except Resume.DoesNotExist:
        return Response({'error': '등록된 이력서가 없습니다.'}, status=404)
    except Exception as e:
        return Response({'error': str(e)}, status=500)

class FullVideoUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        uploaded_video = request.FILES.get("video")
        video_id = request.data.get("videoId")

        if not uploaded_video or not video_id:
            return Response({"error": "필수 값 누락"}, status=400)

        email_prefix = request.user.email.split('@')[0]
        key = f"videos/{email_prefix}/{video_id}.webm"

        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        try:
            s3.upload_fileobj(
                uploaded_video,
                settings.AWS_FULL_VIDEO_BUCKET_NAME,
                key,
                ExtraArgs={"ContentType": "video/webm"}
            )
            return Response({
                "message": "전체 영상 업로드 완료",
                "video_path": key
            })
        except Exception as e:
            return Response({"error": str(e)}, status=500)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def extract_bad_posture_clips(request):
    try:
        print("[🔍 segments 수신 내용]", request.data.get("segments"))
        video_id = request.data.get("videoId")
        segments = request.data.get("segments")
        feedbacks = request.data.get("feedbacks")

        if not video_id or not segments or not feedbacks:
            return Response({"error": "videoId, segments, feedbacks 필수"}, status=400)

        email_prefix = request.user.email.split('@')[0]
        video_key = f"videos/{email_prefix}/{video_id}.webm"

        # S3에서 전체 영상 다운로드
        s3 = boto3.client(
            "s3",
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        full_video_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".webm")
        s3.download_fileobj(settings.AWS_FULL_VIDEO_BUCKET_NAME, video_key, full_video_temp)
        full_video_temp.close()

        # webm → mp4 변환
        converted_video_path = convert_webm_to_mp4(full_video_temp.name)
        video = mp.VideoFileClip(converted_video_path)
        duration = video.duration

        results = []

        for idx, segment in enumerate(segments):
            try:
                start = max(0.0, float(segment["start"]))
                end   = min(duration, float(segment["end"]))
            except Exception as e:
                return Response({"error": f"start/end 변환 실패: {str(e)}"}, status=400)

            if end <= start:
                continue

            # 클립 추출
            clip = video.subclip(start, end)
            clip_path = tempfile.NamedTemporaryFile(delete=False, suffix=f"_clip_{idx+1}.mp4").name
            clip.write_videofile(clip_path, codec="libx264", audio_codec="aac", logger=None)

            # 클립 업로드
            clip_s3_key = f"clips/{email_prefix}/{video_id}_clip_{idx+1}.mp4"
            s3.upload_file(
                clip_path,
                settings.AWS_CLIP_VIDEO_BUCKET_NAME,
                clip_s3_key,
                ExtraArgs={"ContentType": "video/mp4"}
            )

            # 썸네일 생성 및 업로드
            thumbnail_path = tempfile.NamedTemporaryFile(delete=False, suffix=".jpg").name
            clip.save_frame(thumbnail_path, t=(end - start) / 2)
            thumbnail_s3_key = f"thumbnails/{email_prefix}/{video_id}_thumb_{idx+1}.jpg"
            s3.upload_file(
                thumbnail_path,
                settings.AWS_CLIP_VIDEO_BUCKET_NAME,
                thumbnail_s3_key,
                ExtraArgs={"ContentType": "image/jpeg"}
            )

            # presigned URL 생성
            clip_url = s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': settings.AWS_CLIP_VIDEO_BUCKET_NAME, 'Key': clip_s3_key},
                ExpiresIn=60 * 60
            )
            thumbnail_url = s3.generate_presigned_url(
                'get_object',
                Params={'Bucket': settings.AWS_CLIP_VIDEO_BUCKET_NAME, 'Key': thumbnail_s3_key},
                ExpiresIn=60 * 60
            )

            results.append({
                "clipUrl": clip_url,
                "thumbnailUrl": thumbnail_url,
                "feedback": feedbacks[idx] if idx < len(feedbacks) else ""
            })

        return Response({
            "message": "클립 저장 완료",
            "clips": results,
        })

    except Exception as e:
        print("🔥 클립 추출 예외:", traceback.format_exc())
        return Response({"error": str(e)}, status=500)

def convert_webm_to_mp4(input_path):
    output_path = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4").name
    command = [
        "ffmpeg",
        "-y",
        "-i", input_path,
        "-c:v", "libx264",
        "-preset", "fast",
        "-crf", "23",
        "-c:a", "aac",
        output_path
    ]
    subprocess.run(command, check=True)
    return output_path

def convert_webm_to_mp4(input_path):
    output_path = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4").name
    command = [
        "ffmpeg",
        "-y",
        "-i", input_path,
        "-c:v", "libx264",
        "-preset", "fast",
        "-crf", "23",
        "-c:a", "aac",
        output_path
    ]
    subprocess.run(command, check=True)
    return output_path

def merge_texts_from_s3_folder(email_prefix, upload_id):
    import boto3
    
    bucket_name = settings.AWS_AUDIO_BUCKET_NAME

    prefix = f"{email_prefix}/{upload_id}/text/"
    s3 = boto3.client('s3')

    response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    if 'Contents' not in response:
        return ""

    txt_keys = [
        obj['Key']
        for obj in response['Contents']
        if obj['Key'].endswith(".txt")
    ]

    merged_text = ""
    for key in sorted(txt_keys):
        obj = s3.get_object(Bucket=bucket_name, Key=key)
        content = obj['Body'].read().decode('utf-8')
        merged_text += content.strip() + "\n\n"

    return merged_text.strip()

@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_all_questions_view(request):
    email_prefix = request.user.email.split('@')[0]

    def fetch_questions(bucket_name):
        s3 = boto3.client('s3')
        prefix = f"{email_prefix}/"
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
        result = {}
        for obj in response.get('Contents', []):
            key = obj['Key']
            if key.endswith('.txt'):
                question_number = Path(key).stem.replace("질문", "")
                content = s3.get_object(Bucket=bucket_name, Key=key)['Body'].read().decode('utf-8')
                result[question_number] = content.strip()
        return result

    base_questions = fetch_questions('resume-questions')
    followup_questions = fetch_questions('knok-followup-questions')

    merged = {**base_questions, **followup_questions}

    def safe_key(k):
        parts = k.split('-')
        return [(0, int(p)) if p.isdigit() else (1, p) for p in parts]
    
    sorted_merged = dict(sorted(
        merged.items(),
        key=lambda x: safe_key(x[0])
    ))

    return Response({"questions": sorted_merged})
  
def get_interview_question_audio_list(request):
    email = request.user.email
    email_prefix = email.split('@')[0]

    interview_id = request.query_params.get('interview_id')  # e.g., "0614-2"
    if not interview_id:
        return Response({'error': 'interview_id 파라미터가 필요합니다.'}, status=400)

    bucket_name = settings.AWS_TTS_BUCKET_NAME
    prefix = f"{email_prefix}/{interview_id}/"

    s3 = boto3.client('s3',
                      aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                      region_name=settings.AWS_S3_REGION_NAME)

    try:
        response = s3.list_objects_v2(Bucket=bucket_name, Prefix=prefix)
    except Exception as e:
        return Response({'error': 'S3 접근 실패', 'detail': str(e)}, status=500)

    if 'Contents' not in response:
        return Response([], status=200)

    audio_files = [obj['Key'] for obj in response['Contents'] if obj['Key'].endswith('.mp3')]

    def parse_question_info(file_name):
        file_stem = os.path.splitext(os.path.basename(file_name))[0]
        match = re.match(r"질문(\d+(?:-\d+)?)", file_stem)
        return match.group(1) if match else None

    def sort_key(file_name):
        number = parse_question_info(file_name)
        if not number:
            return (float('inf'),)
        return tuple(int(part) for part in number.split('-'))

    audio_files.sort(key=sort_key)

    result = []
    for file_key in audio_files:
        number = parse_question_info(file_key)
        if not number:
            continue

        parent_number = number.split("-")[0] if "-" in number else None

        result.append({
            "question_number": number,
            "parent_number": parent_number,
            "audio_url": f"https://{bucket_name}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{file_key}"
        })

    return Response(result, status=200)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def download_feedback_zip(request):
    """
    클립 + 리포트 PDF가 있는 S3 경로의 파일들을 ZIP으로 묶어 반환
    """
    import zipfile
    import tempfile
    import os

    email_prefix = request.user.email.split('@')[0]
    video_id = request.data.get("videoId")
    if not video_id:
        return Response({"error": "videoId는 필수입니다."}, status=400)

    prefix = f"clips/{email_prefix}/{video_id}_"
    bucket = settings.AWS_CLIP_VIDEO_BUCKET_NAME
    s3 = boto3.client('s3')

    # ✅ prefix로 S3 객체 목록 조회
    objects = s3.list_objects_v2(Bucket=bucket, Prefix=f"clips/{email_prefix}/")
    if 'Contents' not in objects:
        return Response({"error": "해당 경로에 파일이 없습니다."}, status=404)

    target_keys = [
        obj['Key']
        for obj in objects['Contents']
        if obj['Key'].startswith(prefix) and (obj['Key'].endswith('.mp4') or obj['Key'].endswith('.pdf'))
    ]

    if not target_keys:
        return Response({"error": "클립 또는 PDF 파일이 없습니다."}, status=404)

    # ✅ zip 파일을 임시로 생성
    tmp_zip = tempfile.NamedTemporaryFile(delete=False, suffix=".zip")
    zip_path = tmp_zip.name
    tmp_zip.close()

    with zipfile.ZipFile(zip_path, 'w') as zipf:
        for key in target_keys:
            local_path = tempfile.NamedTemporaryFile(delete=False).name
            s3.download_file(bucket, key, local_path)
            zipf.write(local_path, arcname=os.path.basename(key))
            os.remove(local_path)  # 임시 다운로드 파일 제거

    
    if not os.path.exists(zip_path):
        print("❌ ZIP 파일 생성 실패:", zip_path)
        return Response({"error": "ZIP 파일이 존재하지 않습니다."}, status=500)

    response = FileResponse(open(zip_path, 'rb'), as_attachment=True, filename=os.path.basename(zip_path))
    response['Content-Type'] = 'application/zip'
    return response

    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def upload_feedback_pdf(request):
    file = request.FILES.get("file")
    video_id = request.POST.get("videoId")
    if not file or not video_id:
        return Response({"error": "file, videoId 필수"}, status=400)

    email_prefix = request.user.email.split('@')[0]
    pdf_key = f"clips/{email_prefix}/{video_id}_report.pdf"

    s3 = boto3.client("s3",
                      aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                      region_name=settings.AWS_S3_REGION_NAME)
    s3.upload_fileobj(file, settings.AWS_CLIP_VIDEO_BUCKET_NAME, pdf_key,
                      ExtraArgs={"ContentType": "application/pdf"})

    url = f"https://{settings.AWS_CLIP_VIDEO_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{pdf_key}"
    return Response({"pdf_url": url})

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"

@csrf_exempt
def send_to_slack(request):
    if request.method == "POST":
        try:
            print("요청 수신됨")
            print("request.body:", request.body)

            data = json.loads(request.body)
            name = data.get("name", "이름 없음")
            email = data.get("email", "이메일 없음")
            message = data.get("message", "내용 없음")

            slack_data = {
                "text": f"📩 *새 문의가 도착했습니다!*\n\n👤 이름: {name}\n📧 이메일: {email}\n📝 내용: {message}"
            }

            response = requests.post(
                SLACK_WEBHOOK_URL,
                json=slack_data,
                headers={"Content-Type": "application/json"}
            )

            print("슬랙 응답 코드:", response.status_code)
            print("슬랙 응답 내용:", response.text)

            if response.status_code == 200:
                return JsonResponse({"success": True})
            else:
                return JsonResponse({"success": False, "error": response.text}, status=500)

        except Exception as e:
            print("예외 발생:")
            traceback.print_exc()
            return JsonResponse({"success": False, "error": str(e)}, status=500)

    return JsonResponse({"error": "POST 요청만 지원됩니다."}, status=400)

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def end_interview_session(request):
    interview_id= request.data.get('interview_id')
    if not interview_id:
        return Response({'error': 'interview_id는 필수입니다.'}, status=400)

    email_prefix = request.user.email.split('@')[0]

    # 삭제할 버킷들
    targets = [
        (settings.AWS_FOLLOWUP_QUESTION_BUCKET_NAME, f"{email_prefix}/{interview_id}/"),
        (settings.AWS_AUDIO_BUCKET_NAME, f"{email_prefix}/{interview_id}/"),
        (settings.AWS_CLIP_VIDEO_BUCKET_NAME, f"clips/{email_prefix}/{interview_id}_"),
        (settings.AWS_FULL_VIDEO_BUCKET_NAME, f"videos/{email_prefix}/{interview_id}.webm"),
        # 추가적으로 필요한 경로들
    ]

    s3 = boto3.client('s3',
                      aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                      aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                      region_name=settings.AWS_S3_REGION_NAME)

    deleted_files = []

    for bucket, prefix in targets:
        if prefix.endswith('.webm'):  # 단일 파일
            try:
                s3.delete_object(Bucket=bucket, Key=prefix)
                deleted_files.append(prefix)
            except Exception as e:
                print(f"❌ 단일 파일 삭제 실패: {prefix} → {e}")
        else:
            response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
            for obj in response.get('Contents', []):
                s3.delete_object(Bucket=bucket, Key=obj['Key'])
                deleted_files.append(obj['Key'])

    return Response({
        'message': '면접 세션 종료 및 데이터 정리 완료',
        'deleted': deleted_files
    })
# TTS 음성파일 가져오기
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_ordered_question_audio(request):
    user = request.user
    email_prefix = user.email.split('@')[0]
    bucket = settings.AWS_TTS_BUCKET_NAME
    prefix = f'{email_prefix}/'
    #
    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )

    response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    if 'Contents' not in response:
        print("⚠️ S3 목록이 비어있습니다.")
        return Response([], status=200)

    wav_files = [obj['Key'] for obj in response['Contents'] if obj['Key'].endswith('.wav')]
    print("🔍 S3에서 찾은 wav 파일들:", wav_files)

    def parse_question_info(key):
        filename = key.split('/')[-1].replace('.wav', '').replace('질문 ', '')
        match = re.match(r"^(\d+)(?:-(\d+))?$", filename)
        if not match:
            print(f"❌ 정규식 매칭 실패: {filename}")
            return None
        major = int(match.group(1))
        minor = int(match.group(2)) if match.group(2) else 0
        order = major + minor * 0.01
        question_id = f"q{filename.replace('-', '_')}"
        parent_id = f"q{major}" if minor else None
        encoded_key = quote(key)
        audio_url = f"https://{bucket}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{encoded_key}"
        print(f"✅ 파싱 성공: {question_id}, {audio_url}")
        return {
            "id": question_id,
            "audio_url": audio_url,
            "order": order,
            "parent_id": parent_id
        }

    parsed = [parse_question_info(key) for key in wav_files]
    print("🧾 파싱된 결과:", parsed)

    results = list(filter(None, parsed))
    results = sorted(results, key=lambda x: x["order"])
    return Response(results)


@api_view(['POST'])
@permission_classes([IsAuthenticated])
def decide_resume_question(request):
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return Response({'error': 'Authorization 헤더가 없습니다.'}, status=401)
    
    token = auth_header.replace('Bearer ', '', 1).strip()
    headers = {
        "Authorization": f"Bearer {token}"
    }

    tts_url = "http://13.209.16.252:8002/api/generate-resume-question/"
    try:
        # 외부 POST 요청 (body 없음)
        tts_response = requests.post(tts_url, headers=headers)

        # 응답 상태 코드 확인
        if tts_response.status_code != 200:
            return Response({
                "error": "Resume TTS 생성 실패",
                "detail": tts_response.json()
            }, status=tts_response.status_code)

        # 성공 응답 반환
        return Response({
            "message": "Resume TTS 호출 성공",
            "result": tts_response.json()
        }, status=200)

    except requests.exceptions.RequestException as e:
        return Response({
            "error": "Resume TTS 호출 중 예외 발생",
            "detail": str(e)
        }, status=500)

@csrf_exempt
@require_http_methods(["GET", "HEAD"])
def health_check(request):
    return JsonResponse({"status": "ok"})