from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import authentication_classes, permission_classes
from pydub import AudioSegment
from myapp.utils.keyword_extractor import extract_resume_keywords
from myapp.utils.followup_logic import should_generate_followup
from myapp.utils.token_utils import decode_cognito_id_token
from urllib.parse import quote 


import re
import json
import boto3
import hmac
import hashlib
import base64
import uuid
import tempfile
import librosa
import numpy as np
import parselmouth
import time
import PyPDF2
import moviepy.editor as mp
import subprocess
import os

from django.conf import settings
from .models import Resume
from .serializers import ResumeSerializer
from django.http import JsonResponse
from pathlib import Path
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator
from datetime import datetime
from reportlab.pdfgen import canvas  # or your preferred PDF lib
from reportlab.lib.pagesizes import A4

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
    permission_classes = [IsAuthenticated]

    def post(self, request):
        # 1) 파일 유무 체크
        uploaded_file = request.FILES.get('resume')
        if not uploaded_file:
            return Response({"error": "파일이 없습니다."}, status=400)

        # ✅ 2) 사용자 이메일 + 원본 파일명으로 S3 경로 구성
        email_prefix = request.user.email.split('@')[0]
        original_filename = uploaded_file.name
        key = f"resumes/{email_prefix}/{original_filename}"

        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        try:
            s3.upload_fileobj(uploaded_file, settings.AWS_STORAGE_BUCKET_NAME, key)
        except Exception as e:
            return Response({"error": f"S3 업로드 실패: {str(e)}"}, status=500)

        file_url = f"https://{settings.AWS_S3_CUSTOM_DOMAIN}/{key}"

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
@permission_classes([IsAuthenticated])
def get_resume_view(request):
    try:
        resume = Resume.objects.get(user=request.user)
        return Response({'file_url': resume.file_url}, status=200)
    except Resume.DoesNotExist:
        return Response({'file_url': None}, status=200)

# 🧠 Claude에게 이력서 기반으로 질문 요청
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_resume_questions(request):
    user = request.user
    email_prefix = user.email.split('@')[0]
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
    prompt = f"""
    다음은 이력서 내용입니다:
    {text}

    위 이력서를 바탕으로 면접 질문 3개를 만들어주세요.
    형식은 아래와 같이 해주세요:

    - 질문 앞에 숫자나 '질문 1)', '1.', 'Q1' 등의 접두어는 절대 붙이지 마세요.
    - 그냥 질문 내용만 문장 형태로 자연스럽게 출력해주세요.
    - 줄바꿈으로 구분해 주세요.

    예시 출력 형식:
    지원하신 직무와 관련해 가장 자신 있는 기술 스택은 무엇인가요?
    해당 기술을 활용해 문제를 해결했던 경험을 말씀해 주세요.
    팀 프로젝트에서 본인이 맡았던 역할과 해결한 기술적 문제는 무엇이었나요?
    """

    # Claude 호출
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
    
    final_questions = ["간단히 자기소개 부탁드릴게요"] + questions[:3]
    
    for idx, question in enumerate(final_questions, start=1):
        filename = f"{email_prefix}/질문{idx}.txt"
        s3.put_object(
            Bucket=bucket_out,
            Key=filename,
            Body=question.encode('utf-8'),
            ContentType='text/plain'
        )

    return Response({"message": "질문 저장 완료", "questions": final_questions})



# Claude 3 호출 함수 추가
def get_claude_feedback(prompt):
    client = boto3.client("bedrock-runtime", region_name="us-east-1")

    body = {
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
        body=json.dumps(body)
    )

    result = json.loads(response["body"].read())
    return result["content"][0]["text"] if result.get("content") else "Claude 응답 없음"

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

# 🧠 Claude 3에게 보낼 프롬프트 생성
def create_prompt(analysis):
    posture_count = analysis.get("posture_count", None)

    # ✅ 자세 설명 프롬프트
    posture_desc = f"면접 중 총 {posture_count}회의 자세 흔들림이 감지되었습니다. 이 수치를 바탕으로 면접 자세에 대한 피드백을 자연스럽게 작성해주세요."

    # ✅ 음성 분석 설명
    voice_desc = f"""
- 목소리 떨림: {analysis['voice_tremor']}
- Pitch 표준편차: {analysis['pitch_std']}
- 말 속도: {analysis['speech_rate']} 단어/초
- 침묵 비율: {analysis['silence_ratio'] * 100:.1f}%
- 감정 상태: {analysis['emotion']}
"""
    # 면접자의 전체 답변(텍스트)
    transcribe_desc = analysis['transcribe_text']
    
    # ✅ 최종 프롬프트
    return f"""
당신은 면접 코치입니다. 아래는 면접자의 분석 데이터입니다.

[전체 답변 결과]
{transcribe_desc}

[음성 분석 결과]
{voice_desc}

[자세 분석 결과]
{posture_desc}

위 데이터를 바탕으로 면접자의 답변을 다음 기준으로 피드백을 제시해주세요:
1. 일관성: 답변 전체에 흐름이 있고 앞뒤가 자연스럽게 연결되는가?
2. 논리성: 주장에 대해 명확한 이유와 근거가 있으며 논리적 흐름이 있는가?
3. 대처능력: 예상치 못한 질문에도 당황하지 않고 유연하게 답했는가?
4. 구체성: 추상적인 설명보다 구체적인 경험과 예시가 포함되어 있는가?
5. 음성 피드백 : 음성 분석 결과를 기준으로 피드백을 제시해주세요.
6. 자세 피드백 : 자세 분석 결과를 기준으로 피드백을 제시해주세요.

각 피드백 결과는 2~3문장 정도의 길이로 생성하고, 최대한 핵심적인 요소를 강조해주세요.
"""

def analyze_speech_rate_via_transcribe(transcribed_text, audio_path):
    y, sr = librosa.load(audio_path, sr=None)
    duration = librosa.get_duration(y=y, sr=sr)
    words = transcribed_text.strip().split()
    word_count = len(words)
    if duration == 0:
        return 0
    return round(word_count / duration, 2)  # 단어 수 ÷ 총 시간(초)

# API 뷰: 전체 분석 + 프롬프트
@api_view(['POST'])
def analyze_voice_api(request):
    start_time = time.time()

    bucket = 'whisper-testt'
    prefix = 'audio/'  # 여러 질문 오디오가 여기에 저장되어 있다고 가정

    posture_count = request.data.get('posture_count', 0)

    try:
        # 1. 다중 오디오 다운로드 및 병합
        audio_files = download_multiple_audios_from_s3(bucket, prefix)
        merged_audio_path = merge_audio_files(audio_files)

        # 🔍 병합된 오디오 길이 확인 로그 (디버깅용)
        y, sr = librosa.load(merged_audio_path)
        print("\u23f1 병합된 오디오 길이 (초):", librosa.get_duration(y=y, sr=sr))

        # ✅ Transcribe 분석 (STT 텍스트 추출)
        s3_key = "merged/merged_audio.wav"
        upload_merged_audio_to_s3(merged_audio_path, bucket, s3_key)
        transcribe_text = merge_texts_from_s3_folder(email_prefix, upload_id, bucket)

        # 2. 분석 시작
        pitch_result = analyze_pitch(merged_audio_path)
        speech_rate = analyze_speech_rate_via_transcribe(merged_audio_path)
        silence_ratio = analyze_silence_ratio(merged_audio_path)
        emotion = analyze_emotion(merged_audio_path)

        result = {
            **pitch_result,
            'speech_rate': speech_rate,
            'silence_ratio': silence_ratio,
            'emotion': emotion,
            'posture_count': posture_count,
        }

        prompt = create_prompt(result)
        feedback = get_claude_feedback(prompt)

        elapsed_time = round(time.time() - start_time, 2)

        return JsonResponse(
            json.loads(json.dumps({
                'analysis': result,
                'prompt_to_claude': prompt,
                'claude_feedback': feedback,
                'response_time_seconds': elapsed_time
            }, ensure_ascii=False, indent=4)),
            json_dumps_params={'ensure_ascii': False}
        )

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)
    
#잘못된 자세 카운트
@api_view(['POST'])
def receive_posture_count(request):
    count = request.data.get('count')
    print(f"[백엔드 수신] 자세 count: {count}")
    return Response({"message": "count 수신 완료", "count": count})

@api_view(['POST'])
@permission_classes([IsAuthenticated])
def decide_followup_question(request):
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
    suffix_numbers = [
        int(q.split('-')[1])
        for q in existing_question_numbers
        if q.startswith(base_question_number + '-')
    ]
    next_suffix = max(suffix_numbers, default=0) + 1
    followup_question_number = f"{base_question_number}-{next_suffix}"

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

    return Response({
        'followup': True,
        'question_number': followup_question_number,
        'question': question,
        'matched_keywords': matched_keywords
    })



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
    import traceback
    try:
        video_id = request.data.get("videoId")
        segments = request.data.get("segments")
        feedback_text = request.data.get("feedback_text", "면접 분석 피드백 PDF 예시입니다.")  # 프론트에서 분석문 전달하면 여기에
        if not video_id or not segments:
            return Response({"error": "videoId, segments 필수"}, status=400)

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

        # webm → mp4 변환 (MoviePy 지원용)
        converted_video_path = convert_webm_to_mp4(full_video_temp.name)
        video = mp.VideoFileClip(converted_video_path)

        # 1) 클립 추출 및 임시파일 저장
        clip_file_paths = []
        for idx, segment in enumerate(segments):
            start = float(segment["start"])
            end = float(segment["end"])
            clip = video.subclip(start, end)
            clip_path = tempfile.NamedTemporaryFile(delete=False, suffix=f"_clip_{idx+1}.mp4").name
            clip.write_videofile(clip_path, codec="libx264", audio_codec="aac", logger=None)
            clip_file_paths.append(clip_path)

        # 2) PDF 생성
        pdf_bytes = io.BytesIO()
        c = canvas.Canvas(pdf_bytes, pagesize=A4)
        c.setFont("Helvetica-Bold", 16)
        c.drawString(100, 800, "면접 피드백 리포트")
        c.setFont("Helvetica", 12)
        c.drawString(100, 780, f"Video ID: {video_id}")
        c.drawString(100, 760, f"클립 수: {len(clip_file_paths)}")
        # 여러 줄 피드백 표시 (간단한 예시)
        for i, line in enumerate(feedback_text.split("\n")):
            c.drawString(100, 730 - i*18, line)
        c.save()
        pdf_bytes.seek(0)

        # 3) ZIP 버퍼에 PDF + 클립 묶기
        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, 'w') as zf:
            # PDF 추가
            zf.writestr("interview-feedback.pdf", pdf_bytes.read())
            # 클립들 추가
            for path in clip_file_paths:
                zf.write(path, arcname=Path(path).name)
        zip_buffer.seek(0)

        # 4) FileResponse로 zip 다운로드
        response = FileResponse(
            zip_buffer,
            as_attachment=True,
            filename=f"{video_id}_feedback.zip"
        )
        return response

    except Exception as e:
        print("🔥 클립 zip 추출 예외:", traceback.format_exc())
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
    sorted_merged = dict(sorted(
        merged.items(),
        key=lambda x: [int(part) if part.isdigit() else part for part in x[0].split('-')]
    ))

    return Response({"questions": sorted_merged})
  
# TTS 음성파일 가져오기
@api_view(['GET'])
@permission_classes([IsAuthenticated])
def get_ordered_question_audio(request):
    user = request.user
    email_prefix = user.email.split('@')[0]
    bucket = settings.AWS_TTS_BUCKET_NAME
    prefix = f'tts_outputs/dlrjsgh8529/'
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

