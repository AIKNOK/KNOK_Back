from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from pydub import AudioSegment

import json
import whisper
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

from django.conf import settings
from .models import Resume
from .serializers import ResumeSerializer
from django.http import JsonResponse
from pathlib import Path


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
    except client.exceptions.NotAuthorizedException:
        return Response({'error': '아이디 또는 비밀번호 오류'}, status=400)
    except Exception as e:
        return Response({'error': str(e)}, status=400)


# 🚪 로그아웃 API
@api_view(['POST'])
@authentication_classes([])  # 인증 미적용
@permission_classes([])      # 권한 미적용
def logout_view(request):
    token = request.headers.get('Authorization')
    if not token:
        return Response({'error': 'Authorization 헤더가 없습니다.'}, status=400)

    token = token.replace('Bearer ', '')

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
        uploaded_file = request.FILES.get('resume')
        if not uploaded_file:
            return Response({"error": "파일이 없습니다."}, status=400)

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
        resume_obj, _ = Resume.objects.update_or_create(
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
    bucket_in = settings.AWS_STORAGE_BUCKET_NAME
    bucket_out = 'resume-questions'

    s3 = boto3.client(
        's3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )

    prefix = f"resumes/{email_prefix}/"
    response = s3.list_objects_v2(Bucket=bucket_in, Prefix=prefix)
    pdf_files = [
        obj['Key'] for obj in response.get('Contents', [])
        if obj['Key'].endswith('.pdf')
    ]

    if not pdf_files:
        return Response({"error": "PDF 파일이 존재하지 않습니다."}, status=404)

    key = pdf_files[0]
    temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf")
    s3.download_fileobj(bucket_in, key, temp_file)
    temp_file.close()

    with open(temp_file.name, 'rb') as f:
        reader = PyPDF2.PdfReader(f)
        text = "\n".join(
            page.extract_text() for page in reader.pages if page.extract_text()
        )

    prompt = f"""
    다음은 이력서 내용입니다:
    {text}

    위 이력서를 바탕으로 면접 질문 3개를 만들어주세요.
    형식은 아래와 같이 해주세요:
    질문1: ...
    질문2: ...
    질문3: ...
    """

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

    questions = [line for line in content.strip().split('\n') if line.strip()]
    for idx, question in enumerate(questions[:3], start=1):
        filename = f"{email_prefix}/질문{idx}.txt"
        s3.put_object(
            Bucket=bucket_out,
            Key=filename,
            Body=question.encode('utf-8'),
            ContentType='text/plain'
        )

    return Response({"message": "질문 저장 완료", "questions": questions[:3]})


# 🔄 답변 업로드 API (음성 + 전사) 
class UploadAnswerView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        audio_file = request.FILES.get('audio')
        transcript = request.data.get('transcript', '')
        question_id = request.data.get('questionId', 'unknown')
        if not audio_file:
            return Response({"error": "audio 파일이 없습니다."}, status=400)

        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )
        now = int(time.time())
        key_audio = f"audio/{question_id}/{now}.webm"
        key_text = f"text/{question_id}/{now}.txt"
        try:
            s3.upload_fileobj(
                audio_file,
                settings.AWS_STORAGE_BUCKET_NAME,
                key_audio,
                ExtraArgs={'ContentType': 'audio/webm'}
            )
            s3.put_object(
                Bucket=settings.AWS_STORAGE_BUCKET_NAME,
                Key=key_text,
                Body=transcript.encode('utf-8'),
                ContentType='text/plain'
            )
        except Exception as e:
            return Response({"error": f"S3 업로드 실패: {str(e)}"}, status=500)

        return Response({"message": "업로드 성공", "audio_key": key_audio, "text_key": key_text})


# 📝 인터뷰 피드백 생성 API
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_feedback_view(request):
    session_id = request.data.get('sessionId')
    posture_count = request.data.get('posture_count', 0)

    # (예시) S3에서 녹음 파일들을 모아서 병합하고, 음성·자세 분석 및 Claude 호출
    # 실제 로직은 필요한 분석 함수들을 호출하여 처리해주세요.

    feedback_id = f"feedback_{int(time.time())}"
    return Response({'feedbackId': feedback_id})


# API 뷰: 전체 분석 + 프롬프트
@api_view(['POST'])
def analyze_voice_api(request):
    start_time = time.time()

    bucket = 'whisper-testt'
    prefix = 'audio/'

    posture_count = request.data.get('posture_count', 0)

    try:
        # 1. 다중 오디오 다운로드 및 병합
        audio_files = download_multiple_audios_from_s3(bucket, prefix)
        merged_audio_path = merge_audio_files(audio_files)

        # 🔍 병합된 오디오 길이 확인 로그
        y, sr = librosa.load(merged_audio_path)
        print("\u23f1 병합된 오디오 길이 (초):", librosa.get_duration(y=y, sr=sr))

        # 2. 분석 시작
        pitch_result = analyze_pitch(merged_audio_path)
        speech_rate = analyze_speech_rate(merged_audio_path)
        silence_ratio = analyze_silence_ratio(merged_audio_path)
        emotion = analyze_emotion(merged_audio_path)

        result = {
            **pitch_result,
            'speech_rate': speech_rate,
            'silence_ratio': silence_ratio,
            'emotion': emotion,
            'posture_count': posture_count
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


# 잘못된 자세 카운트 수신
@api_view(['POST'])
def receive_posture_count(request):
    count = request.data.get('count')
    print(f"[백엔드 수신] 자세 count: {count}")
    return Response({"message": "count 수신 완료", "count": count})


# — 아래 유틸 함수들은 기존 그대로 유지 — #

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

def analyze_pitch(file_path):
    y, sr = librosa.load(file_path, sr=None)
    pitches, magnitudes = librosa.piptrack(y=y, sr=sr)
    pitch_values = pitches[pitches > 0]
    pitch_std = np.std(pitch_values)
    return {
        'pitch_std': float(round(pitch_std, 2)),
        'voice_tremor': '감지됨' if pitch_std > 20 else '안정적'
    }

def analyze_speech_rate(file_path):
    try:
        model = whisper.load_model("base")
        result = model.transcribe(file_path)
        words = result["text"].split()
        word_count = len(words)

        y, sr = librosa.load(file_path, sr=None)
        duration = librosa.get_duration(y=y, sr=sr)

        if duration == 0:
            return 0.0

        return round(word_count / duration, 2)
    except Exception as e:
        print("❌ 말 속도 분석 실패:", e)
        return 0.0

def analyze_silence_ratio(file_path):
    y, sr = librosa.load(file_path)
    intervals = librosa.effects.split(y, top_db=30)
    total_duration = librosa.get_duration(y=y, sr=sr)
    speech_duration = sum((end - start) for start, end in intervals) / sr
    silence_ratio = 1 - (speech_duration / total_duration)
    return round(silence_ratio, 2)

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

def create_prompt(analysis):
    posture_count = analysis.get("posture_count", None)
    posture_desc = f"면접 중 총 {posture_count}회의 자세 흔들림이 감지되었습니다. 이 수치를 바탕으로 면접 자세에 대한 피드백을 자연스럽게 작성해주세요."
    voice_desc = f"""
- 목소리 떨림: {analysis['voice_tremor']}
- Pitch 표준편차: {analysis['pitch_std']}
- 말 속도: {analysis['speech_rate']} 단어/초
- 침묵 비율: {analysis['silence_ratio'] * 100:.1f}%
- 감정 상태: {analysis['emotion']}
"""
    return f"""
당신은 면접 코치입니다. 아래는 면접자의 분석 데이터입니다.

[음성 분석 결과]
{voice_desc}

[자세 분석 결과]
{posture_desc}

위 데이터를 바탕으로 각각 "음성 피드백"과 "자세 피드백"을 2~3문장으로 각각 나누어 제공해주세요.
"""

def get_claude_feedback(prompt):
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
    result = json.loads(response["body"].read())
    return result["content"][0]["text"] if result.get("content") else "Claude 응답 없음"
