from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.decorators import authentication_classes, permission_classes

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


# 📤 이력서 업로드 API (S3 저장, DB 기록, 중복 업로드 차단)
class ResumeUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file = request.FILES.get('resume')
        if not file:
            return Response({"error": "파일이 없습니다."}, status=400)

        # ✅ 이미 업로드된 이력서가 있는 경우 업로드 차단
        if Resume.objects.filter(user=request.user).exists():
            return Response({"error": "이미 이력서를 업로드하셨습니다. 삭제 후 다시 업로드하세요."}, status=400)

        # ✅ 이메일의 @ 앞부분만 사용
        email_prefix = request.user.email.split('@')[0]
        filename = f"resumes/{email_prefix}/resume.pdf"

        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        try:
            s3.upload_fileobj(file, settings.AWS_STORAGE_BUCKET_NAME, filename)
        except Exception as e:
            return Response({"error": f"S3 업로드 실패: {str(e)}"}, status=500)

        file_url = f"https://{settings.AWS_S3_CUSTOM_DOMAIN}/{filename}"

        resume = Resume.objects.create(user=request.user, file_url=file_url)
        serializer = ResumeSerializer(resume)
        return Response(serializer.data, status=201)


# 🗑️ 이력서 삭제 API (S3 삭제 + DB 삭제)
class ResumeDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        resume = Resume.objects.filter(user=request.user).first()
        if not resume:
            return Response({"error": "업로드된 이력서가 없습니다."}, status=404)

        # S3 경로 추출
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
def download_audio_from_s3(bucket, key):
    s3 = boto3.client('s3')
    temp = tempfile.NamedTemporaryFile(delete=False)
    s3.download_fileobj(bucket, key, temp)
    return temp.name

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

# ✅ 2. 말 속도 분석 (whisper 사용)
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
    return f"""
사용자의 면접 음성 분석 결과는 다음과 같습니다:

- 목소리 떨림: {analysis['voice_tremor']}
- Pitch 표준편차: {analysis['pitch_std']}
- 말 속도: {analysis['speech_rate']} 단어/초
- 침묵 비율: {analysis['silence_ratio'] * 100:.1f}%
- 감정 상태: {analysis['emotion']}

이 데이터를 바탕으로 면접자가 개선할 점과 칭찬할 점을 포함한 피드백을 자연스럽게 2~3문장으로 작성해주세요.
"""

# API 뷰: 전체 분석 + 프롬프트
@api_view(['GET'])
def analyze_voice_api(request):
    bucket = 'whisper-testt'
    key = 'audio/input.wav'

    try:
        audio_path = download_audio_from_s3(bucket, key)

        pitch_result = analyze_pitch(audio_path)
        speech_rate = analyze_speech_rate(audio_path)
        silence_ratio = analyze_silence_ratio(audio_path)
        emotion = analyze_emotion(audio_path)

        result = {
            **pitch_result,
            'speech_rate': speech_rate,
            'silence_ratio': silence_ratio,
            'emotion': emotion
        }

        prompt = create_prompt(result)
        feedback = get_claude_feedback(prompt)

        return JsonResponse(
            json.loads(json.dumps({
                'analysis': result,
                'prompt_to_claude': prompt,
                'claude_feedback': feedback
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

