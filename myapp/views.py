from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status
from rest_framework.decorators import authentication_classes, permission_classes
from pydub import AudioSegment
from myapp.utils.keyword_extractor import extract_resume_keywords
from myapp.utils.followup_logic import should_generate_followup
from myapp.utils.token_utils import decode_cognito_id_token
from datetime import datetime

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
    pdf_files = [obj['Key'] for obj in response.get('Contents', []) if obj['Key'].endswith('.pdf')]

    if not pdf_files:
        return Response({"error": "PDF 파일이 존재하지 않습니다."}, status=404)

    # ✅ 첫 번째 PDF 파일 선택
    key = pdf_files[0]

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
    질문1: ...
    질문2: ...
    질문3: ...
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
    for idx, question in enumerate(questions[:3], start=1):
        filename = f"{email_prefix}/질문{idx}.txt"
        s3.put_object(
            Bucket=bucket_out,
            Key=filename,
            Body=question.encode('utf-8'),
            ContentType='text/plain'
        )

    return Response({"message": "질문 저장 완료", "questions": questions[:3]})



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

def start_transcribe_and_get_text(bucket, key):
    import requests
    transcribe = boto3.client('transcribe', region_name='ap-northeast-2')
    job_name = f"job-{uuid.uuid4()}"

    job_uri = f"https://{bucket}.s3.ap-northeast-2.amazonaws.com/{key}"

    transcribe.start_transcription_job(
        TranscriptionJobName=job_name,
        Media={'MediaFileUri': job_uri},
        MediaFormat='wav',
        LanguageCode='ko-KR'
    )

    # 결과 기다리기
    while True:
        result = transcribe.get_transcription_job(TranscriptionJobName=job_name)
        status = result['TranscriptionJob']['TranscriptionJobStatus']
        if status in ['COMPLETED', 'FAILED']:
            break
        time.sleep(3)

    if status == 'COMPLETED':
        transcript_url = result['TranscriptionJob']['Transcript']['TranscriptFileUri']
        response = requests.get(transcript_url)
        transcript_json = response.json()
        return transcript_json['results']['transcripts'][0]['transcript']
    else:
        raise Exception("Transcription 실패")
    

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

    # ✅ 최종 프롬프트
    return f"""
당신은 면접 코치입니다. 아래는 면접자의 분석 데이터입니다.

[음성 분석 결과]
{voice_desc}

[자세 분석 결과]
{posture_desc}

위 데이터를 바탕으로 각각 "음성 피드백"과 "자세 피드백"을 2~3문장으로 각각 나누어 제공해주세요.
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
        transcribe_text = start_transcribe_and_get_text(bucket, s3_key)

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
    
#잘못된 자세 카운트
@api_view(['POST'])
def receive_posture_count(request):
    count = request.data.get('count')
    print(f"[백엔드 수신] 자세 count: {count}")
    return Response({"message": "count 수신 완료", "count": count})

@api_view(['POST'])
def decide_followup_question(request):
    # 🔐 ID 토큰에서 사용자 이메일 추출
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return Response({"error": "Authorization 헤더가 없습니다."}, status=401)

    id_token = auth_header.replace("Bearer ", "")
    email = decode_cognito_id_token(id_token)
    if not email:
        return Response({"detail": "이메일이 토큰에 없습니다."}, status=403)

    # 🔑 request.user 대신 email 변수 사용 가능
    resume_text = request.data.get('resume_text')
    user_answer = request.data.get('user_answer')

    if not resume_text or not user_answer:
        return Response({'error': 'resume_text와 user_answer를 모두 포함해야 합니다.'}, status=400)

    keywords = extract_resume_keywords(resume_text)
    is_followup = should_generate_followup(user_answer, keywords)

    return Response({
        'followup': is_followup,
        'matched_keywords': [kw for kw in keywords if kw in user_answer],
        'all_keywords': keywords,
        'user_email': email
    })

class AudioUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        uploaded_file = request.FILES.get("audio")
        transcript = request.data.get("transcript")
        email = request.data.get("email")
        question_id = request.data.get("question_id")

        print("📥 업로드 요청 도착!")
        print("🎧 audio:", uploaded_file)
        print("📝 transcript:", transcript)
        print("📧 email:", email)
        print("❓ question_id:", question_id)

        if not uploaded_file or email is None or question_id is None:
            return Response({"error": "필수 값 누락"}, status=400)
        # 경로 구성
        email_prefix = email.split('@')[0]
        timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
        s3 = boto3.client('s3', 
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        audio_key = f"audio/{email_prefix}/question_{question_id}_{timestamp}.webm"
        text_key = f"audio/{email_prefix}/question_{question_id}_{timestamp}.txt"

        # 1) 음성 저장
        s3.upload_fileobj(
            uploaded_file,
            settings.AWS_AUDIO_BUCKET_NAME,  # ✅ 오디오 전용 버킷으로 수정
            audio_key,
            ExtraArgs={"ContentType": "audio/webm"}  # ✅ 이 키는 정확히 맞는 상태
        )
        # 2) 텍스트 저장
        s3.put_object(
            Bucket=settings.AWS_AUDIO_BUCKET_NAME,
            Key=text_key,
            Body=transcript.encode("utf-8"),
            ContentType="text/plain"
        )

        return Response({
            "message": "음성 및 텍스트 저장 완료",
            "audio_path": audio_key,
            "text_path": text_key
        })