from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework.decorators import authentication_classes, permission_classes
from pydub import AudioSegment
from myapp.utils.keyword_extractor import extract_resume_keywords
from myapp.utils.followup_logic import should_generate_followup
from myapp.utils.token_utils import decode_cognito_id_token

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


from django.conf import settings
from .models import Resume
from .serializers import ResumeSerializer
from django.http import JsonResponse
from pathlib import Path
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator



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

    bucket = 'whisper-testt'
    prefix = 'audio/'  # 여러 질문 오디오가 여기에 저장되어 있다고 가정

    posture_count = request.data.get('posture_count', 0)
    # transcribe_text = request.data.get('transcribe_text', '')

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
        return JsonResponse({'error': str(e)}, status=500)
 
# [2] 피드백 리포트 생성 API (STT 분석 결과 기반)
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def generate_feedback_report(request):
    user = request.user
    analysis = request.data.get("analysis")

    # merge_texts_from_s3_folder 호출하여 transcript 획득
    if not analysis.get('transcribe_text'):
        # email_prefix나 upload_id는 클라이언트에서 전달
        email_prefix = analysis.get('email_prefix', user.email)
        upload_id = analysis.get('upload_id')
        transcribe_text = merge_texts_from_s3_folder(email_prefix, upload_id)
        analysis['transcribe_text'] = transcribe_text

    # 프롬프트 생성
    posture_count = analysis.get("posture_count", 0)
		
		# 프롬프트 구성
    voice_desc = f"""
- 목소리 떨림: {analysis['voice_tremor']}
- Pitch 표준편차: {analysis['pitch_std']}
- 말 속도: {analysis['speech_rate']} 단어/초
- 침묵 비율: {analysis['silence_ratio'] * 100:.1f}%
- 감정 상태: {analysis['emotion']}
"""

    posture_desc = f"면접 중 총 {posture_count}회의 자세 흔들림이 감지되었습니다."
    transcribe_desc = analysis["transcribe_text"]

    prompt = f"""
당신은 AI 면접 코치입니다. 아래는 면접자의 분석 데이터입니다:

[전체 답변 결과]
{transcribe_desc}

[음성 분석 결과]
{voice_desc}

[자세 분석 결과]
{posture_desc}

---

위 데이터를 바탕으로 면접자의 답변을 다음 기준으로 피드백을 제시해주세요:
1. 일관성: 답변 전체에 흐름이 있고 앞뒤가 자연스럽게 연결되는가?
2. 논리성: 주장에 대해 명확한 이유와 근거가 있으며 논리적 흐름이 있는가?
3. 대처능력: 예상치 못한 질문에도 당황하지 않고 유연하게 답했는가?
4. 구체성: 추상적인 설명보다 구체적인 경험과 예시가 포함되어 있는가?
5. 음성 피드백 : 음성 분석 결과를 기준으로 피드백을 제시해주세요.
6. 자세 피드백 : 자세 분석 결과를 기준으로 피드백을 제시해주세요.

각 항목에 대해 피드백을 작성하고, 최대한 핵심적인 요소를 강조해주세요. 그리고 0~5점 점수를 chart로 표현해주세요.
다음 JSON 형식으로만 응답해주세요:


{{
  "summary": "...",
  "detail": {{
    "일관성": "...",
    "논리성": "...",
    "대처능력": "...",
    "구체성": "...",
    "말하기방식": "...",
    "면접태도": "..."
  }},
  "chart": {{
    "일관성": 0~5,
    "논리성": 0~5,
    "대처능력": 0~5,
    "구체성": 0~5,
    "말하기방식": 0~5,
    "면접태도": 0~5
  }}
}}

⚠️ 반드시 위 JSON 구조로만 응답해주세요.
JSON 코드 블럭(```json ...```) 안에만 결과를 담아주세요.
"""

    raw_text = get_claude_feedback(prompt)
    
    feedback = parse_claude_feedback_and_score(raw_text)
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

@api_view(["POST"])
@permission_classes([IsAuthenticated])
def decide_followup_question(request):
    data = request.data
    email = request.user.email
    question = data.get("question")
    answer = data.get("answer")
    existing_question_numbers = data.get("existing_question_numbers", [])  # e.g., ["1", "2", "2-1"]
    base_question_number = data.get("base_question_number")  # e.g., "2"

    if not question or not answer or not base_question_number:
        return Response({"error": "Missing required fields."}, status=400)

    # Step 1: Claude로부터 꼬리질문 받아오기
    prompt = f"""다음은 면접 질문과 그에 대한 지원자의 답변입니다. 이 답변을 기반으로 추가로 물어볼 만한 follow-up 질문 하나만 생성해주세요.
질문: {question}
답변: {answer}
follow-up 질문:"""
    followup = get_claude_followup_question(prompt)

    # Step 2: 꼬리질문 번호 자동 생성
    def next_followup_number(existing_numbers, base_number):
        suffixes = [
            int(num.split("-")[1])
            for num in existing_numbers
            if num.startswith(f"{base_number}-") and "-" in num
        ]
        next_num = max(suffixes, default=0) + 1
        return f"{base_number}-{next_num}"

    new_number = next_followup_number(existing_question_numbers, base_question_number)

    # Step 3: followup 질문 S3에 저장
    followup_bucket = 'knok-followup-questions'
    email_prefix = request.user.email.split('@')[0]
    key = f"{email_prefix}/질문{new_number}.txt"

    s3 = boto3.client('s3',
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )

    s3.put_object(
        Bucket=followup_bucket,
        Key=key,
        Body=followup.encode('utf-8'),
        ContentType='text/plain'
    )

    # Step 4: 응답
    return Response({
        "number": new_number,
        "text": followup
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
    import requests
    import traceback

    try:
        print("[🔍 segments 수신 내용]", request.data.get("segments"))
        video_id = request.data.get("videoId")
        if not video_id:
            return Response({"error": "videoId는 필수입니다."}, status=400)

        email_prefix = request.user.email.split('@')[0]
        video_key = f"videos/{email_prefix}/{video_id}.webm"

        print("[🔍 segments 수신 내용]", request.data.get("segments"))

        # 자세 구간 받아오기 (segments)
        posture_data = request.data.get("segments")
        if not posture_data:
            return Response({"error": "segments가 없습니다."}, status=400)

        # 전체 영상 다운로드 (임시 저장)
        s3 = boto3.client("s3", aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                                   aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
                                   region_name=settings.AWS_S3_REGION_NAME)
        full_video_temp = tempfile.NamedTemporaryFile(delete=False, suffix=".webm")
        s3.download_fileobj(settings.AWS_FULL_VIDEO_BUCKET_NAME, video_key, full_video_temp)
        full_video_temp.close()

        # MoviePy로 클립 추출
        converted_video_path = convert_webm_to_mp4(full_video_temp.name)
        video = mp.VideoFileClip(converted_video_path)
        clip_urls = []
        duration = video.duration  # 전체 길이(초) 구하기

        for idx, segment in enumerate(posture_data):
            # 시작/끝을 float로 파싱 & 음수 방지, 끝은 전체 길이 넘지 않게
            try:
                start = max(0.0, float(segment["start"]))
                end   = min(duration, float(segment["end"]))
            except Exception as e:
                return Response({"error": f"start/end 변환 실패: {str(e)}"}, status=400)

            # 유효 구간이 아니면 건너뛰기
            if end <= start:
                continue

            # 클립 추출
            clip = video.subclip(start, end)
            clip_path = tempfile.NamedTemporaryFile(delete=False, suffix=".mp4").name
            clip.write_videofile(clip_path, codec="libx264", audio_codec="aac", logger=None)

            # S3 업로드드
            clip_s3_key = f"clips/{email_prefix}/{video_id}_clip_{idx+1}.mp4"

            s3.upload_file(
                clip_path,
                settings.AWS_CLIP_VIDEO_BUCKET_NAME,
                clip_s3_key,
                ExtraArgs={"ContentType": "video/mp4"}
            )

            # 업로드 URL 생성성
            clip_url = f"https://{settings.AWS_CLIP_VIDEO_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{clip_s3_key}"
            clip_urls.append(clip_url)

        return Response({
            "message": "클립 저장 완료",
            "clips": clip_urls
        })

    except Exception as e:
        import traceback
        traceback_str = traceback.format_exc()
        print("🔥 클립 추출 중 예외 발생:\n", traceback_str)
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
