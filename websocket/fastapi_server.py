import asyncio, json, wave, os, tempfile, requests
from fastapi import FastAPI, WebSocket, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from amazon_transcribe.client import TranscribeStreamingClient
from starlette.websockets import WebSocketDisconnect
from dotenv import load_dotenv

import boto3
import requests
import json


load_dotenv()
upload_id_cache = {}

REGION = os.getenv("AWS_REGION")
S3_BUCKET = os.getenv("AWS_AUDIO_BUCKET_NAME")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
DJANGO_API_URL = os.getenv("DJANGO_API_URL")

# FastAPI 앱에 적용
app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"], allow_credentials=True)

connections: dict[str, WebSocket] = {}

@app.websocket("/ws/transcribe")
async def transcribe_ws(websocket: WebSocket, email: str = Query(...), question_id: str = Query(...), token: str = Query(...)):
    await websocket.accept()
    print(f"WebSocket 연결됨 - 사용자: {email}, 질문 ID: {question_id}")

    audio_buffer = bytearray()
    transcript_text = ""

    client = TranscribeStreamingClient(region=REGION)
    try:
        stream = await client.start_stream_transcription(
            language_code="ko-KR",
            media_sample_rate_hz=16000,
            media_encoding="pcm"
        )
    except Exception as e:
        print("❌ Transcribe 클라이언트 시작 실패:", e)
        await websocket.close()
        return


    async def send_audio():
        try:
            while True:
                try:
                    data = await asyncio.wait_for(websocket.receive_bytes(), timeout=90)
                except asyncio.TimeoutError:
                    print("오디오 수신 없음 - 타임아웃 종료")
                    break

                if data == b"END":
                    print("클라이언트 END 신호 수신")
                    break

                print(f"오디오 수신됨: {len(data)} bytes")
                audio_buffer.extend(data)
                upload_id_entry["audio_bytes"].extend(data)

                try:
                    # 메모리뷰/문자열 방어 코드
                    if isinstance(data, memoryview):
                        data = data.tobytes()
                    elif isinstance(data, str):
                        data = data.encode("utf-8")
                    elif not isinstance(data, (bytes, bytearray)):
                        data = bytes(data)

                    await stream.input_stream.send_audio_event(data)  # ✅ AudioEvent 제거됨

                except Exception as e:
                    print("❌ 오디오 전송 실패:", e)
                    break
        except WebSocketDisconnect:
            print("WebSocket 연결 끊김")
        except Exception as e:
            print("❗ send_audio 예외 발생:", e)
        finally:
            print("오디오 전송 종료")

    async def handle_transcription():
        nonlocal transcript_text
        try:
            async for event in stream.output_stream:
                print("Transcribe 이벤트 수신됨")
                for result in event.transcript.results:
                    if not result.is_partial and result.alternatives:
                        text = result.alternatives[0].transcript
                        print("➡️ 받은 텍스트:", repr(text))
                        if text.strip():
                            transcript_text += text + "\n"
                            await websocket.send_text(json.dumps({"transcript": text}))
        except Exception as e:
            print("❗ 전사 핸들링 예외:", e)
        finally:
            print("Transcribe 결과 수신 종료됨")
    async def handle_text_messages():
        try:
            while True:
                msg = await websocket.receive_text()
                print("📩 텍스트 메시지 수신:", msg)
        except WebSocketDisconnect:
            print("📴 WebSocket 텍스트 연결 종료")
        except Exception as e:
            print("❗ 텍스트 메시지 처리 중 예외:", e)

    upload_id = None

    try:
        print("asyncio.gather 실행")
        email_prefix = email.split('@')[0]

        upload_id_key = f"{email}"  # 또는 f"{email}-{interview_id}" 인터뷰별로 분리하려면

        if upload_id_key not in upload_id_cache:
            new_upload_id = get_upload_id(email_prefix)
            upload_id_cache[upload_id_key] = {
                "upload_id": new_upload_id,
                "transcript": "",
                "audio_bytes": bytearray(),
            }
            
        upload_id_entry = upload_id_cache[upload_id_key]
        upload_id = upload_id_entry["upload_id"]

        # 클라이언트에 upload_id 전송
        await websocket.send_text(json.dumps({
            "type":      "upload_id",
            "upload_id": upload_id
        }))
        
        await send_audio()
        await handle_transcription()
        await handle_text_messages()
        await stream.input_stream.end_stream()  # 수신 후 명시적으로 종료
    
    except Exception as e:
        print("🔥 전사 실패:", e)
    finally:
        print("✅ WebSocket STT 완료")
        try:
            print("📤 Django 전송 전 원본 텍스트:", repr(transcript_text))

             # Claude 3.5로 전사 보정
            refined_transcript = await refine_transcript_with_claude(transcript_text)

            print("📤 Claude 보정 후 텍스트:", repr(refined_transcript))
            if upload_id_entry is not None:
                if upload_id_entry["audio_bytes"]:
                    save_audio_to_s3(upload_id_entry["audio_bytes"], email, upload_id, question_id)
                else:
                    print("⚠️ 저장 생략: 오디오 데이터 없음")

                if refined_transcript.strip():
                    save_transcript_to_s3(refined_transcript, email, upload_id, question_id)
                else:
                    print("⚠️ 저장 생략: 텍스트 전사 없음")
                
            # ✅ 보정된 텍스트 저장 및 전송
            send_transcript_to_django(email, question_id, refined_transcript, token)
        except Exception as e:
            print("❌ 후처리 실패:", e)
        try:
            await websocket.send_text(json.dumps({"status": "done"}))
            await websocket.close()
        except Exception as e:
            print("❌ WebSocket 닫기 실패:", e)


def save_audio_to_s3(audio_bytes, email, upload_id, question_id):
    email_prefix = email.split('@')[0]
    key = f"{email_prefix}/{upload_id}/wavs/live_q{question_id}.wav"

    print(f"🛠️ 저장할 S3 키: {key}")

    temp_wav = tempfile.NamedTemporaryFile(delete=False, suffix=".wav")
    temp_wav.close()

    with wave.open(temp_wav.name, 'wb') as wf:
        wf.setnchannels(1)
        wf.setsampwidth(2)
        wf.setframerate(16000)
        wf.writeframes(audio_bytes)

    s3 = boto3.client('s3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=REGION
    )
    try:
        s3.upload_file(temp_wav.name, S3_BUCKET, key, ExtraArgs={"ContentType": "audio/wav"})
        print(f"📄 S3 업로드 완료: {key}")
    except Exception as e:
        print("❌ S3 업로드 실패:", str(e))
    finally:
        try:
            os.remove(temp_wav.name)
        except Exception as e:
            print("❌ 파일 삭제 실패:", e)


def save_transcript_to_s3(transcript_text, email, upload_id, question_id):
    email_prefix = email.split('@')[0]
    key = f"{email_prefix}/{upload_id}/text/live_q{question_id}.txt"


    s3 = boto3.client('s3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=REGION
    )

    try:
        s3.put_object(
            Bucket=S3_BUCKET,
            Key=key,
            Body=transcript_text.encode('utf-8'),
            ContentType='text/plain'
        )
        print(f"🖍️ 전사 텍스트 S3 업로드 완료: {key}")
    except Exception as e:
        print("❌ 전사 텍스트 S3 저장 실패:", str(e))


def send_transcript_to_django(email, question_id, transcript_text, token):
    headers = {"Authorization": f"Bearer {token}"}
    payload = {
        "email": email,
        "question_id": question_id,
        "transcript": transcript_text
    }

    try:
        response = requests.post(DJANGO_API_URL, json=payload, headers=headers)
        print("📨 Django 저장 응답:", response.status_code, response.text)
    except Exception as e:
        print("🔥 Django 저장 실패:", str(e))

def get_upload_id(email_prefix):
    s3 = boto3.client('s3',
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=REGION
    )

    today_str = datetime.now().strftime("%m%d")
    prefix = f"{email_prefix}/{today_str}-"

    response = s3.list_objects_v2(Bucket=S3_BUCKET, Prefix=prefix)
    existing_ids = set()

    for obj in response.get('Contents', []):
        key = obj['Key']
        # 예: 'kimxodud0823/0610-1/wavs/live_q1.wav' → '0610-1'
        parts = key.split('/')
        if len(parts) >= 2 and parts[1].startswith(today_str + '-'):
            existing_ids.add(parts[1])

    new_index = len(existing_ids) + 1
    return f"{today_str}-{new_index}"

# 텍스트 보정
async def refine_transcript_with_claude(transcript_text: str) -> str:
    if not transcript_text.strip():
        print("⚠️ 전사 텍스트가 비어 있어 Claude 호출 생략")
        return transcript_text

    try:
        client = boto3.client(
            "bedrock-runtime", 
            region_name="us-east-1",
            aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),         # 🔐 반드시 .env에 존재
            aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")  # 🔐 반드시 .env에 존재)  # ✅ 리전
        )

        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "messages": [
                {
                    "role": "user",
                    "content": f"""
다음은 한국어 음성 인식 결과입니다. 문법 오류, 문장 부호 누락을 보정하되, 숫자와 영어 약어는 발음을 분석해 정확한 원래 표기로 복원해 주세요.

예를 들어:
- "십오분" → "15분"
- "이씨투" → "EC2"
- "에이더블유에스" → "AWS"
- "삼 점 일 사" → "3.14"
- "디 비 에스" → "DBS"

단, 발음이 숫자나 영어를 뜻하는 경우에만 변환하세요.
그리고 이름, 지명, 고유명사는 가능한 한 그대로 유지하세요. 의미가 명확하지 않으면 원문을 보존하세요.

[전사 시작]
{transcript_text}
[전사 끝]
"""
                }
            ],
            "max_tokens": 1024,
            "temperature": 0.3,
        }

        response = client.invoke_model(
            modelId="anthropic.claude-3-haiku-20240307-v1:0",
            contentType="application/json",
            accept="application/json",
            body=json.dumps(body)
        )

        result = json.loads(response["body"].read())
        refined_text = result["content"][0]["text"]

        print("📤 Claude 보정 결과:", refined_text)
        return refined_text

    except Exception as e:
        print("❌ Claude (Bedrock) 호출 실패:", e)
        return transcript_text

@app.websocket("/ws/questions")
async def question_ws(websocket: WebSocket, user_email: str = Query(...)):
    await websocket.accept()
    connections[user_email] = websocket
    print(f"Question WebSocket connected for {user_email}")
    try:
        while True:
            # Keep the connection alive, or handle specific control messages
            await websocket.receive_text() 
    except WebSocketDisconnect:
        print(f"Question WebSocket disconnected for {user_email}")
        del connections[user_email]
    except Exception as e:
        print(f"Error in question WebSocket for {user_email}: {e}")

@app.post("/internal/send-question")
async def send_question_to_frontend(data: dict):
    user_email = data.get("user_email")
    question = data.get("question")
    question_number = data.get("question_number")

    if user_email in connections:
        websocket = connections[user_email]
        try:
            await websocket.send_json({
                "type": "new_question",
                "question": question,
                "question_number": question_number
            })
            print(f"Sent question to {user_email} via WebSocket: {question_number}")
            return {"status": "success"}
        except Exception as e:
            print(f"Failed to send question to {user_email}: {e}")
            return {"status": "error", "message": str(e)}
    else:
        print(f"No active WebSocket connection for {user_email}")
        return {"status": "error", "message": "User not connected"}

@app.get("/api/health")
async def health_check():
    return {"status": "ok"}