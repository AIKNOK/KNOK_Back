# fastapi_server.py
import asyncio, json, wave, os, tempfile, requests
from fastapi import FastAPI, WebSocket, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from amazon_transcribe.client import TranscribeStreamingClient
from amazon_transcribe.handlers import TranscriptResultStreamHandler
from starlette.websockets import WebSocketDisconnect
import boto3
from dotenv import load_dotenv

load_dotenv()
upload_id_cache = {}

REGION = os.getenv("AWS_REGION")
S3_BUCKET = os.getenv("AWS_AUDIO_BUCKET_NAME")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
DJANGO_API_URL = os.getenv("DJANGO_API_URL")

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

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
            await stream.input_stream.end_stream()
            print("오디오 전송 종료 및 Transcribe 종료 요청")

    async def handle_transcription():
        nonlocal transcript_text
        try:
            async for event in stream.output_stream:
                print("Transcribe 이벤트 수신됨")
                for result in event.transcript.results:
                    if not result.is_partial:
                        text = result.alternatives[0].transcript
                        transcript_text += text + "\n"
                        await websocket.send_text(json.dumps({"transcript": text}))
        except Exception as e:
            print("❗ 전사 핸들링 예외:", e)
        finally:
            print("Transcribe 결과 수신 종료됨")

    try:
        print("asyncio.gather 실행")
        email_prefix = email.split('@')[0]
        if email not in upload_id_cache:
            upload_id_cache[email] = get_upload_id(email_prefix)
        upload_id = upload_id_cache[email]
        await asyncio.gather(send_audio(), handle_transcription())
    except Exception as e:
        print("🔥 전사 실패:", e)
    finally:
        print("✅ WebSocket STT 완료")
        try:
            save_audio_to_s3(audio_buffer, email, upload_id, question_id)
            save_transcript_to_s3(transcript_text, email, upload_id, question_id)
            send_transcript_to_django(email, question_id, transcript_text, token)
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
