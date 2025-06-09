# fastapi_server.py
import asyncio, json, wave, os, tempfile, requests
from fastapi import FastAPI, WebSocket, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from amazon_transcribe.client import TranscribeStreamingClient
from amazon_transcribe.model import AudioEvent
from amazon_transcribe.handlers import TranscriptResultStreamHandler
from starlette.websockets import WebSocketDisconnect
import boto3
from dotenv import load_dotenv

load_dotenv()

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
    print(f"🎤 WebSocket 연결됨 - 사용자: {email}, 질문 ID: {question_id}")

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
                    print("🕒 오디오 수신 없음 - 타임아웃 종료")
                    await stream.input_stream.end_stream()
                    break

                if data == b"END":
                    print("🔴 클라이언트 END 신호 수신")
                    await stream.input_stream.end_stream()
                    break

                print(f"📥 오디오 수신됨")
                audio_buffer.extend(data)
                await stream.input_stream.send_audio_event(AudioEvent(audio_chunk=data))

        except WebSocketDisconnect:
            print("🔌 WebSocket 연결 끊기")
            await stream.input_stream.end_stream()
        except Exception as e:
            print("❗ 오디오 전송 예제 발생:", e)
            await stream.input_stream.end_stream()

    async def handle_transcription():
        nonlocal transcript_text
        handler = TranscriptResultStreamHandler(stream.output_stream)
        try:
            async for event in handler.handle_events():
                for result in event.transcript.results:
                    if not result.is_partial:
                        text = result.alternatives[0].transcript
                        transcript_text += text + "\n"
                        await websocket.send_text(json.dumps({"transcript": text}))
        except Exception as e:
            print("❗ 전사 핸들링 예제:", e)

    try:
        print("🔹 asyncio.gather 실행")
        await asyncio.gather(send_audio(), handle_transcription())
    except Exception as e:
        print("🔥 전사 실패:", e)

    finally:
        print("✅ WebSocket STT 완료")

        try:
            save_audio_to_s3(audio_buffer, email)
        except Exception as e:
            print("❌ 음성 S3 저장 실패:", e)

        try:
            save_transcript_to_s3(transcript_text, email)
        except Exception as e:
            print("❌ 텍스트 S3 저장 실패:", e)

        try:
            send_transcript_to_django(email, question_id, transcript_text, token)
        except Exception as e:
            print("🔥 Django 전송 실패:", e)

    try:
        await websocket.send_text(json.dumps({"status": "done"}))
        await websocket.close()
    except Exception as e:
        print("❌ WebSocket 닫기 실패:", e)


def save_audio_to_s3(audio_bytes, email):
    email_prefix = email.split('@')[0]
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    key = f"audio/{email_prefix}/wavs/live_{timestamp}.wav"
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


def save_transcript_to_s3(transcript_text, email):
    email_prefix = email.split('@')[0]
    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
    key = f"audio/{email_prefix}/text/live_{timestamp}.txt"

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
