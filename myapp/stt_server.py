from fastapi import FastAPI, WebSocket, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from amazon_transcribe.client import TranscribeStreamingClient
from amazon_transcribe.handlers import TranscriptResultStreamHandler
from amazon_transcribe.model import AudioEvent
from starlette.websockets import WebSocketDisconnect

import boto3
import uuid
import asyncio
from datetime import datetime

app = FastAPI()

# ✅ CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REGION = "us-east-1"
BUCKET_NAME = "live-stt"  # 🔁 실제 사용 중인 버킷명으로 수정

# ✅ WebSocket 기반 실시간 STT
@app.websocket("/ws/transcribe/{user_id}")
async def transcribe_ws(websocket: WebSocket, user_id: str):
    await websocket.accept()

    # ⚠️ 이메일로 안전한 S3 경로 생성
    safe_user_id = user_id.replace("@", "_at_").replace(".", "_dot_")

    client = TranscribeStreamingClient(region=REGION)
    transcript_buffer = []

    class MyEventHandler(TranscriptResultStreamHandler):
        async def handle_transcript_event(self, event):
            for result in event.transcript.results:
                if not result.is_partial:
                    sentence = result.alternatives[0].transcript
                    transcript_buffer.append(sentence)
                    await websocket.send_text(sentence)

    async def audio_stream():
        try:
            async for chunk in websocket.iter_bytes():
                yield AudioEvent(audio_chunk=chunk)
        except WebSocketDisconnect:
            pass

    try:
        stream = await client.start_stream_transcription(
            language_code="ko-KR",
            media_sample_rate_hz=44100,
            media_encoding="pcm",
            audio_stream=audio_stream(),
        )

        handler = MyEventHandler(stream.output_stream)
        await handler.handle_events()
    except Exception as e:
        print(f"[❌ Transcribe 에러]: {e}")
    finally:
        final_text = "\n".join(transcript_buffer)
        s3 = boto3.client("s3")
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=f"result/{safe_user_id}/transcribed.txt",  # ✅ 저장 위치 변경
            Body=final_text.encode("utf-8"),
            ContentType="text/plain"
        )
        await websocket.close()


# ✅ REST API: 오디오 파일 + 텍스트 파일 S3 업로드
@app.post("/upload")
async def upload_file(
    audio: UploadFile = File(...),
    transcript: str = Form(...),
    email: str = Form(...)  # ✅ 사용자 이메일을 Form 데이터로 받음
):
    now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")

    # ⚠️ 이메일을 안전한 경로로 변환
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")

    audio_key = f"audio/{safe_email}/audio_{now}.webm"
    text_key = f"result/{safe_email}/transcript_{now}.txt"

    s3 = boto3.client("s3")

    # 오디오 업로드
    s3.upload_fileobj(audio.file, BUCKET_NAME, audio_key, ExtraArgs={"ContentType": "audio/webm"})

    # 텍스트 업로드
    s3.put_object(
        Bucket=BUCKET_NAME,
        Key=text_key,
        Body=transcript.encode("utf-8"),
        ContentType="text/plain"
    )

    return {"message": "Uploaded to S3 successfully"}
