# myapp/stt_server.py

from fastapi import FastAPI, WebSocket, UploadFile, File, Form
from fastapi.middleware.cors import CORSMiddleware
from amazon_transcribe.client import TranscribeStreamingClient
from amazon_transcribe.handlers import TranscriptResultStreamHandler
from amazon_transcribe.model import AudioEvent
from starlette.websockets import WebSocketDisconnect

import boto3
import asyncio
from datetime import datetime

app = FastAPI()

# ──────────────────────────────────────────────────────────
# CORS 설정: 클라이언트(React)에서 localhost:8001/ws/* 로 연결할 수 있도록
# ──────────────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

REGION = "us-east-1"
BUCKET_NAME = "live-stt"  # 실제 S3 버킷명을 사용하세요

# ──────────────────────────────────────────────────────────
# WebSocket 기반 실시간 STT 엔드포인트
# ──────────────────────────────────────────────────────────
@app.websocket("/ws/transcribe/{user_id}")
async def transcribe_ws(websocket: WebSocket, user_id: str):
    # 1) 연결 수락
    await websocket.accept()

    # 2) S3에 저장할 때 안전한 키 이름 생성
    safe_user_id = user_id.replace("@", "_at_").replace(".", "_dot_")

    client = TranscribeStreamingClient(region=REGION)
    transcript_buffer = []

    # ──────────────────────────────────────────────────────────
    # TranscriptResultStreamHandler 구현
    # ──────────────────────────────────────────────────────────
    class MyEventHandler(TranscriptResultStreamHandler):
        async def handle_transcript_event(self, event):
            for result in event.transcript.results:
                if not result.is_partial:
                    sentence = result.alternatives[0].transcript
                    transcript_buffer.append(sentence)
                    # 실시간으로 WebSocket 클라이언트에 전송
                    await websocket.send_text(sentence)

    # ──────────────────────────────────────────────────────────
    # WebSocket으로 들어오는 바이트(PCM)를 AWS에 전달하기 위한 제너레이터
    # ──────────────────────────────────────────────────────────
    async def audio_stream_generator():
        try:
            async for chunk in websocket.iter_bytes():
                # AWS TranscribeStreamingClient 에는 AudioEvent 형태로 wrapping 필요
                yield AudioEvent(audio_chunk=chunk)
        except WebSocketDisconnect:
            # 클라이언트 연결이 끊어지면 종료
            return

    try:
        # ──────────────────────────────────────────────────────────
        # 음성 스트림을 AWS Transcribe에 넘겨주고, 결과를 수신
        # ──────────────────────────────────────────────────────────
        stream = await client.start_stream_transcription(
            language_code="ko-KR",
            media_sample_rate_hz=44100,
            media_encoding="pcm",
            audio_event_stream=audio_stream_generator(),  # ❌ 키워드 이름 수정
        )

        handler = MyEventHandler(stream.output_stream)
        await handler.handle_events()

    except Exception as e:
        print(f"[❌ Transcribe 에러]: {e}")

    finally:
        # ───────────────────────────
        # 최종 텍스트를 S3에 저장
        # ───────────────────────────
        final_text = "\n".join(transcript_buffer)
        try:
            s3 = boto3.client("s3")
            s3.put_object(
                Bucket=BUCKET_NAME,
                Key=f"result/{safe_user_id}/transcribed.txt",
                Body=final_text.encode("utf-8"),
                ContentType="text/plain",
            )
        except Exception as e:
            print(f"[❌ S3 업로드 에러]: {e}")

        # WebSocket 연결 종료
        await websocket.close()


# ──────────────────────────────────────────────────────────
# REST API: 오디오 + 전사 텍스트 파일 S3 업로드 (/upload/)
#   - FastAPI 쪽에서는 URL이 슬래시로 끝나도록 설정해야 Django와 충돌이 없습니다.
# ──────────────────────────────────────────────────────────
@app.post("/upload/")
async def upload_file(
    audio: UploadFile = File(...),
    transcript: str = Form(...),
    email: str = Form(...),
):
    """
    Frontend에서 form-data로 보낸:
      - audio: .webm 파일
      - transcript: 스트리밍으로 받은 텍스트
      - email: 사용자 이메일
    를 S3에 각각 저장합니다.
    """
    now = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
    safe_email = email.replace("@", "_at_").replace(".", "_dot_")

    audio_key = f"audio/{safe_email}/audio_{now}.webm"
    text_key = f"result/{safe_email}/transcript_{now}.txt"

    try:
        s3 = boto3.client("s3")
        # 오디오 업로드
        await audio.seek(0)
        s3.upload_fileobj(audio.file, BUCKET_NAME, audio_key, ExtraArgs={"ContentType": "audio/webm"})

        # 텍스트 업로드
        s3.put_object(
            Bucket=BUCKET_NAME,
            Key=text_key,
            Body=transcript.encode("utf-8"),
            ContentType="text/plain",
        )
    except Exception as e:
        return {"error": f"S3 업로드 실패: {e}"}

    return {"message": "Uploaded to S3 successfully", "audio_key": audio_key, "text_key": text_key}
