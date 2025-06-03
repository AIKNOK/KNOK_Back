# fastapi_server.py
import asyncio, json, wave
from fastapi import FastAPI, WebSocket, Query
from fastapi.middleware.cors import CORSMiddleware
from datetime import datetime
from amazon_transcribe.client import TranscribeStreamingClient
from amazon_transcribe.model import AudioEvent
from amazon_transcribe.handlers import TranscriptResultStreamHandler
from starlette.websockets import WebSocketDisconnect

app = FastAPI()

app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])

REGION = "us-east-1"

@app.websocket("/ws/transcribe")
async def transcribe_ws(websocket: WebSocket, email: str = Query(...)):
    await websocket.accept()
    print(f"🎤 WebSocket 연결됨 - 사용자: {email}")

    audio_buffer = bytearray()
    transcript_text = ""

    client = TranscribeStreamingClient(region=REGION)
    stream = await client.start_stream_transcription(
        language_code="ko-KR", media_encoding="pcm", sample_rate=16000
    )

    async def microphone_stream():
        try:
            while True:
                data = await websocket.receive_bytes()
                audio_buffer.extend(data)
                yield AudioEvent(data)
        except WebSocketDisconnect:
            await stream.input_stream.end_stream()
            print("🔌 WebSocket 연결 종료됨")

    async def handle_transcription():
        handler = TranscriptResultStreamHandler(stream.output_stream)
        async for event in handler:
            for result in event.transcript.results:
                if not result.is_partial:
                    text = result.alternatives[0].transcript
                    transcript_text += text + "\n"
                    await websocket.send_text(json.dumps({"transcript": text}))

    await asyncio.gather(
        stream.send_audio_event_stream(microphone_stream()),
        handle_transcription(),
    )

    # FastAPI는 S3 업로드는 하지 않음 (Django가 담당)
    print("✅ WebSocket STT 완료")
