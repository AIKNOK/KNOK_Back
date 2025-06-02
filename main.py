import uvicorn
from myapp.stt_server import app  # 여기서 FastAPI app을 불러오기만 함

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8001)