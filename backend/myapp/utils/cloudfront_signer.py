import datetime
from botocore.signers import CloudFrontSigner
import rsa
import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent.parent

KEY_PAIR_ID = os.environ.get("CLOUDFRONT_KEY_PAIR_ID")
CLOUDFRONT_DOMAIN = os.environ.get("CLOUDFRONT_DOMAIN")
PRIVATE_KEY_PATH = BASE_DIR / os.environ.get("CLOUDFRONT_PRIVATE_KEY_PATH")

def rsa_signer(message):
    with open(PRIVATE_KEY_PATH, 'rb') as key_file:
        private_key = rsa.PrivateKey.load_pkcs1(key_file.read())
    return rsa.sign(message, private_key, 'SHA-1')

signer = CloudFrontSigner(KEY_PAIR_ID, rsa_signer)

def generate_signed_url(file_path: str, expire_hours: int = 1):
    try:
        if file_path.startswith("/clips/"):
            file_path = file_path[len("/clips"):] 
        url = f"{CLOUDFRONT_DOMAIN}{file_path}"
        print("🧾 Generating signed URL for:", url)

        expire_date = datetime.datetime.utcnow() + datetime.timedelta(hours=expire_hours)
        signed_url = signer.generate_presigned_url(url=url, date_less_than=expire_date)

        print("✅ Signed URL 생성 완료")
        return signed_url

    except Exception as e:
        print("❌ Signed URL 생성 실패:", str(e))
        raise
