import datetime
from botocore.signers import CloudFrontSigner
from django.conf import settings
import rsa
import os
from pathlib import Path
import boto3
import base64


KEY_PAIR_ID = os.environ.get("CLOUDFRONT_KEY_PAIR_ID")
CLOUDFRONT_DOMAIN = os.environ.get("CLOUDFRONT_DOMAIN")
SECRET_NAME = settings.CLOUDFRONT_SECRET_NAME
print("✅ loaded SECRET_NAME:", SECRET_NAME)  
REGION_NAME = os.environ.get("AWS_REGION")

def get_private_key_from_secrets_manager():
    client = boto3.client("secretsmanager", region_name=REGION_NAME)
    response = client.get_secret_value(SecretId=SECRET_NAME)

    secret_string = response.get("SecretString")
    if not secret_string:
        raise ValueError("SecretString not found in the secret.")

    import json
    secret_dict = json.loads(secret_string)
    pem_data = secret_dict.get("private_key.pem")
    if not pem_data:
        raise ValueError("private_key.pem key not found in the secret.")
    
    pem_data = pem_data.replace("\\n", "\n")
    print(pem_data)
    
    return pem_data.encode("utf-8")

def rsa_signer(message):
    private_key_pem = get_private_key_from_secrets_manager()
    private_key = rsa.PrivateKey.load_pkcs1(private_key_pem)
    return rsa.sign(message, private_key, 'SHA-1')

signer = CloudFrontSigner(KEY_PAIR_ID, rsa_signer)

def generate_signed_url(file_path: str, expire_hours: int = 24 * 30):
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
