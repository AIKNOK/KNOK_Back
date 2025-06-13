# check_bedrock_models.py
import boto3
import os
from dotenv import load_dotenv

load_dotenv()  # .env에 있는 AWS 키 불러오기

bedrock = boto3.client(
    service_name="bedrock",
    region_name="us-east-1",  # 혹은 us-west-2
    aws_access_key_id=os.getenv("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.getenv("AWS_SECRET_ACCESS_KEY")
)

response = bedrock.list_foundation_models()

for model in response["modelSummaries"]:
    if "anthropic" in model["modelId"]:
        print(f"{model['modelName']} | {model['modelId']} | access: {model['responseStreamingSupported']}")
