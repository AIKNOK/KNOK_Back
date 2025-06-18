import tempfile
import boto3
from django.conf import settings

def feedback_pdf_upload(email_prefix, video_id):
    pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name

    # S3 업로드
    s3 = boto3.client(
        "s3",
        aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
        aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
        region_name=settings.AWS_S3_REGION_NAME
    )
    pdf_key = f"clips/{email_prefix}/{video_id}_report.pdf"
    s3.upload_file(pdf_path, settings.AWS_CLIP_VIDEO_BUCKET_NAME, pdf_key,
                   ExtraArgs={"ContentType": "application/pdf"})

    pdf_url = f"https://{settings.AWS_CLIP_VIDEO_BUCKET_NAME}.s3.{settings.AWS_S3_REGION_NAME}.amazonaws.com/{pdf_key}"
    return pdf_url
