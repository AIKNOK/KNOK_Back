from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
import tempfile
import boto3
from django.conf import settings

def generate_feedback_pdf_and_upload(email_prefix, video_id, feedback_text):
    # PDF 파일 생성
    pdf_path = tempfile.NamedTemporaryFile(delete=False, suffix=".pdf").name
    c = canvas.Canvas(pdf_path, pagesize=A4)
    width, height = A4
    y = height - 50
    for line in feedback_text.strip().split('\n'):
        c.drawString(50, y, line.strip())
        y -= 20
        if y < 50:
            c.showPage()
            y = height - 50
    c.save()

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
