import boto3
from boto3.dynamodb.conditions import Key, Attr
from ..utils.cloudfront_signer import generate_signed_url

dynamodb = boto3.resource('dynamodb', region_name='ap-northeast-2')
table = dynamodb.Table('feedback_reports')

def get_signed_pdf_url_by_video_id(user_email: str, video_id: str) -> str | None:
    # user_email을 파티션 키로, video_id는 필터로 사용
    response = table.query(
        IndexName="GSI_user_email_created_at",
        KeyConditionExpression=Key("user_email").eq(user_email),
        FilterExpression=Attr("video_id").eq(video_id)
    )

    items = response.get("Items", [])
    print("🔍 query items:", items)
    print("🔑 video_id param:", video_id)
    if not items:
        return None

    item = items[0]
    email_prefix = user_email.split("@")[0]
    filename = f"{video_id}_report.pdf"
    print("📄 filename:", filename)
    file_path = f"/clips/{email_prefix}/{filename}"
    print("filepath: ", file_path)

    return generate_signed_url(file_path)