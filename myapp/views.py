from rest_framework.decorators import api_view
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated
from rest_framework import status

import boto3
import hmac
import hashlib
import base64
import uuid

from django.conf import settings
from .models import Resume
from .serializers import ResumeSerializer


def get_secret_hash(username):
    message = username + settings.COGNITO_APP_CLIENT_ID
    digest = hmac.new(
        settings.COGNITO_APP_CLIENT_SECRET.encode('utf-8'),
        message.encode('utf-8'),
        hashlib.sha256
    ).digest()
    return base64.b64encode(digest).decode()


@api_view(['POST'])
def signup(request):
    email = request.data.get('email')
    password = request.data.get('password')

    client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)

    try:
        client.sign_up(
            ClientId=settings.COGNITO_APP_CLIENT_ID,
            SecretHash=get_secret_hash(email),
            Username=email,
            Password=password,
            UserAttributes=[{'Name': 'email', 'Value': email}],
        )
        return Response({'message': '회원가입 성공! 이메일 인증 필요'})
    except client.exceptions.UsernameExistsException:
        return Response({'error': '이미 존재하는 사용자입니다.'}, status=400)
    except Exception as e:
        return Response({'error': str(e)}, status=400)


@api_view(['POST'])
def confirm_email(request):
    email = request.data.get('email')
    code = request.data.get('code')

    client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)

    try:
        client.confirm_sign_up(
            ClientId=settings.COGNITO_APP_CLIENT_ID,
            SecretHash=get_secret_hash(email),
            Username=email,
            ConfirmationCode=code
        )
        return Response({'message': '이메일 인증 완료'})
    except client.exceptions.CodeMismatchException:
        return Response({'error': '인증 코드가 틀렸습니다.'}, status=400)
    except client.exceptions.ExpiredCodeException:
        return Response({'error': '인증 코드가 만료되었습니다.'}, status=400)
    except Exception as e:
        return Response({'error': str(e)}, status=400)


@api_view(['POST'])
def login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    client = boto3.client('cognito-idp', region_name=settings.AWS_REGION)

    try:
        response = client.initiate_auth(
            ClientId=settings.COGNITO_APP_CLIENT_ID,
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': email,
                'PASSWORD': password,
                'SECRET_HASH': get_secret_hash(email)
            }
        )
        token = response['AuthenticationResult']['IdToken']
        return Response({'message': '로그인되었습니다', 'token': token})
    except client.exceptions.NotAuthorizedException:
        return Response({'error': '아이디 또는 비밀번호 오류'}, status=400)
    except Exception as e:
        return Response({'error': str(e)}, status=400)


class ResumeUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        file = request.FILES.get('resume')
        if not file:
            return Response({"error": "파일이 없습니다."}, status=400)

        filename = f"resumes/{uuid.uuid4()}_{file.name}"
        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        s3.upload_fileobj(file, settings.AWS_STORAGE_BUCKET_NAME, filename)
        file_url = f"https://{settings.AWS_S3_CUSTOM_DOMAIN}/{filename}"

        Resume.objects.filter(user=request.user).delete()
        resume = Resume.objects.create(user=request.user, file_url=file_url)
        serializer = ResumeSerializer(resume)
        return Response(serializer.data, status=201)


class ResumeDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        resume = Resume.objects.filter(user=request.user).first()
        if not resume:
            return Response({"error": "업로드된 이력서가 없습니다."}, status=404)

        key = resume.file_url.split(f"{settings.AWS_S3_CUSTOM_DOMAIN}/")[-1]

        s3 = boto3.client(
            's3',
            aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
            aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY,
            region_name=settings.AWS_S3_REGION_NAME
        )

        s3.delete_object(Bucket=settings.AWS_STORAGE_BUCKET_NAME, Key=key)
        resume.delete()
        return Response({"message": "이력서 삭제 완료"}, status=204)