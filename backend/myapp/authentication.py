import jwt
from jwt import PyJWKClient
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed
from django.contrib.auth.models import User
from django.conf import settings

COGNITO_POOL_ID = settings.COGNITO_USER_POOL_ID
COGNITO_REGION = settings.AWS_REGION
APP_CLIENT_ID = settings.COGNITO_APP_CLIENT_ID

JWKS_URL = f"https://cognito-idp.{COGNITO_REGION}.amazonaws.com/{COGNITO_POOL_ID}/.well-known/jwks.json"


class CognitoJWTAuthentication(BaseAuthentication):
    def authenticate(self, request):
        print("✅ [CognitoJWTAuthentication] 호출됨")
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return None

        token = auth_header.split(' ')[1]

        try:
            # 🔑 PyJWT 공식 키 가져오기 방식 사용
            jwk_client = PyJWKClient(JWKS_URL)
            signing_key = jwk_client.get_signing_key_from_jwt(token).key

            decoded = jwt.decode(
                token,
                signing_key,
                algorithms=["RS256"],
                options={"verify_aud": False}
            )

            username = decoded.get('email') or decoded.get('cognito:username')
            if not username:
                raise AuthenticationFailed("이메일이 토큰에 없습니다.")

            # Django 유저 매핑
            user, _ = User.objects.get_or_create(username=username, defaults={"email": username})
            return (user, token)

        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('토큰이 만료되었습니다.')
        except jwt.InvalidTokenError as e:
            raise AuthenticationFailed(f'유효하지 않은 토큰입니다: {str(e)}')
