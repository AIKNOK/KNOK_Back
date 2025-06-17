from jose import jwt

def decode_cognito_id_token(id_token: str) -> str | None:
    try:
        claims = jwt.get_unverified_claims(id_token)
        return claims.get("email")
    except Exception as e:
        print("[❌ ID 토큰 디코딩 실패]", str(e))
        return None
