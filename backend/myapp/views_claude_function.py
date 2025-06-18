# Claude 3 호출 함수 추가
def get_claude_feedback(prompt: str) -> str:
    print(">> get_claude_feedback received:", prompt)
    
    client = boto3.client("bedrock-runtime", region_name="us-east-1")
    
    try:
        # Claude 3.7 Sonnet 모델 직접 호출 (온디맨드 방식)
        response = client.invoke_model(
            modelId="anthropic.claude-3-7-sonnet-20250219-v1:0",  # Claude 3.7 Sonnet 모델 ID
            contentType="application/json",
            accept="application/json",
            body=json.dumps({
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 1024,
                "temperature": 0.7,
                "messages": [
                    {
                        "role": "user",
                        "content": prompt
                    }
                ]
            }),
        )
    except ClientError as e:
        print(f"Claude API 호출 오류: {str(e)}")
        raise
    
    payload = json.loads(response["body"].read().decode("utf-8"))
    
    # 최신 Claude API는 content 배열을 반환
    if "content" in payload and len(payload["content"]) > 0:
        return payload["content"][0]["text"].strip()
    else:
        print("Claude 응답에 content 필드가 없습니다:", payload)
        return ""
