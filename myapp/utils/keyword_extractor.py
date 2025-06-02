from keybert import KeyBERT

kw_model = KeyBERT('distiluse-base-multilingual-cased-v1')

def extract_resume_keywords(text, top_n=10):
    try:
        # whitespace만 있는 경우 방어
        if not text or text.strip() == "":
            return []

        results = kw_model.extract_keywords(text, top_n=top_n)
        # 결과가 비정상적일 경우 방어
        return [kw[0] for kw in results if isinstance(kw, (list, tuple)) and kw]
    except Exception as e:
        print(f"[❌ 키워드 추출 실패] {e}")
        return []
