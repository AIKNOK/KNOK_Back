from keybert import KeyBERT
from sentence_transformers import SentenceTransformer

print("✅ [KeyBERT] SentenceTransformer 모델 로딩 시작")
model = SentenceTransformer('sentence-transformers/distiluse-base-multilingual-cased-v1')
print("✅ [KeyBERT] 모델 로딩 완료")
kw_model = KeyBERT(model)

def extract_resume_keywords(text, top_n=10):
   print("✅ [KeyBERT] 키워드 추출 시작")
   print("📄 입력 텍스트 길이:", len(text.strip()) if text else "None")
   try:
       if not text or text.strip() == "":
           return []

       results = kw_model.extract_keywords(text, top_n=top_n)
       print("🎯 추출된 키워드 원본:", results)
       return [kw[0] for kw in results if isinstance(kw, (list, tuple)) and kw]
   except Exception as e:
       print(f"[❌ 키워드 추출 실패] {e}")
       return []