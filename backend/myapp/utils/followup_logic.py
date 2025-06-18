# aws8/myapp/utils/followup_logic.py

def should_generate_followup(user_answer, resume_keywords, threshold=1):
    match_count = sum(1 for kw in resume_keywords if kw in user_answer)
    return match_count >= threshold
