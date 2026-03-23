from google import genai
import os
import json
from datetime import datetime

async def analyze_content(action_type: str, content: str) -> dict:
    try:
        # genai.Client() automatically picks up GEMINI_API_KEY from environment.
        client = genai.Client()
    except Exception as e:
        print(f"Gemini Client Init Error (e.g., Missing API key): {e}")
        return {
            "status": "WARNING",
            "reason": "내부 시스템 설정 문제로 현재 평가를 수행할 수 없습니다.",
            "is_error": True
        }

    current_time_str = datetime.now().strftime("%Y년 %m월 %d일 %H시 %M분")
    
    prompt = f"""
    당신은 보안 취약계층을 돕는 친절한 전문가입니다. '인증서 만료', 'XSS' 같은 어려운 기술 용어는 절대 쓰지 말고, 중학생도 이해할 수 있는 쉬운 비유와 일상어로 답변하세요.
    
    현재 시스템 날짜와 시간은 {current_time_str} 입니다. 내용에 포함된 날짜가 과거인지 미래인지 판단할 때 반드시 이 현재 시간을 기준으로 절대적으로 계산하세요! (예: 정상적인 메일이나 문자의 과거 날짜를 미래로 착각하여 스팸이라 오해하지 않도록 매우 주의)
    
    사용자가 다음 작업을 수행했습니다.
    작업 유형: {action_type} (hover는 링크에 마우스를 올린 것, drag는 텍스트를 드래그한 것)
    내용: {content}
    
    이 내용이 피싱 사이트나 악성 스크립트, 사기성 정보 등 보안상 위험한지 분석해주세요.
    반드시 다음 형식의 순수한 JSON 으로만 응답해주세요. 시작과 끝에 마크다운 기호를 붙이지 마세요.
    {{
        "status": "SAFE" | "WARNING" | "DANGER",
        "reason": "쉬운 이유 설명"
    }}
    """
    
    try:
        # Use aio for async calls in google-genai
        response = await client.aio.models.generate_content(
            model='gemini-3.1-flash-lite-preview',
            contents=prompt,
            config={"response_mime_type": "application/json"}
        )
        
        result = json.loads(response.text)
        
        # Validation fallback
        if result.get("status") not in ["SAFE", "WARNING", "DANGER"]:
            result["status"] = "WARNING"
            result["reason"] = "상태를 명확하게 판단할 수 없습니다. 주의해서 확인해주세요."
            
        return result
    except Exception as e:
        error_msg = str(e)
        if "429" in error_msg or "RESOURCE_EXHAUSTED" in error_msg:
            print(f"Gemini API Quota Exceeded (gemini-3.1-flash-lite): {e}\nFallback 동작: gemma-3-27b 모델로 재시도합니다.")
            
            try:
                fallback_response = await client.aio.models.generate_content(
                    model='gemma-3-27b',
                    contents=prompt,
                    config={"response_mime_type": "application/json"}
                )
                
                result = json.loads(fallback_response.text)
                if result.get("status") not in ["SAFE", "WARNING", "DANGER"]:
                    result["status"] = "WARNING"
                    result["reason"] = "상태를 명확하게 판단할 수 없습니다. 주의해서 확인해주세요."
                    
                return result
            except Exception as fallback_e:
                print(f"Fallback gemma-3-27b Error: {fallback_e}")
                return {
                    "status": "WARNING",
                    "reason": "현재 연속된 분석 요청으로 인해 메인 AI와 보조 AI의 무료 검사 횟수를 모두 초과했습니다. 약 1분 뒤 다시 시도해 주세요.",
                    "is_error": True
                }
            
        print(f"Gemini API Error: {e}")
        return {
            "status": "WARNING",
            "reason": "현재 분석 시스템에 일시적인 오류가 발생했습니다. 접속이나 이용에 주의해 주세요.",
            "is_error": True
        }
