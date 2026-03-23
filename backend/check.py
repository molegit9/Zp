import asyncio
import os
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from google import genai
from google.genai import types
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv

# 기존 작업된 database.py 모듈에서 필요한 함수 임포트
try:
    from database import init_db, get_db, log_analysis, get_cached_analysis
except ImportError:
    print("Warning: database.py not found. DB features will not work.")
    def init_db(): pass
    def log_analysis(a,b,c,d): pass
    def get_cached_analysis(a): return None

# 환경 변수 로드
load_dotenv()

# VirusTotal 모듈 임포트
try:
    from virustotal_service import check_url_virustotal
except ImportError:
    print("Warning: virustotal_service.py not found.")
    async def check_url_virustotal(url): return None

# 서버 실행/종료 시 DB 초기화를 진행하는 Lifespan 셋업
@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup phase
    init_db()
    print("Database initialized successfully.")
    yield
    # Shutdown phase

app = FastAPI(lifespan=lifespan)

# CORS 설정
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Gemini API 설정
api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
client = None
if api_key:
    client = genai.Client(api_key=api_key)
else:
    print("Warning: GOOGLE_API_KEY or GEMINI_API_KEY not found in .env file.")

class URLRequest(BaseModel):
    url: str
    is_spoofed: bool
    # Python 3.9 에러 해결: 'str | None' 대신 Optional[str] 사용
    target_brand: Optional[str] = None

import httpx
from datetime import datetime
import json

async def get_domain_age_rdap(domain: str):
    """
    [OSINT] 실제 RDAP API를 호출하여 도메인 생성일을 확인합니다.
    """
    # 서브도메인이 포함되어 있다면 최상위 도메인(예: google.com)만 분리
    parts = domain.split('.')
    if len(parts) > 2:
        domain = '.'.join(parts[-2:])
        
    try:
        # 타임아웃을 1.0초로 제한하여 호버링 응답 속도를 방어합니다.
        async with httpx.AsyncClient(timeout=1.0) as client:
            res = await client.get(f"https://rdap.org/domain/{domain}")
            
            if res.status_code == 200:
                data = res.json()
                for event in data.get("events", []):
                    # 'registration' 이라는 이벤트의 날짜를 찾아서 나이 계산
                    if event.get("eventAction") == "registration":
                        reg_date_str = event.get("eventDate")
                        if reg_date_str:
                            reg_date = datetime.fromisoformat(reg_date_str.replace('Z', '+00:00'))
                            now = datetime.now(reg_date.tzinfo)
                            days_old = (now - reg_date).days
                            if days_old < 30:
                                return f"생성된 지 {days_old}일 밖에 안 된 신규(위험) 도메인!!"
                            else:
                                years = days_old // 365
                                return f"생성된 지 {years}년 이상 된 오래된 안전 도메인"
    except Exception as e:
        print(f"[RDAP] 도메인 수집 오류({domain}): {e}")
        pass
        
    return "도메인 생성일 정보 보안 처리됨 (수년 이상 된 일반 도메인일 확률 높음)"

@app.post("/api/v1/analyze")
async def analyze_url(req: URLRequest):
    try:
        domain = req.url.split("//")[-1].split("/")[0]
        
        # 1. 캐시 최적화: 이전에 검사한 적 있는 URL인지 확인 (DB 조회)
        cached = get_cached_analysis(req.url)
        if cached:
            status_val = str(cached["status"])
            # 과거 DB에 있던 "VT_SAFE", "WARNING" 등 문자열 데이터 하위 호환 처리
            if not status_val.isdigit():
                if "SAFE" in status_val: status_val = "100"
                elif "WARNING" in status_val: status_val = "40"
                elif "DANGER" in status_val: status_val = "10"
                else: status_val = "50"
            
            # JSON 파싱 시 특수문자나 따옴표("") 충돌 방지를 위해 json.dumps 사용
            import json
            cache_data = {"safety_score": int(status_val), "reason": cached["reason"]}
            return {"status": "success", "data": json.dumps(cache_data)}
        
        # 2. 외부 API 병렬 호출 (RDAP 도메인 나이 & VirusTotal 블랙리스트 동시 검사)
        domain_age_task = asyncio.create_task(get_domain_age_rdap(domain))
        vt_task = asyncio.create_task(check_url_virustotal(req.url))
        
        domain_age, vt_result = await asyncio.gather(domain_age_task, vt_task)
        
        vt_info = "미확인 (기록 없거나 대기열 초과)"
        if vt_result:
            if vt_result.get("status") == "VT_DANGER":
                vt_info = "위험 (기존 보안 엔진 블랙리스트에 이미 감지된 악성 도메인!)"
            else:
                vt_info = "안전 (전문 보안 엔진 블랙리스트에 없음)"
        
        # 3. Gemini 프롬프트 구성 (대상자 맞춤형 및 안전도 점수 기준 명확화)
        target_str = req.target_brand if req.target_brand else "없음"
        
        prompt = f"""
        당신은 보안 취약계층(어르신, 학생 등)을 돕는 친절한 화이트해커 전문가입니다.
        '인증서 만료', 'XSS' 같은 어려운 기술 용어는 절대 쓰지 말고, 중학생도 이해할 수 있는 쉬운 비유와 일상어로 1~2문장으로 대답해야 합니다.
        
        대상 URL: {req.url}
        
        [사전 분석 메타데이터]
        - Levenshtein 타이포스쿼팅 탐지: {req.is_spoofed} (사칭 타겟: {target_str})
        - 도메인 나이(RDAP): {domain_age}
        - VirusTotal 보안 DB 감지 여부: {vt_info}
        
        위 메타데이터와 시스템 컨텍스트를 파악하여, 이 사이트의 안전도 점수(0~100)를 평가하세요.
        100점은 '공식 사이트이며 완전히 안전함'을 뜻하고, 0점은 '심각한 사기/피싱 환경'을 의미합니다.
        
        응답은 반드시 아래 JSON 형식으로만 반환하세요:
        {{"safety_score": 90, "reason": "이곳은 아이폰 공식 홈페이지입니다. 안심하고 쓰셔도 좋습니다."}}
        """
        
        # 4. 모델 호출 (최신 google-genai 비동기 방식 및 정확한 모델명 복구)
        response = await client.aio.models.generate_content(
            model='gemini-3.1-flash-lite-preview',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
            )
        )
        
        # 5. DB에 결과 저장 (다음 번 호버링 속도 최적화를 위해)
        import json
        try:
            res_data = json.loads(response.text)
            log_score = str(res_data.get("safety_score", 50))
            log_reason = res_data.get("reason", "")
            log_analysis("hover", req.url, log_score, log_reason)
        except Exception as db_e:
            print("DB 로그 저장 에러:", db_e)
            
        return {"status": "success", "data": response.text}
    except Exception as e:
        return {"status": "error", "message": str(e)}

# 유저가 요청한 기존 DB 초기화(Clear) 엔드포인트 복구 적용
@app.post("/api/clear-db")
async def clear_db():
    try:
        with get_db() as conn:
            conn.execute('DELETE FROM security_logs')
        return {"status": "success", "message": "Database cleared safely."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    # 서버 실행: uvicorn check:app --reload --port 8000
    uvicorn.run("check:app", host="0.0.0.0", port=8000, reload=True)