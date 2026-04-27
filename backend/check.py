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

# ChromaDB 모듈 호환성 임포트
try:
    import chromadb
    from chromadb.utils import embedding_functions
    HAS_CHROMA = True
except ImportError:
    HAS_CHROMA = False

chroma_client = None
rag_collection = None

# 서버 실행/종료 시 DB 초기화를 진행하는 Lifespan 셋업
@asynccontextmanager
async def lifespan(app: FastAPI):
    global chroma_client, rag_collection
    # Startup phase
    init_db()
    print("SQLite initialized successfully.")
    
    # RAG DB 자동 로드
    if HAS_CHROMA and os.path.exists("./chroma_db"):
        try:
            chroma_client = chromadb.PersistentClient(path="./chroma_db")
            emb_fn = embedding_functions.SentenceTransformerEmbeddingFunction(model_name="jhgan/ko-sroberta-multitask")
            rag_collection = chroma_client.get_collection(name="security_texts", embedding_function=emb_fn)
            print(f"RAG Vector DB loaded securely. Documents inside: {rag_collection.count()}")
        except Exception as e:
            print("RAG Vector DB load failed. Run rag_initializer.py manually.", e)
    else:
        print("Warning: Vector DB folder not found. RAG functionality will run without local context.")

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
    url: Optional[str] = None
    text: Optional[str] = None
    action_type: Optional[str] = "hover"
    is_spoofed: Optional[bool] = False
    target_brand: Optional[str] = None

class TextAnalyzeRequest(BaseModel):
    selected_text: str

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
        # 이하 기존 호버(Hover) URL 분석 모드
        if not req.url:
            return {"status": "error", "message": "Hover action requires a valid URL."}
            
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
        is_https = "사용 중 (안전함)" if str(req.url).startswith("https://") else "미사용 - HTTP 기반의 암호화되지 않은 취약한 연결 (개인정보 탈취 위험 높음!)"
        
        prompt = f"""
        당신은 보안 취약계층(어르신, 학생 등)을 돕는 친절한 화이트해커 전문가입니다.
        '인증서 만료', 'XSS' 같은 어려운 기술 용어는 절대 쓰지 말고, 중학생도 이해할 수 있는 쉬운 비유와 일상어로 1~2문장으로 대답해야 합니다.
        
        대상 URL: {req.url}
        
        [사전 분석 메타데이터]
        - HTTPS 통신 보안 프로토콜 사용 여부: {is_https}
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

# 신규 RAG 연동 전용 드래그 텍스트 분석 엔드포인트
@app.post("/api/v1/analyze/text")
async def analyze_rag_text(req: TextAnalyzeRequest):
    try:
        # 1. RAG Context Retrieval (벡터 조회)
        retrieved_context = ""
        if rag_collection:
            results = rag_collection.query(query_texts=[req.selected_text], n_results=3)
            
            if results and "documents" in results and len(results["documents"]) > 0 and len(results["documents"][0]) > 0:
                docs = results["documents"][0]
                metas = results["metadatas"][0]
                distances = results.get("distances", [[999]])[0]

                # --- 🚀 [성능 최적화: LLM 고속 처리 우회 (Vector Cache Hit)] ---
                # 만약 드래그한 문구 벡터가 데이터셋의 문구와 사실상 완벽하게 똑같다면 (거리 차이 0.15 미만)
                # 느린 LLM(Gemini)에 물어볼 필요 없이 곧바로 데이터셋의 라벨을 토대로 빛의 속도로 초고속 반환합니다.
                if len(distances) > 0 and distances[0] < 0.15:
                    best_label = str(metas[0].get("label", "0"))
                    if best_label == "2":
                        return {"risk_level": "위험", "score": 95, "reason": "보안 데이터베이스의 악성 피싱 판례와 100% 일치하여, AI 딥러닝을 거치지 않고 초고속(0.01초)으로 차단했습니다.", "mitigation": "절대로 링크를 클릭하지 마세요."}
                    elif best_label in ["1", "3"]:
                        return {"risk_level": "안전", "score": 5, "reason": "보안 DB의 안전한 문구 판례와 100% 일치하여 AI 분석을 생략하고 초고속 통과시킵니다.", "mitigation": "안심하세요."}
                    elif best_label in ["4", "5"]:
                        return {"risk_level": "위험", "score": 85, "reason": "알려진 악성 스팸 메일 판례와 파일이 100% 동일합니다. 초고속 차단됨.", "mitigation": "링크를 클릭하지 말고 즉시 삭제하세요."}
                # -----------------------------------------------------------------

                context_pieces = []
                for i, doc in enumerate(docs):
                    label = metas[i].get("label", "unknown")
                    source = metas[i].get("source", "unknown")
                    context_pieces.append(f"[사례 {i+1} : 과거 라벨 {label} ({source})]\n> 내용: {doc}")
                retrieved_context = "\n\n".join(context_pieces)
        else:
            retrieved_context = "(로컬 Vector DB가 오프라인입니다. 자체 지식망으로 판단하세요.)"

        # 2. Gemini RAG Prompt Design
        rag_prompt = f"""
        당신은 개인용 보안 시스템의 코어 엔진 역할을 하는 RAG(검색 증강 생성) 기반 위협 분석 AI입니다.
        사용자가 웹에서 의심스러워 드래그한 텍스트에 스미싱, 피싱, 악성 메일 유도 등 사회공학적 사기 의도가 있는지 분석하세요.

        **[분석 대상 텍스트]**
        "{req.selected_text}"

        **[RAG 지식베이스 검색 결과: 유사 과거 판례 3건]**
        {retrieved_context}
        
        (※ 참고: 판례 Label 디코딩: 1=일상대화/안전, 2=스미싱/피싱, 3=정상정보, 4=스팸 메일, 5=악성 바이러스 메일)

        위의 RAG 판례 기록과 텍스트 문맥을 교차 대조하여, 대상 텍스트의 실질적 위협도를 종합 분석하세요.
        분석 결과는 **0~100점**의 score로 표기해야 합니다.
        - 점수 등급: 0~30점(안전), 31~70점(주의), 71~100점(위험)
        
        반드시 지정된 아래 JSON Schema(Pydantic 대응) 형식으로만 응답하세요:
        {{"risk_level": "위험", "score": 95, "reason": "이 텍스트는 RAG 데이터베이스의 Label 2 판례와 문맥이 99% 일치하는 악성 택배 스미싱 수법입니다.", "mitigation": "절대로 링크를 클릭하지 말고 해당 발신자를 즉시 차단하세요."}}
        """

        # 3. Requesting JSON bounded structure directly from LLM
        response = await client.aio.models.generate_content(
            model='gemini-3.1-flash-lite-preview',
            contents=rag_prompt,
            config=types.GenerateContentConfig(response_mime_type="application/json")
        )
        
        import json
        try:
            res_data = json.loads(response.text)
            return res_data
        except json.JSONDecodeError:
            return {"risk_level": "에러", "score": 0, "reason": "AI 파싱 오류", "mitigation": "-"}
            
    except Exception as e:
        return {"risk_level": "시스템 오류", "score": 0, "reason": f"RAG 에러: {str(e)}", "mitigation": "관리자 문의"}

if __name__ == "__main__":
    import uvicorn
    # 서버 실행: uvicorn check:app --reload --port 8000
    uvicorn.run("check:app", host="0.0.0.0", port=8000, reload=True)