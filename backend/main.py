import os
import json
import redis
from contextlib import asynccontextmanager
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from database import init_db, log_analysis, get_cached_analysis
from gemini_service import analyze_content

redis_client = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- Startup phase ---
    init_db()
    
    global redis_client
    try:
        # Adding socket_connect_timeout so it doesn't hang if Redis is unavailable
        redis_client = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True, socket_connect_timeout=2)
        redis_client.ping()
        print("Redis connected successfully.")
    except Exception as e:
        print(f"WARNING: Failed to connect to Redis. Caching is disabled. Server will continue without cache. Error: {e}")
        redis_client = None
        
    if not os.environ.get("GEMINI_API_KEY"):
        print("WARNING: GEMINI_API_KEY environment variable is not set! API calls will fail.")
        
    yield
    
    # --- Shutdown phase ---
    if redis_client:
        redis_client.close()

app = FastAPI(title="Security Action Analysis API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    action_type: str
    content: str

@app.post("/api/analyze")
async def analyze(request: AnalyzeRequest):
    if request.action_type not in ["hover", "drag"]:
        raise HTTPException(status_code=400, detail="Invalid action_type")
        
    cache_key = f"sec_analysis:{request.content}"
    
    # Optional Cache Check (Redis)
    if redis_client:
        try:
            cached_result = redis_client.get(cache_key)
            if cached_result:
                return json.loads(cached_result)
        except Exception as e:
            print(f"Redis cache GET error: {e}")

    # Fallback Permanent Cache Check (SQLite)
    db_result = get_cached_analysis(request.content)
    if db_result:
        if redis_client:
            try:
                redis_client.setex(cache_key, 86400, json.dumps(db_result))
            except Exception:
                pass
        return db_result

    # 3. VirusTotal & Gemini Flow
    final_status = "WARNING"
    final_reason = "분석 중 오류 발생"
    vt_result = None

    if request.action_type == "hover" and request.content.startswith("http"):
        from virustotal_service import check_url_virustotal
        try:
            vt_result = await check_url_virustotal(request.content)
        except Exception as e:
            print(f"VT Error: {e}")

    if vt_result and vt_result.get("status") == "VT_SAFE":
        final_status = "VT_SAFE"
        final_reason = vt_result.get("reason", "안전함")
    else:
        gemini_res = await analyze_content(request.action_type, request.content)
        final_status = gemini_res.get("status", "WARNING")
        final_reason = gemini_res.get("reason", "")
        
        if final_status == "SAFE":
            if vt_result and vt_result.get("status") == "VT_DANGER":
                final_status = "GEMINI_SAFE" 
                final_reason = f"주의: 보안 엔진(VT)은 경고했으나 AI는 안전하다고 판단했습니다. {final_reason}"
            else:
                final_status = "GEMINI_SAFE"

    result = {"status": final_status, "reason": final_reason}
    
    is_error = gemini_res.get("is_error", False) if 'gemini_res' in locals() else False
    
    if not is_error:
        # Save to Redis
        if redis_client:
            try:
                redis_client.setex(cache_key, 86400, json.dumps(result))
            except Exception as e:
                print(f"Redis cache SET error: {e}")

        # Save to SQLite DB explicitly so it's loaded fast next time
        try:
            log_analysis(request.action_type, request.content, final_status, final_reason)
        except Exception as e:
            print(f"SQLite log error: {e}")
            
    return result

@app.post("/api/clear-db")
async def clear_db():
    try:
        from database import get_db
        with get_db() as conn:
            conn.execute('DELETE FROM security_logs')
        if redis_client:
            redis_client.flushdb()
        return {"status": "success", "message": "Database and cache cleared safely."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
