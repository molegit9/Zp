import os
import base64
import httpx

async def check_url_virustotal(url: str) -> dict:
    vt_api_key = os.environ.get("VIRUSTOTAL_API_KEY")
    if not vt_api_key:
        return None

    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {"x-apikey": vt_api_key}
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=5.0
            )
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                if malicious > 0 or suspicious > 0:
                    return {
                        "status": "VT_DANGER",
                        "reason": f"VirusTotal의 {malicious + suspicious}개 엔진에서 이 링크를 위험요소로 감지했습니다."
                    }
                else:
                    return {
                        "status": "VT_SAFE",
                        "reason": "전문 보안 엔진(VirusTotal) 검사 결과, 이 링크는 안전한 것으로 확인되었습니다."
                    }
            elif response.status_code == 404:
                # Not found in VT database
                return None
            else:
                return None
    except Exception as e:
        print(f"VirusTotal request error: {e}")
        return None
