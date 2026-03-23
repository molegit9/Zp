// 보호 대상 탑티어 도메인들
const topBrands = ["apple.com", "naver.com", "google.com", "amazon.com", "github.com", "facebook.com", "netflix.com"];

// Levenshtein 거리 계산 알고리즘 (0.01초 소요)
function calculateDistance(a, b) {
    if (!a) return b ? b.length : 0;
    if (!b) return a.length;
    const matrix = [];
    for (let i = 0; i <= b.length; i++) matrix[i] = [i];
    for (let j = 0; j <= a.length; j++) matrix[0][j] = j;
    for (let i = 1; i <= b.length; i++) {
        for (let j = 1; j <= a.length; j++) {
            if (b.charAt(i - 1) === a.charAt(j - 1)) {
                matrix[i][j] = matrix[i - 1][j - 1];
            } else {
                matrix[i][j] = Math.min(
                    matrix[i - 1][j - 1] + 1, // substitution
                    Math.min(matrix[i][j - 1] + 1, // insertion
                             matrix[i - 1][j] + 1)); // deletion
            }
        }
    }
    return matrix[b.length][a.length];
}

function checkLevenshtein(domain) {
    try {
        const parts = domain.split('.');
        let baseDomain = domain;
        if (parts.length > 2) {
            baseDomain = parts.slice(-2).join('.');
        }

        for (const brand of topBrands) {
            if (baseDomain === brand) return { spoofed: false, brand: null }; // 완벽 일치하면 공식 도메인
            
            const dist = calculateDistance(baseDomain, brand);
            // 타겟과 글자수 차이가 1~2글자이면서 불일치하면 오타 사칭(Typosquatting) 의심
            if (dist > 0 && dist <= 2) {
                return { spoofed: true, brand: brand };
            }
        }
        return { spoofed: false, brand: null };
    } catch(err) {
        console.error("[Phishing Detector] Levenshtein 분석 중 오류:", err);
        return { spoofed: false, brand: null };
    }
}

let hoverTimer;
let currentTooltip = null;

function showSafetyTooltip(x, y, safetyScore, reason) {
    console.log(`[Phishing Detector] 툴팁 표시 시도 - 점수: ${safetyScore}, 이유: ${reason}`);
    
    if (currentTooltip) {
        currentTooltip.remove();
    }
    
    const tooltip = document.createElement('div');
    tooltip.className = 'phishing-detector-tooltip';
    
    // 안전도 스타일링 (100점 만점에 가까울수록 안전)
    let colorClass = 'safe';
    let label = '안전함';
    if (safetyScore <= 40) { colorClass = 'danger'; label = '위험 (접속 금지)'; }
    else if (safetyScore <= 70) { colorClass = 'warning'; label = '주의 요망'; }

    tooltip.classList.add(colorClass);
    
    tooltip.innerHTML = `
        <div class="header">Zero-shot URL 탐지기</div>
        <div class="score">보안 점수: <strong>${safetyScore}점</strong> / 100점 (${label})</div>
        <div class="reason">${reason}</div>
    `;
    
    tooltip.style.left = `${x + 15}px`;
    tooltip.style.top = `${y + 15}px`;
    
    document.body.appendChild(tooltip);
    currentTooltip = tooltip;
}

function removeTooltip() {
    if (currentTooltip) {
        currentTooltip.remove();
        currentTooltip = null;
    }
}

document.addEventListener('mouseover', (e) => {
    const link = e.target.closest('a');
    if (!link) return; // 하이퍼링크가 아니면 무시

    const url = link.href;
    
    // 브라우저 내부 링크, 자바스크립트 등 비정상 링크는 스킵
    if (!url.startsWith('http')) return; 

    console.log(`[Phishing Detector] 링크 호버 감지됨: ${url}`);

    // 0.2초간 마우스가 머물면 의도(Hover)로 파악하고 즉시 검사 시작
    hoverTimer = setTimeout(async () => {
        try {
            const domain = new URL(url).hostname;
            console.log(`[Phishing Detector] 호버 시간 유지! 서버 검사 요청 시작... (도메인: ${domain})`);
            
            // 1. 순식간에 끝나는 로컬 연산
            const brandData = checkLevenshtein(domain);
            console.log(`[Phishing Detector] 로컬 사칭 탐지 결과:`, brandData);
            
            // 2. 백엔드(FastAPI)로 검사 요청 (Gemini + RDAP 병렬)
            console.log(`[Phishing Detector] 서버 API 호출 중... (localhost:8000)`);
            const response = await fetch('http://localhost:8000/api/v1/analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    url: url,
                    is_spoofed: brandData.spoofed,
                    target_brand: brandData.brand
                })
            });
            
            console.log(`[Phishing Detector] HTTP 서버 응답 상태: ${response.status}`);
            
            if (!response.ok) {
                throw new Error(`서버 에러 상태코드: ${response.status}`);
            }

            const result = await response.json();
            console.log(`[Phishing Detector] 백엔드 최종 결과 데이터:`, result);
            
            if (result.status === 'success') {
                const data = JSON.parse(result.data);
                showSafetyTooltip(e.pageX, e.pageY, data.safety_score, data.reason);
            } else {
                console.error("[Phishing Detector] 백엔드 분석 실패 원인:", result.message);
            }
        } catch (err) {
            console.error('[Phishing Detector] API 연결 또는 파싱 에러 (서버 켜져있나요?)', err);
        }
    }, 200); 
});

document.addEventListener('mouseout', (e) => {
    const link = e.target.closest('a');
    if (!link) return;
    
    clearTimeout(hoverTimer);
    // 호버에서 마우스가 빠졌을 때, 드래그 상태가 아니면 툴팁을 지운다.
    const selectedText = window.getSelection().toString().trim();
    if (selectedText.length === 0) removeTooltip();
});

// 화면의 빈 공간을 클릭하면 툴팁 닫기
document.addEventListener('mousedown', (e) => {
    // 툴팁 위를 클릭한게 아닐 경우
    if (!e.target.closest('.phishing-detector-tooltip')) {
        setTimeout(() => {
            const selectedText = window.getSelection().toString().trim();
            if (selectedText.length === 0) removeTooltip();
        }, 10);
    }
});

// 드래그(텍스트 선택) 감지 로직
document.addEventListener('mouseup', async (e) => {
    if (e.target.closest('.phishing-detector-tooltip')) return;
    
    const selectedText = window.getSelection().toString().trim();
    
    // 10자 이상, 500자 이하의 텍스트를 드래그 했을 때만 의도로 파악하고 작동
    if (selectedText.length >= 10 && selectedText.length <= 500) {
        console.log(`[Phishing Detector] 텍스트 드래그 감지됨: "${selectedText}"`);
        
        try {
            // 임시 툴팁 생성
            showSafetyTooltip(e.pageX, e.pageY, 50, "드래그한 문맥의 악의성을 AI가 분석 중입니다... 🔄");
            if(currentTooltip) currentTooltip.classList.remove('safe', 'danger', 'warning');
            
            const response = await fetch('http://localhost:8000/api/v1/analyze', {
                method: 'POST',
                headers: {'Content-Type': 'application/json'},
                body: JSON.stringify({
                    action_type: "drag",
                    text: selectedText
                })
            });
            
            if (!response.ok) throw new Error("서버 연동 에러");
            
            const result = await response.json();
            if (result.status === 'success') {
                const data = JSON.parse(result.data);
                showSafetyTooltip(e.pageX, e.pageY, data.safety_score, data.reason);
            } else {
                console.error("[Phishing Detector] 드래그 에러:", result.message);
            }
        } catch (err) {
            console.error('[Phishing Detector] 드래그 분석 API 연동 실패', err);
        }
    }
});

console.log("[Phishing Detector] 클라이언트 코드 로드 완료 및 감지 대기 중...");
