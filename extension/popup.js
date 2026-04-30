document.addEventListener('DOMContentLoaded', () => {
    const toggle = document.getElementById('progressToggle');
    
    // Load saved state
    if (typeof chrome !== 'undefined' && chrome.storage) {
        chrome.storage.local.get(['showProgress'], function(result) {
            if (result.showProgress !== undefined) {
                toggle.checked = result.showProgress;
            } else {
                toggle.checked = true; // default
            }
        });
        
        // Save state on change
        toggle.addEventListener('change', (e) => {
            chrome.storage.local.set({ showProgress: e.target.checked });
        });
    }
});

document.getElementById('clearBtn').addEventListener('click', async () => {
    const btn = document.getElementById('clearBtn');
    const msg = document.getElementById('statusMsg');
    
    btn.disabled = true;
    btn.innerText = "서버 통신 중...";
    
    try {
        const response = await fetch('http://localhost:8000/api/clear-db', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'}
        });
        
        if (response.ok) {
            btn.style.display = 'none';
            msg.style.display = 'block';
            // 1.5초 뒤 창 자동 닫기
            setTimeout(() => { window.close(); }, 1500); 
        } else {
            alert('서버 에러가 발생했습니다. 백엔드 동작 여부를 확인하세요.');
            btn.disabled = false;
            btn.innerText = "데이터베이스(DB) 초기화";
        }
    } catch (e) {
        alert('백엔드 서버(uvicorn)에 연결할 수 없습니다. 서버가 켜져있는지 확인하세요.');
        btn.disabled = false;
        btn.innerText = "데이터베이스(DB) 초기화";
    }
});
