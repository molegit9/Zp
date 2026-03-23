document.addEventListener('DOMContentLoaded', () => {
    const clearBtn = document.getElementById('clearBtn');
    const statusEl = document.getElementById('status');

    clearBtn.addEventListener('click', async () => {
        statusEl.textContent = "초기화 중...";
        statusEl.style.color = "#888";
        
        try {
            const response = await fetch("http://localhost:8000/api/clear-db", {
                method: "POST"
            });
            
            if (response.ok) {
                statusEl.textContent = "✅ DB 초기화 완료!";
                statusEl.style.color = "#34c759";  // Apple green
            } else {
                statusEl.textContent = "❌ 초기화 실패 (서버 에러)";
                statusEl.style.color = "#ff3b30";
            }
        } catch (err) {
            statusEl.textContent = "❌ 초기화 실패 (서버 꺼짐)";
            statusEl.style.color = "#ff3b30";
        }
        
        // 메시지를 3초 뒤에 삭제합니다
        setTimeout(() => {
            statusEl.textContent = "";
        }, 3000);
    });
});
