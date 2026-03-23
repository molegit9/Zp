let hoverTimeout = null;
let currentTooltip = null;

const STATUS_EMOJIS = {
    "VT_SAFE": "🟢",
    "GEMINI_SAFE": "🟡",
    "SAFE": "🟢", // Fallback
    "WARNING": "🟡",
    "DANGER": "🔴"
};

function createOrUpdateTooltip(x, y, data) {
    if (!currentTooltip) {
        currentTooltip = document.createElement('div');
        currentTooltip.className = 'safety-net-tooltip';
        document.body.appendChild(currentTooltip);
    }
    
    const emoji = STATUS_EMOJIS[data.status] || "⚪";
    let statusText = "분석 중...";
    let textClass = "";

    if (data.status === 'VT_SAFE') {
        statusText = '안전함 (보안 엔진 확인)';
        textClass = 'status-blue-text';
    } else if (data.status === 'GEMINI_SAFE' || data.status === 'SAFE') {
        statusText = '안전함 (AI 분석)';
    } else if (data.status === 'WARNING') {
        statusText = '주의 필요';
    } else if (data.status === 'DANGER') {
        statusText = '위험함';
    }
    
    currentTooltip.innerHTML = `<strong class="${textClass}">${emoji} ${statusText}</strong><br>${data.reason}`;
    
    // reset position temporarily for dimension measurements
    currentTooltip.style.left = '0px';
    currentTooltip.style.top = '0px';
    currentTooltip.style.opacity = '0';
    currentTooltip.style.display = 'block';
    
    const rect = currentTooltip.getBoundingClientRect();
    const tooltipWidth = rect.width;
    const tooltipHeight = rect.height;
    
    const viewportWidth = window.innerWidth;
    const viewportHeight = window.innerHeight;
    
    let finalX = x + 15;
    let finalY = y + 15;
    
    // Prevent overflow to the right
    if (finalX + tooltipWidth > viewportWidth) {
        finalX = x - tooltipWidth - 15;
    }
    
    // Prevent overflow below
    if (finalY + tooltipHeight > viewportHeight) {
        finalY = y - tooltipHeight - 15;
    }
    
    if (finalX < 0) finalX = 10;
    if (finalY < 0) finalY = 10;
    
    currentTooltip.style.left = `${finalX}px`;
    currentTooltip.style.top = `${finalY}px`;
    
    // Ensure animation logic starts
    requestAnimationFrame(() => {
        currentTooltip.style.opacity = '1';
    });
}

function removeTooltip() {
    if (currentTooltip) {
        currentTooltip.style.opacity = '0';
        setTimeout(() => {
            if (currentTooltip && currentTooltip.style.opacity === '0') {
                currentTooltip.style.display = 'none';
            }
        }, 300);
    }
}

async function analyzeContent(actionType, content, e) {
    if (!content || content.trim() === '') return;

    try {
        chrome.runtime.sendMessage({
            type: "ANALYZE_CONTENT",
            action_type: actionType,
            content: content
        }, (response) => {
            if (chrome.runtime.lastError) {
                console.warn("Message sending failed, probably background context missing:", chrome.runtime.lastError.message);
                return;
            }

            if (response && response.success) {
                createOrUpdateTooltip(e.clientX, e.clientY, response.data);
            } else {
                console.error("Analysis API failed:", response ? response.error : 'Unknown status');
            }
        });
    } catch (err) {
        console.error("Message send error:", err);
    }
}

// 1. Debounced Hover Detection
document.addEventListener('mouseover', (e) => {
    const link = e.target.closest('a');
    
    if (link && link.href) {
        if (hoverTimeout) clearTimeout(hoverTimeout);
        removeTooltip();
        
        hoverTimeout = setTimeout(() => {
            // Check if user is still hovering
            if (link.matches(':hover')) {
                analyzeContent('hover', link.href, e);
            }
        }, 500); // 0.5s debouncing
    }
});

document.addEventListener('mouseout', (e) => {
    const link = e.target.closest('a');
    if (link) {
        if (hoverTimeout) clearTimeout(hoverTimeout);
        removeTooltip();
    }
});

// 2. Drag Detection
document.addEventListener('mouseup', (e) => {
    const selectedText = window.getSelection().toString().trim();
    if (selectedText.length > 5) {
        // Assume text drag and drop event triggered
        analyzeContent('drag', selectedText, e);
    } else {
        // Ensure no false hiding if hovering
        if (!e.target.closest('a')) {
            removeTooltip();
        }
    }
});

document.addEventListener('mousedown', (e) => {
    // Prevent accidental hiding if we click exactly the tooltip, although pointer-events:none prevents this.
    removeTooltip();
    if (hoverTimeout) clearTimeout(hoverTimeout);
});
