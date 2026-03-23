chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.type === "ANALYZE_CONTENT") {
        fetch("http://localhost:8000/api/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({
                action_type: request.action_type,
                content: request.content
            })
        })
        .then(response => response.json())
        .then(data => sendResponse({ success: true, data: data }))
        .catch(error => {
            console.error("Fetch Error:", error);
            sendResponse({ success: false, error: error.toString() });
        });
        
        return true; // Needed for async sendResponse
    }
});
