// 스크립트 요소 감시
let scannedScripts = new Set();

function checkForMaliciousScripts() {
  document.querySelectorAll("script").forEach((script) => {
    // 이미 스캔한 스크립트는 건너뛰기
    if (scannedScripts.has(script)) return;

    let scriptContent = script.innerText || script.textContent;
    
    // 빈 스크립트는 건너뛰기
    if (!scriptContent || scriptContent.trim() === '') return;

    // 스캔 완료된 스크립트로 표시
    scannedScripts.add(script);

    // 간단한 로컬 검사 (명백한 악성 패턴)
    const obviousMalicious = [
      "document.cookie.indexOf(\"password\")",
      "eval(String.fromCharCode(",
      "window.location='http://malware'"
    ];

    // 명백한 악성 패턴이 있는 경우 즉시 차단
    for (const pattern of obviousMalicious) {
      if (scriptContent.includes(pattern)) {
        console.warn("🚨 명백한 악성 스크립트 탐지:", scriptContent.substring(0, 100) + "...");
        chrome.runtime.sendMessage({ action: "malicious_script_detected" });
        script.remove();
        return;
      }
    }

    // 🚀 Flask 서버로 스크립트 내용 전송하여 AI 기반 분석
    fetch("http://localhost:5000/scan_script", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ script: scriptContent }),
    })
      .then((response) => response.json())
      .then((data) => {
        if (data.prediction === "malicious") {
          console.warn("🚨 악성 스크립트 탐지:", scriptContent.substring(0, 100) + "...");
          chrome.runtime.sendMessage({ action: "malicious_script_detected" });
          script.remove();
        }
      })
      .catch((err) => console.error("스크립트 스캔 오류:", err));
  });
}

// DOM 변화 감시하여 동적으로 추가되는 스크립트 탐지
const observer = new MutationObserver((mutations) => {
  mutations.forEach((mutation) => {
    if (mutation.addedNodes && mutation.addedNodes.length > 0) {
      // 새로 추가된 노드 중 script가 있는지 확인
      const hasNewScript = Array.from(mutation.addedNodes).some(
        (node) => node.tagName === "SCRIPT" || 
                 (node.nodeType === 1 && node.querySelector("script"))
      );
      
      if (hasNewScript) {
        checkForMaliciousScripts();
      }
    }
  });
});

// 페이지가 로드되면 초기 검사 실행
document.addEventListener("DOMContentLoaded", () => {
  checkForMaliciousScripts();
  
  // DOM 변화 감시 시작
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
});

// 백업: 주기적으로 검사 실행
setInterval(checkForMaliciousScripts, 3000);