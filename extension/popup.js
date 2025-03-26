// 페이지 로드 시 최신 스캔 결과가 있으면 가져오기
document.addEventListener('DOMContentLoaded', function() {
  chrome.runtime.sendMessage({ action: "get_scan_report" }, function(response) {
    if (response && response.filename) {
      displayScanReport(response);
    }
  });
});

document.getElementById("scan").addEventListener("click", function () {
  document.getElementById("status").textContent = "스캔 중...";
  
  try {
    chrome.runtime.sendMessage({ action: "manual_scan" }, (response) => {
      if (chrome.runtime.lastError) {
        console.error("❌ 메시지 전송 오류:", chrome.runtime.lastError.message);
        console.warn("⚠️ 확장 프로그램을 다시 로드해보세요.");
        document.getElementById("status").textContent = "오류 발생";
        return;
      }
      console.log("🔍 검사 요청 전송됨:", response);
    });
  } catch (error) {
    console.error("🚨 메시지 전송 중 오류 발생:", error);
    document.getElementById("status").textContent = "오류 발생";
  }
});

chrome.runtime.onMessage.addListener((message) => {
  console.log("📩 popup.js에서 메시지 수신:", message);

  if (message.action === "malware_detected") {
    document.getElementById("status").textContent = "⚠️ 악성코드 감지!";
    document.getElementById("status").className = "status-danger";
    
    // 스캔 결과 요청
    chrome.runtime.sendMessage({ action: "get_scan_report" }, function(response) {
      if (response) {
        displayScanReport(response);
      }
    });
    
  } else if (message.action === "scan_complete") {
    document.getElementById("status").textContent = "✅ 안전함";
    document.getElementById("status").className = "status-safe";
    
    // 스캔 결과 요청
    chrome.runtime.sendMessage({ action: "get_scan_report" }, function(response) {
      if (response) {
        displayScanReport(response);
      }
    });
  } else if (message.action === "scan_error") {
    document.getElementById("status").textContent = "⚠️ 스캔 오류 발생";
  }
});

// 스캔 결과 표시 함수
function displayScanReport(data) {
  // 보고서 컨테이너 표시
  document.getElementById('report-container').style.display = 'block';
  
  // 파일 정보 업데이트
  document.getElementById('filename').textContent = data.filename || '-';
  
  const predictionElement = document.getElementById('prediction');
  if (data.prediction === 'malicious') {
    predictionElement.textContent = '악성';
    predictionElement.style.color = 'red';
    predictionElement.style.fontWeight = 'bold';
  } else {
    predictionElement.textContent = '안전';
    predictionElement.style.color = 'green';
  }
  
  document.getElementById('file-hash').textContent = data.file_hash || '-';
  
  // YARA 결과 표시
  const yaraElement = document.getElementById('yara-results');
  if (data.yara_results && data.yara_results.length > 0) {
    let yaraHtml = '<ul>';
    data.yara_results.forEach(result => {
      yaraHtml += `<li><strong>${result.rule}</strong>: `;
      
      // 메타데이터가 있으면 표시
      if (result.meta && Object.keys(result.meta).length > 0) {
        yaraHtml += '<ul>';
        for (const [key, value] of Object.entries(result.meta)) {
          yaraHtml += `<li>${key}: ${value}</li>`;
        }
        yaraHtml += '</ul>';
      }
      
      yaraHtml += '</li>';
    });
    yaraHtml += '</ul>';
    yaraElement.innerHTML = yaraHtml;
  } else {
    yaraElement.textContent = '일치하는 YARA 규칙 없음';
  }
  
  // 위험 요소 표시 (데이터가 있는 경우)
  const riskElement = document.getElementById('risk-factors');
  if (data.risk_factors && data.risk_factors.length > 0) {
    let riskHtml = '<ul>';
    data.risk_factors.forEach(risk => {
      riskHtml += `<li>${risk.type}: ${risk.description}</li>`;
    });
    riskHtml += '</ul>';
    riskElement.innerHTML = riskHtml;
  } else {
    riskElement.textContent = '확인된 위험 요소 없음';
  }
}
