// 스캔 결과 저장용 전역 변수
let latestScanResult = {
  filename: "",
  prediction: "",
  file_hash: "",
  yara_results: [],
  timestamp: "",
  scan_status: "none" // none, scanning, complete, error
};

// 백그라운드에서 Python 스크립트 실행
function startMonitorScript() {
  chrome.runtime.sendNativeMessage(
    "com.example.monitor",
    { action: "start" },
    function (response) {
      if (chrome.runtime.lastError) {
        console.error(
          "❌ Native 메시지 전송 오류:",
          chrome.runtime.lastError.message
        );
      } else {
        console.log("✅ Python 스크립트 실행됨:", response);
      }
    }
  );
}

// 다운로드한 파일 스캔 함수 - 수정
function scanDownloadedFile(downloadItem) {
  console.log("📥 새 파일 다운로드 감지:", downloadItem.filename);
  
  // 다운로드가 완료될 때까지 대기
  if (downloadItem.state !== 'complete') {
    return;
  }
  
  console.log("✅ 다운로드 완료, 스캔 시작:", downloadItem.filename);
  
  // 스캔 상태 업데이트
  latestScanResult = {
    filename: downloadItem.filename,
    prediction: "",
    file_hash: "",
    yara_results: [],
    timestamp: new Date().toISOString(),
    scan_status: "scanning"
  };
  
  fetch("http://localhost:5000/scan", {
    method: "POST",
    body: JSON.stringify({
      action: "scan_file",
      filepath: downloadItem.filename,
      downloadId: downloadItem.id
    }),
    headers: {
      "Content-Type": "application/json",
    },
  })
  .then(response => response.json())
  .then(data => {
    console.log("🔍 스캔 결과:", data);
    
    // 스캔 결과 저장
    latestScanResult = {
      filename: downloadItem.filename,
      prediction: data.prediction || "benign",
      file_hash: data.file_hash || "",
      yara_results: data.yara_results || [],
      timestamp: new Date().toISOString(),
      scan_status: "complete"
    };
    
    // 스캔 결과에 따른 알림 생성
    if (data.prediction === "malicious") {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/alert.png",
        title: "악성코드 감지!",
        message: `파일 '${downloadItem.filename}'에서 악성코드가 발견되었습니다.`,
      });
      
      safelySendMessage({ action: "malware_detected" });
    } else {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/vaccine.png",
        title: "파일 스캔 완료",
        message: `파일 '${downloadItem.filename}'은 안전합니다.`,
      });
      
      safelySendMessage({ action: "scan_complete" });
    }
  })
  .catch(err => {
    console.error("파일 스캔 오류:", err);
    latestScanResult.scan_status = "error";
    safelySendMessage({ action: "scan_error" });
  });
}

// 파일 스캔 요청 처리 (수동 검사용)
function scanFiles() {
  // 스캔 상태 초기화
  latestScanResult = {
    filename: "최근 다운로드 파일",
    prediction: "",
    file_hash: "",
    yara_results: [],
    timestamp: new Date().toISOString(),
    scan_status: "scanning"
  };
  
  fetch("http://localhost:5000/scan", {
    method: "POST",
    body: JSON.stringify({ action: "scan_recent_downloads" }),
    headers: {
      "Content-Type": "application/json",
    },
  })
  .then((response) => response.json())
  .then((data) => {
    console.log("🔍 스캔 결과:", data);
    
    latestScanResult = {
      filename: data.filename || "최근 다운로드 파일",
      prediction: data.prediction || "benign",
      file_hash: data.file_hash || "",
      yara_results: data.yara_results || [],
      timestamp: new Date().toISOString(),
      scan_status: "complete"
    };
    
    if (data.prediction === "malicious") {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/alert.png",
        title: "악성코드 감지!",
        message: `파일 '${latestScanResult.filename}'에서 악성코드가 발견되었습니다.`,
      });
      
      safelySendMessage({ action: "malware_detected" });
    } else {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/vaccine.png",
        title: "스캔 완료",
        message: "검사한 모든 파일이 안전합니다.",
      });
      
      safelySendMessage({ action: "scan_complete" });
    }
  })
  .catch((err) => {
    console.error("스캔 요청 오류:", err);
    latestScanResult.scan_status = "error";
    safelySendMessage({ action: "scan_error" });
  });
}

// 메시지 리스너 등록 - 수정
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  console.log("📩 background.js에서 메시지 수신:", message);

  if (message.action === "get_scan_report") {
    // 항상 현재 저장된 결과를 반환
    sendResponse(latestScanResult);
    return true;
  }
  
  if (message.action === "manual_scan") {
    console.log("🔍 수동 스캔 요청 수신");
    scanFiles();
    sendResponse({ status: "scanning" });
    return true; // 비동기 응답을 위해 true 반환
  }
  
  if (message.action === "malicious_script_detected") {
    chrome.notifications.create({
      type: "basic",
      iconUrl: "icons/alert.png",
      title: "악성 스크립트 감지!",
      message: "웹페이지에서 악성 스크립트가 감지되었습니다.",
    });
    sendResponse({ status: "notification_created" }); // 응답 추가
    return true;
  }

  // 알 수 없는 메시지에 대한 기본 응답 추가
  sendResponse({ status: "unknown_action" });
  return true;
});

// 확장 프로그램이 설치되면 Python 모니터링 스크립트 실행
chrome.runtime.onInstalled.addListener(() => {
  console.log("🚀 확장 프로그램이 설치됨");
  startMonitorScript();
  
  // 기존 규칙 정리 후 새로운 규칙 추가
  chrome.declarativeNetRequest.getDynamicRules((existingRules) => {
    const existingRuleIds = existingRules.map(rule => rule.id);
    
    if (existingRuleIds.length > 0) {
      // 기존 규칙 삭제
      chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: existingRuleIds,
        addRules: [] // 먼저 모든 규칙 삭제
      }, () => {
        // 그 후 새로운 규칙 추가
        loadAndApplyRules();
      });
    } else {
      // 기존 규칙이 없으면 바로 새 규칙 추가
      loadAndApplyRules();
    }
  });
  
  // 다운로드 이벤트 리스너 및 기타 코드는 그대로 유지
});

// 규칙 로드 및 적용 함수
function loadAndApplyRules() {
  fetch("rules.json")
    .then((response) => response.json())
    .then((rules) => {
      chrome.declarativeNetRequest.updateDynamicRules({
        addRules: rules
      }, () => {
        if (chrome.runtime.lastError) {
          console.error("규칙 업데이트 오류:", chrome.runtime.lastError.message);
        } else {
          console.log("규칙 업데이트 완료");
        }
      });
    })
    .catch((error) => {
      console.error("규칙 로드 오류:", error);
    });
}

// 안전하게 메시지 전송하는 함수
function safelySendMessage(message) {
  try {
    chrome.runtime.sendMessage(message);
  } catch (error) {
    console.log("메시지 전송 실패 (수신자 없음)");
  }
}