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
  
  // 상세 분석 정보 표시 (새로 추가된 부분)
  if (data.detailed_analysis) {
    displayDetailedAnalysis(data.detailed_analysis);
  }
  
  // 위험 요소 표시 (업데이트된 부분)
  displayRiskFactors(data);
}

// 상세 분석 정보 표시 함수
function displayDetailedAnalysis(analysis) {
  // 기본 파일 정보 업데이트
  if (analysis.size_human) {
    document.getElementById('file-size').textContent = analysis.size_human;
  }
  
  if (analysis.sha256) {
    document.getElementById('file-sha256').textContent = 
      analysis.sha256.substring(0, 12) + '...' + analysis.sha256.substring(analysis.sha256.length - 8);
  }
  
  if (analysis.entropy) {
    document.getElementById('file-entropy').textContent = 
      analysis.entropy.toFixed(2) + ` (${getEntropyDescription(analysis.entropy)})`;
  }
  
  if (analysis.created_time) {
    const date = new Date(analysis.created_time);
    document.getElementById('file-created').textContent = 
      date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
  }
  
  // 바이트 분포 차트 표시 (바이트 분포 데이터가 있는 경우)
  if (analysis.byte_distribution && analysis.byte_distribution.length > 0) {
    document.getElementById('entropy-chart-section').style.display = 'block';
    displayByteDistributionChart(analysis.byte_distribution);
  }
  
  // PE 파일 정보 표시 (PE 파일인 경우)
  if (analysis.file_type === 'PE' && analysis.pe_analysis) {
    document.getElementById('pe-info-section').style.display = 'block';
    
    const peType = analysis.pe_analysis.is_dll ? 'DLL 라이브러리' :
                  analysis.pe_analysis.is_exe ? '실행 파일' : '알 수 없음';
    document.getElementById('pe-type').textContent = 
      `${peType} (${analysis.pe_analysis.cpu_type || '알 수 없음'})`;
    
    // 컴파일 시간이 있으면 표시
    if (analysis.pe_analysis.compile_time && analysis.pe_analysis.compile_time !== 'Invalid timestamp') {
      const date = new Date(analysis.pe_analysis.compile_time);
      document.getElementById('pe-compile-time').textContent = 
        date.toLocaleDateString() + ' ' + date.toLocaleTimeString();
    } else {
      document.getElementById('pe-compile-time').textContent = '알 수 없음';
    }
    
    // 섹션 정보 표시
    if (analysis.pe_analysis.sections && analysis.pe_analysis.sections.length > 0) {
      let sectionText = '';
      analysis.pe_analysis.sections.forEach(section => {
        const entropyClass = section.entropy > 7.0 ? 'color: red;' : 
                            section.entropy > 6.0 ? 'color: orange;' : '';
        sectionText += `<span style="${entropyClass}">${section.name}</span> (${formatBytes(section.size)}), `;
      });
      document.getElementById('pe-sections').innerHTML = sectionText.substring(0, sectionText.length - 2);
    } else {
      document.getElementById('pe-sections').textContent = '정보 없음';
    }
  }
}

// 바이트 분포 차트 표시 함수
function displayByteDistributionChart(distribution) {
  const ctx = document.getElementById('entropy-chart').getContext('2d');
  
  // 차트 데이터 준비
  const labels = Array.from({length: 256}, (_, i) => i);
  const data = {
    labels: labels,
    datasets: [{
      label: '바이트 분포',
      data: distribution,
      backgroundColor: generateColorGradient(distribution.length),
      borderWidth: 1
    }]
  };
  
  // 차트 생성
  new Chart(ctx, {
    type: 'bar',
    data: data,
    options: {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        y: {
          beginAtZero: true,
          title: {
            display: true,
            text: '빈도'
          }
        },
        x: {
          title: {
            display: true,
            text: '바이트 값'
          },
          ticks: {
            autoSkip: true,
            maxTicksLimit: 16
          }
        }
      },
      plugins: {
        legend: {
          display: false
        },
        tooltip: {
          callbacks: {
            title: function(tooltipItems) {
              return `바이트 값: ${tooltipItems[0].label}`;
            },
            label: function(tooltipItem) {
              const percent = (tooltipItem.raw * 100).toFixed(2);
              return `빈도: ${percent}%`;
            }
          }
        }
      }
    }
  });
}

// 위험 요소 표시 함수
function displayRiskFactors(data) {
  const riskElement = document.getElementById('risk-factors');
  const riskDetailsElement = document.getElementById('risk-details');
  let foundRisks = false;
  
  // 기존 YARA 매치 기반 위험 요소
  if (data.yara_results && data.yara_results.length > 0) {
    foundRisks = true;
    let riskHtml = '<ul>';
    data.yara_results.forEach(result => {
      riskHtml += `<li>YARA 규칙 일치: ${result.rule}</li>`;
    });
    riskHtml += '</ul>';
    riskElement.innerHTML = riskHtml;
  }
  
  // 상세 분석 기반 위험 요소
  if (data.detailed_analysis && data.detailed_analysis.risk_factors && 
      data.detailed_analysis.risk_factors.length > 0) {
    
    foundRisks = true;
    let detailsHtml = '';
    
    data.detailed_analysis.risk_factors.forEach(risk => {
      detailsHtml += `<div class="risk-item risk-${risk.severity || 'low'}">
                        <div class="risk-title">${risk.type}</div>
                        <div class="risk-desc">${risk.description}</div>
                        <div class="risk-recommendation">${risk.recommendation || ''}</div>
                      </div>`;
    });
    
    riskDetailsElement.innerHTML = detailsHtml;
  } else if (!foundRisks) {
    // 위험 요소가 없으면 기본 메시지 표시
    riskElement.textContent = '확인된 위험 요소 없음';
    riskDetailsElement.textContent = '확인된 위험 요소 없음';
  }
  
  // 기존 위험 요소 (data.risk_factors)가 있다면 추가로 표시
  if (data.risk_factors && data.risk_factors.length > 0) {
    foundRisks = true;
    let riskHtml = riskElement.innerHTML === '확인된 위험 요소 없음' ? '<ul>' : 
                   riskElement.innerHTML.replace('</ul>', '');
                   
    data.risk_factors.forEach(risk => {
      riskHtml += `<li>${risk.type}: ${risk.description}</li>`;
    });
    
    riskHtml += '</ul>';
    riskElement.innerHTML = riskHtml;
  }
}

// 엔트로피 설명 반환 함수
function getEntropyDescription(entropy) {
  if (entropy < 1.0) return '매우 낮음 (반복 패턴)';
  if (entropy < 3.0) return '낮음';
  if (entropy < 5.0) return '보통';
  if (entropy < 7.0) return '높음';
  return '매우 높음 (암호화/압축)';
}

// 바이트 크기 포맷 함수
function formatBytes(bytes, decimals = 2) {
  if (bytes === 0) return '0 Bytes';
  
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB', 'EB', 'ZB', 'YB'];
  
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}

// 색상 그라데이션 생성 함수
function generateColorGradient(length) {
  const colors = [];
  for (let i = 0; i < length; i++) {
    const hue = (i / length) * 240; // 0(빨강)에서 240(파랑)까지
    colors.push(`hsla(${hue}, 100%, 50%, 0.7)`);
  }
  return colors;
}
