from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import hashlib
import tempfile
import json
import datetime 
from file_analyzer import FileAnalyzer

try:
    import yara
    YARA_AVAILABLE = True
except ImportError:
    YARA_AVAILABLE = False
    print("⚠️ yara-python 모듈을 찾을 수 없습니다. YARA 스캐닝이 비활성화됩니다.")

# YARA 스캐너 클래스 정의
class YaraScanner:
    def __init__(self, rules_directory):
        """YARA 스캐너 초기화"""
        self.rules = None
        self.rules_directory = rules_directory
        self.compile_rules()
        
    def compile_rules(self):
        """YARA 규칙 컴파일"""
        if not YARA_AVAILABLE:
            print("YARA 모듈이 설치되지 않아 규칙을 컴파일할 수 없습니다.")
            return
            
        try:
            filepaths = {}
            # 디렉토리에서 모든 .yar 파일 찾기
            if os.path.exists(self.rules_directory):
                for filename in os.listdir(self.rules_directory):
                    if filename.endswith('.yar'):
                        file_path = os.path.join(self.rules_directory, filename)
                        filepaths[filename] = file_path
                
                if filepaths:
                    self.rules = yara.compile(filepaths=filepaths)
                    print(f"YARA 규칙 컴파일 완료. 로드된 파일: {', '.join(filepaths.keys())}")
                else:
                    print(f"디렉토리 {self.rules_directory}에서 YARA 규칙 파일을 찾을 수 없습니다.")
            else:
                print(f"YARA 규칙 디렉토리가 존재하지 않습니다: {self.rules_directory}")
        except Exception as e:
            print(f"YARA 규칙 컴파일 실패: {str(e)}")
            self.rules = None
    
    def scan_file(self, file_path):
        """파일을 스캔하여 YARA 규칙과 일치하는지 확인"""
        if not YARA_AVAILABLE or not self.rules:
            print("YARA 스캔을 수행할 수 없습니다.")
            return []
            
        try:
            matches = self.rules.match(file_path)
            if matches:
                match_names = [match.rule for match in matches]
                print(f"파일 {file_path}에서 다음 규칙 일치: {', '.join(match_names)}")
            return matches
        except Exception as e:
            print(f"파일 {file_path} 스캔 중 오류 발생: {str(e)}")
            return []

# 시스템 파일 필터링 함수 추가
def is_system_file(filename):
    """시스템 파일인지 확인"""
    system_files = ['.DS_Store', 'Thumbs.db', 'desktop.ini', '.localized']
    return filename in system_files or filename.startswith('.')

# 분석 결과 요약 함수 추가
def summarize_analysis(analysis):
    """분석 결과에서 중요 정보만 추출"""
    if not analysis:
        return {}
    
    # 중요 정보만 추출
    summary = {
        "file_info": {
            "filename": analysis.get("filename"),
            "size": analysis.get("size_human"),
            "modified_time": analysis.get("modified_time"),
            "file_type": analysis.get("file_type", "UNKNOWN"),
        },
        "security_info": {
            "md5": analysis.get("md5"),
            "sha1": analysis.get("sha1"),
            "sha256": analysis.get("sha256"),
            "entropy_score": round(analysis.get("entropy_normalized", 0) * 10, 1),
        }
    }
    
    # 위험 요소가 있는 경우만 포함
    risk_factors = analysis.get("risk_factors", [])
    if risk_factors:
        summary["security_info"]["risk_factors"] = risk_factors
    
    return summary

# API 응답 구성 함수 추가
def prepare_scan_response(filename, file_hash, prediction, yara_results, detailed_analysis):
    """스캔 응답 데이터 구성"""
    # 분석 결과 요약
    summary = summarize_analysis(detailed_analysis)
    
    # 기본 응답 구성
    response = {
        "scan_result": {
            "filename": filename,
            "prediction": prediction,
            "scan_time": datetime.datetime.now().isoformat(),
        },
        "file_details": summary.get("file_info", {}),
        "security_details": summary.get("security_info", {})
    }
    
    # YARA 결과가 있으면 추가
    if yara_results:
        response["yara_matches"] = [
            {"rule": match.get("rule"), "description": match.get("meta", {}).get("description", "N/A")}
            for match in yara_results
        ]
    
    return response

# 파일 분석기 초기화
file_analyzer = FileAnalyzer()

# 간단한 악성코드 예측 함수 (실제 모델 없이)
def predict_malware(file_path_or_content):
    return "benign"  # 기본값으로 안전하다고 판단

# JSON 직렬화를 위한 기본 함수 추가
def json_default(obj):
    if isinstance(obj, (datetime.date, datetime.datetime)):
        return obj.isoformat()
    return str(obj)

# 현재 디렉토리 기준 상대 경로
current_dir = os.path.dirname(os.path.abspath(__file__))
YARA_RULES_DIR = os.path.join(current_dir, "rules", "yara")

# YARA 스캐너 초기화 (있는 경우에만)
yara_scanner = YaraScanner(YARA_RULES_DIR) if YARA_AVAILABLE else None

app = Flask(__name__)
CORS(app)  # 크로스 오리진 요청 허용

@app.route("/scan", methods=["POST"])
def scan_file():
    # 모든 응답을 위한 기본 오류 응답 형식
    error_response = {
        "scan_result": {
            "prediction": "error",
            "scan_time": datetime.datetime.now().isoformat(),
        },
        "message": "파일이 없거나 스캔 요청이 잘못되었습니다"
    }
    
    # JSON 요청 처리 부분
    if request.json:
        action = request.json.get('action')
        
        if action == 'scan_recent_downloads':
            # 다운로드 폴더에서 시스템 파일 제외한 최근 파일 찾기
            download_dir = os.path.expanduser("~/Downloads")
            files = sorted(
                [os.path.join(download_dir, f) for f in os.listdir(download_dir) 
                 if os.path.isfile(os.path.join(download_dir, f)) and not is_system_file(f)],
                key=os.path.getmtime,
                reverse=True
            )
            
            if not files:
                return json.dumps({
                    "scan_result": {
                        "prediction": "benign",
                        "scan_time": datetime.datetime.now().isoformat(),
                    },
                    "message": "최근 다운로드 파일 없음"
                }, default=json_default, indent=2), 200, {'Content-Type': 'application/json'}
            
            recent_file = files[0]
            filename = os.path.basename(recent_file)
            file_hash = hashlib.md5(open(recent_file, 'rb').read()).hexdigest()
            
            # YARA 스캔 수행
            yara_results = []
            prediction = "benign"
            
            if YARA_AVAILABLE and yara_scanner:
                yara_matches = yara_scanner.scan_file(recent_file)
                if yara_matches:
                    prediction = "malicious"
                    yara_results = [{"rule": match.rule, "meta": getattr(match, 'meta', {})} for match in yara_matches]
            
            # 상세 분석 수행
            detailed_analysis = file_analyzer.analyze_file(recent_file)
            
            # 응답 데이터 구성
            response_data = prepare_scan_response(
                filename, file_hash, prediction, yara_results, detailed_analysis
            )
            
            return json.dumps(response_data, default=json_default, indent=2), 200, {'Content-Type': 'application/json'}
        
        elif action == 'scan_file':
            # 파일 경로로 스캔 요청을 받았을 때
            filepath = request.json.get('filepath')
            if not filepath:
                error_response["message"] = "파일 경로가 제공되지 않았습니다."
                return json.dumps(error_response, default=json_default, indent=2), 400, {'Content-Type': 'application/json'}
            
            # 가능하면 전체 경로 구성
            if not os.path.isabs(filepath):
                filepath = os.path.join(os.path.expanduser("~/Downloads"), os.path.basename(filepath))
            
            if not os.path.exists(filepath):
                return json.dumps({
                    "scan_result": {
                        "prediction": "benign", 
                        "scan_time": datetime.datetime.now().isoformat(),
                    },
                    "message": f"파일을 찾을 수 없음: {filepath}"
                }, default=json_default, indent=2), 404, {'Content-Type': 'application/json'}
            
            filename = os.path.basename(filepath)
            file_hash = hashlib.md5(open(filepath, 'rb').read()).hexdigest()
            
            # YARA 스캔 수행
            yara_results = []
            prediction = "benign"
            
            if YARA_AVAILABLE and yara_scanner:
                yara_matches = yara_scanner.scan_file(filepath)
                if yara_matches:
                    prediction = "malicious"
                    yara_results = [{"rule": match.rule, "meta": getattr(match, 'meta', {})} for match in yara_matches]
            
            # FileAnalyzer를 사용한 상세 분석 추가
            detailed_analysis = file_analyzer.analyze_file(filepath)
            
            # 응답 데이터 구성
            response_data = prepare_scan_response(
                filename, file_hash, prediction, yara_results, detailed_analysis
            )
            
            return json.dumps(response_data, default=json_default, indent=2), 200, {'Content-Type': 'application/json'}
    
    # 파일 업로드 처리 부분
    if "file" in request.files:
        uploaded_file = request.files["file"]
        os.makedirs("uploads", exist_ok=True)
        file_path = os.path.join("uploads", uploaded_file.filename)
        uploaded_file.save(file_path)

        # 간단한 해시 값 계산
        file_hash = hashlib.md5(open(file_path, 'rb').read()).hexdigest()

        # YARA 스캔 수행 (가능한 경우)
        yara_results = []
        prediction = "benign"
        
        if YARA_AVAILABLE and yara_scanner:
            yara_matches = yara_scanner.scan_file(file_path)
            if yara_matches:
                # YARA 매치가 있으면 악성으로 판단
                prediction = "malicious"
                yara_results = [{"rule": match.rule, "meta": getattr(match, 'meta', {})} for match in yara_matches]
            else:
                # YARA 매치가 없으면 기본 함수로 예측
                prediction = predict_malware(file_path)
        else:
            # YARA가 없으면 기본 함수로만 예측
            prediction = predict_malware(file_path)
        
        # 상세 분석 추가
        detailed_analysis = file_analyzer.analyze_file(file_path)
        
        # 응답 데이터 구성
        response_data = prepare_scan_response(
            uploaded_file.filename, file_hash, prediction, yara_results, detailed_analysis
        )
        
        return json.dumps(response_data, default=json_default, indent=2), 200, {'Content-Type': 'application/json'}
    
    # 유효한 요청이 없는 경우
    return json.dumps(error_response, default=json_default, indent=2), 400, {'Content-Type': 'application/json'}

@app.route("/scan_script", methods=["POST"])
def scan_script():
    data = request.json
    script_content = data.get("script", "")

    if not script_content:
        return jsonify({"error": "No script content provided"}), 400

    # 위험한 패턴이 있는지 간단히 확인
    malicious_patterns = [
        "document.cookie", "eval(", ".eval(", 
        "fromCharCode", "String.fromCharCode",
        "document.write(unescape", "base64"
    ]
    
    suspicious_count = 0
    for pattern in malicious_patterns:
        if pattern in script_content:
            suspicious_count += 1
    
    # 간단한 판단 로직
    if suspicious_count >= 3:
        prediction = "malicious"
    else:
        prediction = "benign"
    
    return jsonify({"prediction": prediction})

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)