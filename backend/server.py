import os
import datetime
import hashlib
import json
from flask import Flask, jsonify, request
from flask_cors import CORS
from file_analyzer import FileAnalyzer
from werkzeug.utils import secure_filename
from worker import static_queue, dynamic_queue, ml_queue

# 결과 저장 디렉토리
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# 업로드 폴더 설정
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

import tempfile
import json
from file_analyzer import FileAnalyzer
from worker import static_queue, dynamic_queue
from werkzeug.utils import secure_filename

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

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route("/results/<file_hash>", methods=["GET"])
def get_scan_results(file_hash):
    """특정 파일 해시에 대한 분석 결과 조회"""
    static_result_path = os.path.join(RESULTS_DIR, f"{file_hash}_static.json")
    dynamic_result_path = os.path.join(RESULTS_DIR, f"{file_hash}_dynamic.json")
    ml_result_path = os.path.join(RESULTS_DIR, f"{file_hash}_ml.json")
    
    results = {}
    
    # 정적 분석 결과 확인
    if os.path.exists(static_result_path):
        with open(static_result_path, 'r', encoding='utf-8') as f:
            results['static_analysis'] = json.load(f)
    
    # 동적 분석 결과 확인
    if os.path.exists(dynamic_result_path):
        with open(dynamic_result_path, 'r', encoding='utf-8') as f:
            results['dynamic_analysis'] = json.load(f)
    
    # ML 분석 결과 확인
    if os.path.exists(ml_result_path):
        with open(ml_result_path, 'r', encoding='utf-8') as f:
            results['ml_analysis'] = json.load(f)
    
    if not results:
        return jsonify({"message": "해당 파일에 대한 분석 결과가 없습니다."}), 404
    
    return jsonify(results), 200

@app.route("/scan", methods=["POST"])
def scan_file():
    """파일 스캔 요청 처리"""
    # 파일 업로드 처리
    if 'file' not in request.files:
        return jsonify({"message": "No file part in the request"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"message": "No selected file"}), 400

    # 파일 저장
    filename = secure_filename(file.filename)
    file_path = os.path.join(UPLOAD_FOLDER, filename)
    file.save(file_path)
    
    # 파일 해시 계산
    file_hash = None
    try:
        hasher = hashlib.sha256()
        with open(file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        file_hash = hasher.hexdigest()
    except Exception as e:
        print(f"해시 계산 오류: {e}")
    
    # 정적 및 동적 큐에 작업 추가
    static_queue.put(file_path)
    dynamic_queue.put(file_path)
    
    # 정적 및 동적 분석이 완료된 후 ML 워커에 추가하기 위해
    # 파일 경로와 해시를 전달
    if file_hash:
        ml_queue.put((file_path, file_hash))

    response = {
        "message": "파일 스캔 작업이 큐에 추가되었습니다.", 
        "file_path": file_path
    }
    
    if file_hash:
        response["file_hash"] = file_hash
        response["results_url"] = f"/results/{file_hash}"
    
    return jsonify(response), 202

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
    app.run(debug=True, port=5001)  # 포트를 5001로 변경