import threading
from queue import Queue
import os
import json
import time
from file_analyzer import FileAnalyzer
import hashlib
from ml_naive_bayes import NaiveBayes

# 결과 저장 디렉토리
RESULTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')
os.makedirs(RESULTS_DIR, exist_ok=True)

# 파일 해시 계산 함수
def calculate_file_hash(file_path):
    hasher = hashlib.sha256()
    try:
        with open(file_path, 'rb') as f:
            buf = f.read()
            hasher.update(buf)
        return hasher.hexdigest()
    except Exception as e:
        print(f"해시 계산 오류: {e}")
        return None

# 결과 저장 함수
def save_result(file_path, result, analysis_type):
    try:
        file_hash = calculate_file_hash(file_path)
        if not file_hash:
            file_hash = "unknown_hash"
        
        result_file = os.path.join(RESULTS_DIR, f"{file_hash}_{analysis_type}.json")
        
        with open(result_file, 'w', encoding='utf-8') as f:
            json.dump(result, f, ensure_ascii=False, indent=2)
        
        print(f"[{analysis_type}] 결과 저장 완료: {result_file}")
        return result_file
    except Exception as e:
        print(f"결과 저장 오류: {e}")
        return None

# StaticWorker: 정적 분석 담당
class StaticWorker(threading.Thread):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue
        self.file_analyzer = FileAnalyzer()

    def run(self):
        while True:
            task = self.queue.get()
            if task is None:  # 종료 신호
                break

            try:
                print(f"[StaticWorker] 파일 분석 시작: {task}")
                # FileAnalyzer를 호출하여 정적 분석 수행
                result = self.file_analyzer.analyze_file(task)
                
                # 결과 저장
                result_file = save_result(task, result, "static")
                print(f"[StaticWorker] 파일 분석 완료: {task}")
            except Exception as e:
                print(f"[StaticWorker] 오류 발생: {e}")
            
            self.queue.task_done()

# DynamicWorker: 동적 분석 담당
class DynamicWorker(threading.Thread):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue

    def run_in_sandbox(self, sample_path):
        """Docker 샌드박스 컨테이너에서 파일 실행 및 모니터링"""
        import subprocess
        import shlex
        
        # 샘플 절대 경로 가져오기
        sample_abs_path = os.path.abspath(sample_path)
        
        # 타임스탬프로 결과 디렉토리 생성
        result_dir = os.path.join(RESULTS_DIR, f"sandbox_{int(time.time())}")
        os.makedirs(result_dir, exist_ok=True)
        
        try:
            print(f"[DynamicWorker] 샌드박스 실행 준비: {sample_path}")
            
            # Docker 이미지가 존재하는지 확인
            check_cmd = "docker image ls -q sandbox-image"
            result = subprocess.run(shlex.split(check_cmd), capture_output=True, text=True)
            
            if not result.stdout.strip():
                print("[DynamicWorker] 샌드박스 이미지 빌드 시작...")
                # 이미지 빌드
                build_cmd = f"docker build -t sandbox-image -f {os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}/Dockerfile ."
                subprocess.run(shlex.split(build_cmd), check=True)
            
            # 샌드박스 실행
            cmd = f"docker run --rm -v {sample_abs_path}:/sample/target:ro sandbox-image /sample/target"
            print(f"[DynamicWorker] 샌드박스 명령어: {cmd}")
            
            # 제한 시간 30초로 실행
            proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True, timeout=30)
            
            # 결과 수집
            result = {
                "exit_code": proc.returncode,
                "stdout": proc.stdout,
                "stderr": proc.stderr,
                "execution_time": "30s (최대)",
                "file_path": sample_path
            }
            
            return result
            
        except subprocess.TimeoutExpired:
            print(f"[DynamicWorker] 샌드박스 실행 시간 초과")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": "Execution timeout",
                "execution_time": "30s (최대, 타임아웃)",
                "file_path": sample_path
            }
        except Exception as e:
            print(f"[DynamicWorker] 샌드박스 실행 오류: {e}")
            return {
                "exit_code": -1,
                "stdout": "",
                "stderr": str(e),
                "execution_time": "오류 발생",
                "file_path": sample_path
            }

    def run(self):
        while True:
            task = self.queue.get()
            if task is None:  # 종료 신호
                break

            try:
                print(f"[DynamicWorker] 동적 분석 시작: {task}")
                # Docker 샌드박스를 호출하여 동적 분석 수행
                result = self.run_in_sandbox(task)
                
                # 결과 저장
                result_file = save_result(task, result, "dynamic")
                print(f"[DynamicWorker] 동적 분석 완료: {task}")
            except Exception as e:
                print(f"[DynamicWorker] 오류 발생: {e}")
            
            self.queue.task_done()

# 큐 초기화
static_queue = Queue()
dynamic_queue = Queue()
ml_queue = Queue()

# MLWorker: 머신러닝 분석 담당
class MLWorker(threading.Thread):
    def __init__(self, queue):
        super().__init__()
        self.queue = queue
        self.model = NaiveBayes()
        self._init_model()
    
    def _init_model(self):
        """초기 모델 설정 (미리 훈련된 모델이 없는 경우 간단한 데이터로 초기화)"""
        # 간단한 초기 훈련 데이터
        # 실제로는 더 많은 데이터와 특성이 필요합니다
        training_data = [
            ({"entropy": 0.9, "null_byte_ratio": 0.1, "text_byte_ratio": 0.8}, "benign"),
            ({"entropy": 7.2, "null_byte_ratio": 0.05, "text_byte_ratio": 0.4}, "malicious"),
            ({"entropy": 6.8, "null_byte_ratio": 0.3, "text_byte_ratio": 0.2}, "malicious"),
            ({"entropy": 2.1, "null_byte_ratio": 0.01, "text_byte_ratio": 0.9}, "benign"),
            ({"entropy": 4.5, "null_byte_ratio": 0.02, "text_byte_ratio": 0.75}, "benign"),
        ]
        
        self.model.train(training_data)
        print("[MLWorker] 기본 모델 초기화 완료")
    
    def extract_features(self, static_result, dynamic_result=None):
        """정적 및 동적 분석 결과에서 특성 추출"""
        features = {}
        
        # 정적 분석 특성
        if static_result:
            features["entropy"] = static_result.get("entropy", 0)
            features["null_byte_ratio"] = static_result.get("null_byte_ratio", 0)
            features["text_byte_ratio"] = static_result.get("text_byte_ratio", 0)
        
        # 동적 분석 특성 (가능한 경우)
        if dynamic_result:
            # 여기에 동적 분석 결과에서 특성 추출 코드 추가
            features["exit_code"] = 1 if dynamic_result.get("exit_code", 0) != 0 else 0
        
        return features
    
    def run(self):
        while True:
            task = self.queue.get()
            if task is None:  # 종료 신호
                break
                
            try:
                file_path, file_hash = task
                print(f"[MLWorker] 머신러닝 분석 시작: {file_path}")
                
                # 정적 및 동적 분석 결과 로드
                static_result = None
                dynamic_result = None
                
                static_result_path = os.path.join(RESULTS_DIR, f"{file_hash}_static.json")
                dynamic_result_path = os.path.join(RESULTS_DIR, f"{file_hash}_dynamic.json")
                
                # 정적 분석 결과 확인
                if os.path.exists(static_result_path):
                    with open(static_result_path, 'r', encoding='utf-8') as f:
                        static_result = json.load(f)
                
                # 동적 분석 결과 확인
                if os.path.exists(dynamic_result_path):
                    with open(dynamic_result_path, 'r', encoding='utf-8') as f:
                        dynamic_result = json.load(f)
                
                # 특성 추출
                features = self.extract_features(static_result, dynamic_result)
                
                # 예측
                prediction = "unknown"
                if features:
                    prediction = self.model.predict(features)
                
                # 결과 저장
                result = {
                    "file_path": file_path,
                    "prediction": prediction,
                    "features": features,
                    "confidence": 0.8,  # 간단한 예제에서는 고정값 사용
                    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
                }
                
                result_file = save_result(file_path, result, "ml")
                print(f"[MLWorker] 머신러닝 분석 완료: {file_path}, 결과: {prediction}")
                
            except Exception as e:
                print(f"[MLWorker] 오류 발생: {e}")
            
            self.queue.task_done()

# 워커 스레드 시작
static_worker = StaticWorker(static_queue)
dynamic_worker = DynamicWorker(dynamic_queue)
ml_worker = MLWorker(ml_queue)

static_worker.start()
dynamic_worker.start()
ml_worker.start()
