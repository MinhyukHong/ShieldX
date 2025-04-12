import os
import math
import hashlib
import collections
import json
import numpy as np
from datetime import datetime

class FileAnalyzer:
    def __init__(self):
        """파일 분석기 초기화"""
        pass
        
    def analyze_file(self, file_path):
        """파일에 대한 종합 분석 수행"""
        if not os.path.exists(file_path):
            return {"error": f"파일을 찾을 수 없음: {file_path}"}
            
        result = {}
        
        # 기본 파일 정보
        result.update(self.get_file_info(file_path))
        
        # 엔트로피 및 바이트 통계
        result.update(self.analyze_byte_statistics(file_path))
        
        # 파일 타입별 특수 분석
        file_type = self.detect_file_type(file_path)
        result["file_type"] = file_type
        
        if file_type == "PE":
            # Windows 실행 파일인 경우 PE 분석 추가
            try:
                import pefile
                result.update(self.analyze_pe_file(file_path))
            except ImportError:
                result["pe_analysis"] = "pefile 라이브러리가 설치되지 않아 PE 분석을 수행할 수 없습니다."
        
        # 위험 요소 분석
        result["risk_factors"] = self.analyze_risk_factors(file_path, result)
        
        return result
    
    def get_file_info(self, file_path):
        """기본 파일 메타데이터 수집"""
        info = {}
        try:
            file_stat = os.stat(file_path)
            info["filename"] = os.path.basename(file_path)
            info["size_bytes"] = file_stat.st_size
            info["size_human"] = self.human_readable_size(file_stat.st_size)
            info["created_time"] = datetime.fromtimestamp(file_stat.st_ctime).isoformat()
            info["modified_time"] = datetime.fromtimestamp(file_stat.st_mtime).isoformat()
            info["accessed_time"] = datetime.fromtimestamp(file_stat.st_atime).isoformat()
            
            # 해시값 계산
            with open(file_path, 'rb') as f:
                content = f.read()
                info["md5"] = hashlib.md5(content).hexdigest()
                info["sha1"] = hashlib.sha1(content).hexdigest()
                info["sha256"] = hashlib.sha256(content).hexdigest()
                
        except Exception as e:
            info["error"] = f"파일 정보 수집 중 오류: {str(e)}"
            
        return info
    
    def analyze_byte_statistics(self, file_path, sample_size=None):
        """파일의 바이트 통계 및 엔트로피 계산"""
        stats = {}
        try:
            with open(file_path, 'rb') as f:
                content = f.read(sample_size) if sample_size else f.read()
                
            # 바이트 빈도 계산
            byte_freq = collections.Counter(content)
            total_bytes = len(content)
            
            # 엔트로피 계산
            entropy = 0
            for count in byte_freq.values():
                probability = count / total_bytes
                entropy -= probability * math.log2(probability)
                
            stats["entropy"] = entropy
            stats["entropy_normalized"] = entropy / 8.0  # 8비트 기준 정규화
            
            # 바이트 분포 (시각화용)
            byte_dist = [0] * 256
            for byte, count in byte_freq.items():
                byte_dist[byte] = count / total_bytes
                
            stats["byte_distribution"] = byte_dist
            
            # NULL 바이트 및 텍스트 바이트 비율
            null_bytes = byte_freq.get(0, 0)
            text_bytes = sum(byte_freq.get(b, 0) for b in range(32, 127))
            
            stats["null_byte_ratio"] = null_bytes / total_bytes
            stats["text_byte_ratio"] = text_bytes / total_bytes
            
        except Exception as e:
            stats["error"] = f"바이트 통계 분석 중 오류: {str(e)}"
            
        return stats
    
    def detect_file_type(self, file_path):
        """파일 타입 감지"""
        try:
            with open(file_path, 'rb') as f:
                header = f.read(16)
                
            # PE 파일 (Windows 실행 파일)
            if header[0:2] == b'MZ':
                return "PE"
            # ELF 파일 (Linux 실행 파일)
            elif header[0:4] == b'\x7fELF':
                return "ELF"
            # PDF 파일
            elif header[0:4] == b'%PDF':
                return "PDF"
            # ZIP 파일 (및 Office 문서)
            elif header[0:4] == b'PK\x03\x04':
                return "ZIP"
            # 기타 파일 타입 등...
            else:
                return "UNKNOWN"
                
        except Exception:
            return "UNKNOWN"
    
    def analyze_pe_file(self, file_path):
        """PE 파일 분석 (Windows 실행 파일)"""
        pe_data = {}
        try:
            import pefile
            pe = pefile.PE(file_path)
            
            # 기본 PE 정보
            pe_data["is_dll"] = pe.is_dll()
            pe_data["is_exe"] = pe.is_exe()
            pe_data["cpu_type"] = "x64" if pe.FILE_HEADER.Machine == pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"] else "x86"
            
            # 컴파일 시간
            timestamp = pe.FILE_HEADER.TimeDateStamp
            try:
                pe_data["compile_time"] = datetime.fromtimestamp(timestamp).isoformat()
            except:
                pe_data["compile_time"] = "Invalid timestamp"
            
            # 임포트 분석
            imports = {}
            try:
                for entry in pe.DIRECTORY_ENTRY_IMPORT:
                    dll_name = entry.dll.decode('utf-8', errors='ignore')
                    imports[dll_name] = []
                    for imp in entry.imports:
                        if imp.name:
                            imports[dll_name].append(imp.name.decode('utf-8', errors='ignore'))
                        else:
                            imports[dll_name].append(f"Ordinal {imp.ordinal}")
            except AttributeError:
                pass
                
            pe_data["imports"] = imports
            
            # 섹션 정보
            sections = []
            for section in pe.sections:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                sections.append({
                    "name": section_name,
                    "size": section.SizeOfRawData,
                    "entropy": section.get_entropy()
                })
            pe_data["sections"] = sections
            
            # 악성코드와 관련된 특성 분석
            pe_data["suspicious_characteristics"] = self.check_pe_suspicious_characteristics(pe)
            
        except Exception as e:
            pe_data["error"] = f"PE 파일 분석 중 오류: {str(e)}"
            
        return {"pe_analysis": pe_data}
    
    def check_pe_suspicious_characteristics(self, pe):
        """PE 파일에서 악성코드 관련 특성 확인"""
        suspicious = []
        
        # 의심스러운 섹션 이름 확인
        unusual_sections = [".evil", ".crck", ".boom", ".hack", ".slid", ".cccc"]
        for section in pe.sections:
            section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
            if section_name in unusual_sections:
                suspicious.append(f"의심스러운 섹션 이름: {section_name}")
                
        # 높은 엔트로피 섹션 (패킹 또는 암호화 흔적)
        for section in pe.sections:
            entropy = section.get_entropy()
            if entropy > 7.0:
                section_name = section.Name.decode('utf-8', errors='ignore').strip('\x00')
                suspicious.append(f"높은 엔트로피 섹션 (패킹 흔적): {section_name}, 엔트로피: {entropy:.2f}")
                
        # 의심스러운 임포트 확인
        suspicious_imports = [
            "CreateRemoteThread", "WriteProcessMemory", "VirtualAllocEx", 
            "ReadProcessMemory", "CreateProcess", "WinExec", "ShellExecute"
        ]
        
        try:
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8', errors='ignore')
                for imp in entry.imports:
                    if imp.name:
                        imp_name = imp.name.decode('utf-8', errors='ignore')
                        if imp_name in suspicious_imports:
                            suspicious.append(f"의심스러운 API 임포트: {dll_name}.{imp_name}")
        except AttributeError:
            pass
            
        # 리소스 섹션 확인
        try:
            if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
                for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                    if resource_type.name is not None:
                        name = resource_type.name
                    else:
                        name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, "UNKNOWN")
                    if name == "RT_ICON" and len(resource_type.directory.entries) > 10:
                        suspicious.append("비정상적으로 많은 아이콘 리소스 (10개 이상)")
        except (AttributeError, IndexError):
            pass
            
        return suspicious
    
    def analyze_risk_factors(self, file_path, analysis_data):
        """파일의 위험 요소 분석"""
        risk_factors = []
        
        # 엔트로피 기반 위험 요소
        entropy = analysis_data.get("entropy", 0)
        if entropy > 7.0:
            risk_factors.append({
                "type": "PACKING",
                "severity": "medium",
                "description": f"높은 엔트로피 (값: {entropy:.2f})는 파일이 패킹되었거나 암호화되었을 가능성을 나타냅니다.",
                "recommendation": "패킹된 파일은 악성코드가 자신을 숨기는 데 일반적으로 사용되는 기법입니다. 신뢰할 수 있는 소스가 아니라면 실행하지 마세요."
            })
            
        # PE 파일 특이사항 (Windows 실행 파일)
        if analysis_data.get("file_type") == "PE" and "pe_analysis" in analysis_data:
            pe_data = analysis_data["pe_analysis"]
            
            # 의심스러운 특성 확인
            if "suspicious_characteristics" in pe_data:
                for char in pe_data["suspicious_characteristics"]:
                    if "의심스러운 API 임포트" in char:
                        risk_factors.append({
                            "type": "SUSPICIOUS_API",
                            "severity": "high",
                            "description": f"{char}는 시스템 침투나 권한 상승에 사용될 수 있습니다.",
                            "recommendation": "이 파일은 프로세스 조작 기능이 있으므로 신뢰할 수 없는 소스에서 받은 경우 실행하지 마세요."
                        })
                    elif "높은 엔트로피 섹션" in char:
                        risk_factors.append({
                            "type": "OBFUSCATION",
                            "severity": "medium",
                            "description": char,
                            "recommendation": "이 파일은 코드 난독화 기법이 사용되었을 가능성이 있습니다. 신뢰할 수 있는 소스인지 확인하세요."
                        })
                    elif "의심스러운 섹션 이름" in char:
                        risk_factors.append({
                            "type": "SUSPICIOUS_SECTION",
                            "severity": "medium",
                            "description": char,
                            "recommendation": "이 파일에는 비정상적인 섹션 이름이 포함되어 있습니다."
                        })
                    else:
                        risk_factors.append({
                            "type": "OTHER_SUSPICIOUS",
                            "severity": "low",
                            "description": char,
                            "recommendation": "이 파일에서 의심스러운 특성이 발견되었습니다."
                        })
                        
        # 체크섬 검증
        # (여기서는 VirusTotal 같은 외부 API 연동이 필요하므로 예시로만 표시)
        # 실제 구현시 VirusTotal, MalwareBazaar 등의 API를 연동하여 해시 검증 필요
                
        return risk_factors
        
    def human_readable_size(self, size_bytes):
        """바이트 단위를 사람이 읽기 쉬운 크기로 변환"""
        if size_bytes == 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 2)
        return f"{s} {size_name[i]}"