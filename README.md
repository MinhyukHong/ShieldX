# ShieldX

가상환경 설정 안내
프로젝트를 실행하기 위한 가상환경 설정 방법은 다음과 같습니다:

### 가상환경 생성 및 활성화
``` 
# 가상환경 생성
python3 -m venv venv

#가상환경 활성화 (macOS/Linux)
source venv/bin/activate

# 가상환경 활성화 (Windows)
venv\Scripts\activate
```

### 의존성 설치
```
# 필요한 패키지 설치
pip install -r requirements.txt

# pip 최신 버전으로 업그레이드 (선택사항)
pip install --upgrade pip
```