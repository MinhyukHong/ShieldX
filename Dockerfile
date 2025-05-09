# 베이스 이미지
FROM debian:stable-slim

# 필수 패키지 설치
RUN apt-get update && apt-get install -y \
    strace \
    procps \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# 작업 디렉토리 설정
WORKDIR /sandbox

# 샘플 파일 마운트 지점
VOLUME /sample

# 기본 실행 명령
ENTRYPOINT ["/bin/strace", "-f", "-o", "/trace.log"]
