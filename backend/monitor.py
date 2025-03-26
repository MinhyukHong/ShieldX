#!/usr/bin/env python3
import json
import sys
import time
import struct


def send_message(message):
    """ Chrome에 JSON 형식으로 메시지 전송 """
    message_json = json.dumps(message)
    # 메시지 길이를 리틀 엔디안으로 인코딩
    sys.stdout.buffer.write(struct.pack('<I', len(message_json)))
    # 메시지 내용 전송
    sys.stdout.buffer.write(message_json.encode('utf-8'))
    sys.stdout.buffer.flush()

def read_message():
    """ Chrome으로부터 메시지 읽기 """
    # 메시지 길이 읽기
    raw_length = sys.stdin.buffer.read(4)
    if not raw_length:
        return None
    message_length = struct.unpack('<I', raw_length)[0]
    # 메시지 읽기
    message_raw = sys.stdin.buffer.read(message_length)
    return json.loads(message_raw.decode('utf-8'))

if __name__ == "__main__":
    send_message({"status": "ready"})  # Chrome 확장 프로그램에 시작 알림
    while True:
        message = read_message()
        if message is None:
            break
        if message.get("action") == "start":
            send_message({"status": "running"})
        time.sleep(1)