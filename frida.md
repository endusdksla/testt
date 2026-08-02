# Frida 동적분석 세팅 가이드

## 환경
- 호스트: macOS
- 게스트 VM: Windows ARM11 @ 172.16.217.128
- frida-server 포트: 27042

---

## 설치

### 1. 호스트 macOS (venv)
```bash
cd /Users/endusdksla/study/rev/Malware
source venv/bin/activate
pip install frida frida-tools
```

### 2. VM Windows ARM — frida-server 다운로드
GitHub Releases에서 windows-arm64 버전 다운로드:
https://github.com/frida/frida/releases
→ `frida-server-*-windows-arm64.exe.xz` 다운로드 후 압축 해제

---

## VM 실행 설정

### 방화벽 허용 (최초 1회, 관리자 PowerShell)
```powershell
netsh advfirewall firewall add rule name="frida" dir=in action=allow protocol=TCP localport=27042
```

### frida-server 실행 (관리자 권한 필요, -l 옵션 필수)
```powershell
.\frida-server.exe -l 0.0.0.0:27042
```
> `-l 0.0.0.0:27042` 없이 실행하면 외부에서 연결 불가

### 실행 확인
```powershell
netstat -ano | findstr 27042
# LISTENING 상태여야 함
```

---

## 호스트에서 연결 확인
```bash
nc -zv 172.16.217.128 27042
# Connection succeeded 확인
```

---

## 사용법

```bash
source venv/bin/activate

# 프로세스 목록 조회
frida-ps -H 172.16.217.128:27042

# 실행 중인 프로세스에 attach
frida -H 172.16.217.128:27042 -n target.exe

# 프로세스 spawn 후 attach
frida -H 172.16.217.128:27042 -f "C:\path\to\target.exe"

# API 호출 트레이싱
frida-trace -H 172.16.217.128:27042 -n target.exe -i "CreateFile*" -i "RegOpenKey*"
```

---

## 트러블슈팅

| 증상 | 원인 | 해결 |
|------|------|------|
| 포트 타임아웃 | -l 옵션 미사용 | `frida-server.exe -l 0.0.0.0:27042`로 재실행 |
| 포트 타임아웃 | 방화벽 차단 | 방화벽 규칙 추가 |
| frida-ps 비어있음 | 관리자 권한 없이 실행 | 관리자 PowerShell로 재실행 |
