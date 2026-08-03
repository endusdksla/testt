# IDA Pro MCP + Claude Code / Codex 연결 가이드
# (radare2 / x64dbg와 동일한 네트워크 격리 모델)

## 목표 구조

```text
Host macOS
- Claude Code / Codex Desktop
- ida_mcp_bridge.py (stdio <-> HTTP 중계 역할)

Network (Host-only, VMware Fusion vmnet1 / bridge100)
- 172.16.217.1   (Host)
- 172.16.217.129 (Guest)

Guest VM (Windows ARM)
- IDA Pro + ida-pro-mcp 플러그인 (zeromcp, 모듈러 버전)
- IDA MCP HTTP 서버 (:13337, /mcp)
- 방화벽: 호스트 IP만 TCP 13337 허용

분석 흐름:
호스트 Claude Code / Codex
  → 로컬 ida_mcp_bridge.py 를 stdio MCP 서버로 실행
  → 브리지(python)가 HTTP로 Guest의 IDA MCP (/mcp)에 연결
  → 결과 반환 (바이너리는 Guest에 격리)
```

## 개요

radare2와 동일한 구조지만, **게스트 플러그인이 이미 완전한 MCP를 HTTP로 서빙**하는 점이 다르다:
- **게스트**: IDA Pro의 `ida-pro-mcp` 플러그인이 MCP HTTP 서버로 동작 (포트 13337, `/mcp`, `/sse`)
- **호스트**: `ida_mcp_bridge.py` 가 stdio MCP 서버로 실행되어 게스트 HTTP `/mcp` 에 중계
- **Claude Code / Codex**: 호스트의 로컬 브리지(stdio)만 호출
- **보안**: 바이너리(IDB)는 게스트에만 존재

### ⚠️ 왜 URL 직결이 아니라 브리지가 필요한가 (핵심)

게스트가 `http://172.16.217.129:13337/mcp` 로 표준 MCP를 직접 서빙하므로,
이론상 Claude/Codex 에 `url = ...` 로 바로 등록하면 될 것 같지만 **동작하지 않는다.**

이 호스트에서 **node(Claude Code) / electron(Codex Desktop) 의 아웃바운드가
host-only 게스트로 못 나간다** (`EHOSTUNREACH`). 반면 **curl / python 은 정상**으로 도달한다.
(원인: utun VPN 인터페이스가 게스트 서브넷 라우팅을 스코프에서 밀어내는 것으로 추정.
`node -e fetch` 로 샌드박스 꺼도 재현됨.)

> Codex가 "curl 로 되니까 됨" 이라고 결론내는 건 착각이다 — curl ≠ 앱의 MCP 클라이언트.
> 실제로 `ida_vm` 툴이 tool namespace 에 떠야 "되는" 것.

→ 그래서 **radare2 와 똑같이**, python 이 대신 아웃바운드를 해주는 **로컬 stdio 브리지**를 쓴다.
node/electron 은 자식 python 과 stdio 로만 통신하고, VM 으로의 HTTP 는 python(허용됨)이 수행한다.

---

## 게스트 PC (Windows ARM VM) 설정

### 1. IDA Pro + ida-pro-mcp 플러그인 설치

게스트에서 IDA Pro(유료, IDA Free 불가)와 모듈러 `ida-pro-mcp` 플러그인이 설치되어 있어야 한다.
설치 시 플러그인은 다음 위치에 깔린다:

```
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp.py
%APPDATA%\Hex-Rays\IDA Pro\plugins\ida_mcp\   (zeromcp, api_*.py 등)
```

- `ida_mcp.py --install` 은 **IDA 콘솔이 아니라 일반 셸에서** 실행하는 CLI (플러그인 파일 복사만 함)
- 설치 후 **IDA 재시작 + 분석할 바이너리(IDB) 열기** 필요 (열려 있어야 툴 호출이 동작)

### 2. 리스닝 주소를 0.0.0.0:13337 로

플러그인이 `0.0.0.0:13337` 로 바인딩되어야 호스트에서 접근 가능하다.
IDA 를 켠 뒤 확인:

```powershell
netstat -ano | findstr 13337
```

정상 출력:
```
TCP    0.0.0.0:13337        0.0.0.0:0    LISTENING
```

### 3. Windows 방화벽 설정 (중요)

게스트 Windows PowerShell (관리자):

```powershell
# 호스트 IP(172.16.217.1)만 TCP 13337 접근 허용
New-NetFirewallRule `
  -DisplayName "IDA MCP Host-only" `
  -Direction Inbound `
  -Action Allow `
  -Protocol TCP `
  -LocalPort 13337 `
  -RemoteAddress 172.16.217.1 `
  -Profile Any
```

---

## 호스트 PC (macOS) 설정

### 1. 네트워크 연결 확인

```bash
# TCP 도달 확인 (curl/python 은 되고 node 는 안 되는 게 정상)
nc -zv 172.16.217.129 13337

# 실제 MCP 핸드셰이크까지 확인
curl -s -X POST http://172.16.217.129:13337/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"p","version":"0"}}}'
# -> serverInfo {name: ida-pro-mcp, version: 1.0.0} 나오면 정상
```

### 2. 브리지 스크립트

`/Users/endusdksla/study/rev/Malware/mcp/ida_mcp_bridge.py` (표준 라이브러리만 사용).

- 역할: stdio 로 받은 MCP JSON-RPC 를 게스트 `/mcp` 로 그대로 중계, `Mcp-Session-Id` 유지
- 실행 인터프리터: **malware venv python** (radare2 가 쓰는 것과 동일, VM 아웃바운드 허용됨)
  - `/Users/endusdksla/study/rev/Malware/venv/bin/python3`
- 대상 URL 변경: 첫 번째 인자 또는 `IDA_MCP_URL` 환경변수
  ```bash
  ida_mcp_bridge.py "http://172.16.217.129:13337/mcp"
  # 또는
  IDA_MCP_URL="http://<다른IP>:13337/mcp" ida_mcp_bridge.py
  ```

### 3-a. Claude Code MCP 등록

Claude Code 는 `~/.claude.json` 의 root `mcpServers` 를 읽는다 (`~/.claude/mcp.json` 아님).
CLI 로 등록하는 게 가장 안전:

```bash
claude mcp add ida_vm -s user -- \
  /Users/endusdksla/study/rev/Malware/venv/bin/python3 \
  /Users/endusdksla/study/rev/Malware/mcp/ida_mcp_bridge.py

# 연결 확인 (브리지를 띄워 게스트까지 initialize 함)
claude mcp get ida_vm      # -> Status: ✔ Connected
```

### 3-b. Codex Desktop MCP 등록

`~/.codex/config.toml` (기존 항목은 건드리지 말고 별도 이름으로 추가):

```toml
[mcp_servers.ida_vm]
enabled = true
command = "/Users/endusdksla/study/rev/Malware/venv/bin/python3"
args = ["/Users/endusdksla/study/rev/Malware/mcp/ida_mcp_bridge.py"]
startup_timeout_sec = 30
tool_timeout_sec = 120
```

### 4. 앱 재시작

Claude Code / Codex 를 완전히 재시작해야 MCP 서버가 로드된다.

---

## 연결 테스트

### 호스트에서 브리지 직접 구동 (stdio)

```bash
VENV=/Users/endusdksla/study/rev/Malware/venv/bin/python3
printf '%s\n' \
'{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"t","version":"0"}}}' \
'{"jsonrpc":"2.0","method":"notifications/initialized"}' \
'{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' \
'{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"server_health","arguments":{}}}' \
| "$VENV" /Users/endusdksla/study/rev/Malware/mcp/ida_mcp_bridge.py
# -> initialize / tools/list(65개) / server_health(status ok) 응답
```

### Claude Code / Codex 에서 테스트

재시작 후 `ida_vm` 툴이 tool namespace 에 떠야 한다 (`mcp__ida_vm__*`, Codex 는 `ida_vm/*`).
주요 툴: `server_health`, `list_funcs`, `func_query`, `decompile`, `disasm`,
`imports`, `find_regex`, `survey_binary` 등 (총 65개).

프롬프트 예:
```
ida_vm MCP 로 현재 열린 IDB 를 읽기 전용으로 분석해줘.
1. server_health 로 열린 파일/분석 상태 확인
2. 함수 목록, 임포트 목록, 문자열 확인
```

---

## 트러블슈팅

### 툴이 안 뜸 / FailedToOpenSocket / EHOSTUNREACH
```
- url 직결로 등록하면 발생 (node/electron 이 게스트로 못 나감). 반드시 브리지(command) 방식 사용.
- 브리지가 Connected 인지: claude mcp get ida_vm
- 브리지 자체 테스트: 위 "stdio 직접 구동" 실행
```

### initialize 는 되는데 툴 호출이 -32601 / 이상함
```
- 게스트에 IDB(바이너리)가 안 열려 있음 -> IDA 에서 파일 열기
- 게스트 플러그인 버전 불일치 -> 모듈러 ida-pro-mcp(zeromcp) 인지 확인
```

### 연결 자체가 안 됨 (nc/curl 도 실패)
```
- VM IP 변동: 게스트에서 ipconfig 로 현재 IP 확인 (고정 아님)
  이력: 192.168.41.131 -> 172.16.217.128 -> 172.16.217.129
- 게스트 listen 확인: netstat -ano | findstr 13337  (0.0.0.0:13337)
- 방화벽 룰 확인: Get-NetFirewallRule -DisplayName "IDA MCP Host-only"
- IP 바뀌면 브리지 대상도 갱신: IDA_MCP_URL 또는 args 의 URL
```

---

## 최종 요약

| 항목 | 값 |
|------|-----|
| 게스트 listen | 0.0.0.0:13337 (/mcp, /sse) |
| 게스트 플러그인 | ida-pro-mcp 모듈러 (zeromcp/1.3.0, 65 tools) |
| 게스트 방화벽 | 호스트 IP(172.16.217.1)만 TCP 13337 |
| 호스트 브리지 | ida_mcp_bridge.py (stdio<->HTTP), venv python 으로 실행 |
| Claude Code | ~/.claude.json (claude mcp add ida_vm) |
| Codex | ~/.codex/config.toml [mcp_servers.ida_vm] |
| 직결 URL | ✗ 불가 (node/electron EHOSTUNREACH) — 반드시 브리지 |
| 바이너리 위치 | 게스트 VM 에만 (격리) |
| 네트워크 | Host-only (NAT/Bridged 금지) |

---

## 보안 체크리스트

- [ ] 게스트 방화벽: 호스트 IP(172.16.217.1)만 TCP 13337 허용
- [ ] 바이너리(IDB): 게스트에만 존재 (호스트로 복사하지 않음)
- [ ] 네트워크: Host-only 네트워크 사용 (NAT 아님)
- [ ] 분석 실습 전: 게스트 스냅샷 생성, 공유폴더·클립보드·드래그앤드롭 비활성화
- [ ] 샘플 실행보다 정적 분석 우선
