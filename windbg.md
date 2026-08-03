# windbg MCP (svnscha/mcp-windbg) 연결

호스트(macOS, Claude Code/Codex)에서 게스트 VM(Windows)의 WinDbg/cdb를 MCP로 구동하기 위한 설정.
저장소: https://github.com/svnscha/mcp-windbg

## x64dbg MCP와 구조가 다름 (중요)

| | x64dbg MCP | mcp-windbg |
|---|---|---|
| 디버거 접근 | 게스트 안 **플러그인이 HTTP 서버**를 염 | **cdb.exe/kd.exe를 로컬 subprocess로 직접 실행** |
| MCP 서버(파이썬) 실행 위치 | **호스트(macOS)** — HTTP로 게스트에 붙음 | **cdb가 있는 게스트 Windows** 에서 실행 |
| macOS 호스트에서 서버 실행 | 가능 | **불가능** (macOS엔 cdb.exe 없음) |

→ x64dbg처럼 "호스트에서 py 서버 띄우고 게스트에 붙는" 방식은 windbg엔 **안 됨.**
mcp-windbg는 자기가 cdb.exe를 직접 subprocess로 돌리므로 **서버 자체가 게스트 안에서** 돌아야 한다.
다행히 mcp-windbg는 **streamable-http transport**를 지원해서, 게스트가 직접 HTTP MCP를 서빙하고
호스트는 거기에 붙기만 하면 된다 (IDA zeromcp와 동일한 구조).

## 게스트 VM(Windows)에서 할 일

1. **전제**: Windows Debugging Tools(`cdb.exe`) 설치. windbg 이미 쓰면 있음 (MS Store "WinDbg" 또는
   Windows SDK로 설치되며 자동 탐지됨). Python 3.10+ 필요.
2. **설치**:
   ```powershell
   pip install mcp-windbg
   ```
3. **HTTP transport로 실행** — `--host 0.0.0.0`이 핵심 (x64dbg의 `httpbind 0.0.0.0`과 같은 역할):
   ```powershell
   mcp-windbg --transport streamable-http --host 0.0.0.0 --port 8000
   # 또는: python -m mcp_windbg --transport streamable-http --host 0.0.0.0 --port 8000
   ```
   기본값이 `--host 127.0.0.1`(루프백 전용)이라, 그냥 띄우면 호스트에서 접속 불가.
4. **방화벽 인바운드 8000 허용** (관리자 PowerShell):
   ```powershell
   New-NetFirewallRule -DisplayName "windbg MCP TCP 8000" -Direction Inbound -Protocol TCP -LocalPort 8000 -Action Allow
   ```
5. **(권장) 심볼 경로**:
   ```powershell
   setx _NT_SYMBOL_PATH "SRV*C:\Symbols*https://msdl.microsoft.com/download/symbols"
   ```

### 주요 CLI 플래그
| 플래그 | 기본값 | 설명 |
|--------|--------|------|
| `--transport` | `stdio` | `stdio` 또는 `streamable-http` |
| `--host` | `127.0.0.1` | HTTP 바인드 주소 (외부 접속엔 `0.0.0.0`) |
| `--port` | `8000` | HTTP 포트 |
| `--cdb-path` | 자동탐지 | cdb.exe 경로 |
| `--kd-path` | 자동탐지 | kd.exe 경로(커널 디버깅) |
| `--symbols-path` | `_NT_SYMBOL_PATH` | 심볼 검색 경로 |
| `--timeout` | `60` | 명령/연결 타임아웃(초) |
| `--verbose` | off | stderr 로깅 |

세션 도구: `open_cdb_dump`(덤프 분석), `open_cdb_remote`(원격/라이브), `open_kd_session`(커널).

## 호스트(macOS) 등록 — stdio 브리지 경유 (직접 URL 아님)

**함정**: 이 호스트에서는 Claude Code/Codex(node/electron)의 네트워크 스택이 VMware host-only 게스트로
**직접 못 붙는다(EHOSTUNREACH)**. curl/python만 게스트에 도달한다. 그래서 mcp.json에 `"type":"http"`로
게스트 URL을 직접 넣으면 작동하지 않는다 (IDA `ida_vm`도 같은 이유로 브리지를 쓴다).

해결: python stdio ↔ streamable-http 브리지를 경유한다. 범용 브리지 스크립트:
`/Users/endusdksla/study/rev/Malware/mcp/mcp_http_bridge.py`
(python은 게스트에 도달 가능하므로, 클라이언트↔브리지는 stdio, 브리지↔게스트는 HTTP로 릴레이.
argv[1] 또는 `MCP_HTTP_URL` 환경변수로 대상 URL 지정. `ida_mcp_bridge.py`의 범용 복사본.)

**URL은 반드시 끝에 슬래시 `/mcp/`** — uvicorn/starlette 서버가 `/mcp`(슬래시 없음)로 오면 `/mcp/`로
**307 리다이렉트**하는데, 브리지는 리다이렉트를 안 따라가서 빈 응답만 받는다(연결은 되는데 initialize가
안 됨). 반드시 슬래시 포함으로 등록할 것.

### Claude Code — 실제 설정은 `~/.claude.json` (아래 CLI로 등록)
```bash
claude mcp add-json windbg '{"type":"stdio","command":"/Users/endusdksla/study/rev/Malware/venv/bin/python3","args":["/Users/endusdksla/study/rev/Malware/mcp/mcp_http_bridge.py","http://172.16.217.129:8000/mcp/"],"env":{}}' -s user
```
Claude Code는 `~/.claude/mcp.json`이 아니라 `~/.claude.json` 루트 `mcpServers`를 읽는다(저장소는
`~/.claude/mcp.json`에도 미러를 두지만 그건 문서용). 미러도 같이 두려면 동일 형식으로:
```json
"windbg": {
  "command": "/Users/endusdksla/study/rev/Malware/venv/bin/python3",
  "args": [
    "/Users/endusdksla/study/rev/Malware/mcp/mcp_http_bridge.py",
    "http://172.16.217.129:8000/mcp/"
  ],
  "timeout": 60
}
```

### Codex — `~/.codex/config.toml`
```toml
[mcp_servers.windbg]
enabled = true
command = "/Users/endusdksla/study/rev/Malware/venv/bin/python3"
args = ["/Users/endusdksla/study/rev/Malware/mcp/mcp_http_bridge.py", "http://172.16.217.129:8000/mcp/"]
startup_timeout_sec = 30
tool_timeout_sec = 120
```

- VM IP가 바뀌면 세 곳(`~/.claude.json`, `~/.claude/mcp.json`, `config.toml`)의 `172.16.217.129`를 모두 갱신한다.
- 설정 변경은 Claude Code / Codex **재시작 후** 반영된다.

## 연결 확인

1. 게스트에서 서버 기동 후 호스트에서 TCP 확인:
   ```bash
   nc -z -G 3 172.16.217.129 8000   # succeeded 나오면 정상
   ```
   `8000 CLOSED`면 `--host 0.0.0.0` 누락 또는 방화벽 문제.
2. 브리지 단독 스모크 테스트 (게스트 서버가 떠 있어야 정상 응답, 아니면 transport error 반환):
   ```bash
   printf '%s\n' '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
     | /Users/endusdksla/study/rev/Malware/venv/bin/python3 \
       /Users/endusdksla/study/rev/Malware/mcp/mcp_http_bridge.py http://172.16.217.129:8000/mcp/
   ```
3. AI 프롬프트: "windbg MCP 연결 확인해줘. 세션 열고 현재 타겟/레지스터를 요약해줘."

## 트러블슈팅: `pip install mcp-windbg`가 cryptography 빌드 실패 (Windows ARM64)

증상: `pip install mcp-windbg` 시 **cryptography에서 "failed building wheel for install"** 에러.

원인 사슬: `mcp-windbg` → `mcp`(SDK 2.0.0) → **`pyjwt[crypto]`** → **cryptography**.
mcp SDK가 `pyjwt[crypto]`를 무조건 요구해 cryptography가 끌려온다. 그런데 **cryptography는
win_arm64 prebuilt 휠이 아예 없어서**(win32/win_amd64만 존재) ARM64 Python에선 소스 빌드로 떨어진다.
그 소스 빌드는 VS C++ 빌드툴만으론 안 되고 **Rust 툴체인 + 별도 OpenSSL(ARM64) + `OPENSSL_DIR`**
까지 필요해서 사실상 토끼굴이다. → **소스 빌드하지 말 것.**

인터넷 전제: 이 VM은 host-only면 pypi DNS가 안 됨(`getaddrinfo failed`). 네트워크를 shared
("private to my Mac")로 바꿔야 pip이 다운로드 가능.

### 해결 (권장): x64 Python으로 설치 → prebuilt 휠 사용
cryptography는 **win_amd64(x64) 휠은 존재**하고 Windows 11 ARM은 x64를 에뮬레이션으로 돌린다.
그래서 **x64 빌드 Python**으로 설치하면 cryptography가 휠로 그냥 설치됨(Rust/OpenSSL/빌드툴 전부 불필요).

1. python.org에서 **"Windows installer (64-bit)"** (= amd64, 파일명 `python-3.13.x-amd64.exe`) 설치.
   ARM 기기라 ARM64 인스톨러를 기본 추천할 수 있으니 목록에서 명시적으로 64-bit를 고를 것.
   기존 arm64 파이썬(`...\Python313-arm64\`)과 다른 폴더(`...\Python313\`)에 공존 설치됨.
   "Add to PATH"는 체크하지 말고 전체 경로로 쓰는 게 깔끔.
2. 아키텍처 확인 (핵심):
   ```powershell
   C:\Users\owo\AppData\Local\Programs\Python\Python313\python.exe -c "import platform;print(platform.machine())"
   ```
   → **`AMD64`** 나오면 정상. `ARM64`면 또 arm64 받은 것.
3. 그 x64 python으로 venv 만들어 설치 (shared 네트워크 상태에서). **PowerShell 기준** —
   cmd의 `%USERPROFILE%`가 아니라 `$env:USERPROFILE`를 쓴다:
   ```powershell
   C:\...\Python313\python.exe -m venv "$env:USERPROFILE\mcpwindbg-venv"

   # venv 활성화 (PowerShell): & 로 스크립트 경로를 실행
   & "$env:USERPROFILE\mcpwindbg-venv\Scripts\Activate.ps1"

   # 활성화되면 python/pip이 venv 것으로 잡힘
   pip install mcp-windbg
   pip install "mcp<2"      # ★ 필수 — 아래 "mcp SDK 2.0 호환성" 참고
   mcp-windbg --transport streamable-http --host 0.0.0.0 --port 8000
   ```
   활성화 없이 전체 경로로 직접 실행해도 됨:
   ```powershell
   & "$env:USERPROFILE\mcpwindbg-venv\Scripts\python.exe" -m pip install mcp-windbg
   & "$env:USERPROFILE\mcpwindbg-venv\Scripts\mcp-windbg.exe" --transport streamable-http --host 0.0.0.0 --port 8000
   ```

   **Activate.ps1 실행이 막히는 경우** (`... cannot be loaded because running scripts is disabled ...`):
   PowerShell 실행 정책을 CurrentUser 범위로 완화한 뒤 프롬프트에 `y` 입력:
   ```powershell
   Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
   # "Do you want to change the execution policy?" → Y 입력
   ```
   그 후 다시 `& "$env:USERPROFILE\mcpwindbg-venv\Scripts\Activate.ps1"`.

   cdb는 arch가 안 맞아도 됨 (mcp-windbg가 subprocess로 spawn만 하므로). 에뮬 x64 python이 ARM64 cdb 실행 OK.

### 대안 (비권장): cryptography 건너뛰기
`pip install --no-deps`로 mcp-windbg + 의존성을 수동 설치하며 `pyjwt[crypto]` 대신 순정 `pyjwt`만 넣으면
cryptography를 스킵 가능(인증 없는 로컬 http는 JWT 서명 코드를 안 탐). 단 transitive deps를 손으로 다
챙겨야 해서 깨지기 쉬움. x64 Python 방식이 더 안전.

## 트러블슈팅: `mcp-windbg` 실행 시 `ImportError: cannot import name 'McpError'`

증상: 설치는 됐는데 `mcp-windbg` 실행하면 즉시:
```
ImportError: cannot import name 'McpError' from 'mcp.shared.exceptions'. Did you mean: 'MCPError'?
```

원인: `pip install mcp-windbg`가 **mcp SDK 최신 2.0.0**을 끌어오는데, mcp-windbg 1.0.0은 구버전 API인
`McpError`를 임포트한다. mcp 2.0.0에서 `McpError` → `MCPError`로 **breaking rename**되면서 깨진 것.
즉 mcp-windbg 1.0.0은 아직 mcp 2.x 미대응이고, 원래 **mcp 1.x용**으로 만들어졌다.

해결 (venv 안에서):
```powershell
pip install "mcp<2"
```
- 꼼수 다운그레이드가 아니라 **원래 맞는 조합**으로 되돌리는 것. 전용 venv라 다른 것에 영향 없음
  (호스트 macOS의 MCP 도구들은 완전히 다른 파이썬 사용). 나머지 deps(pydantic/starlette/uvicorn/
  httpx/pyjwt/cryptography)는 mcp 1.x와 호환되며, pip이 2.x 전용 부속(mcp-types==2.0.0, httpx2)을
  1.x 세트로 정리해준다.
- **주의: 이 venv에서 `pip install -U mcp` 금지** — 다시 2.0으로 올라가 똑같이 깨진다. mcp 2.x는
  mcp-windbg가 2.x 대응 릴리스를 낼 때만.

참고 — 확인된 정상 조합: **x64 venv + cryptography(휠) + mcp<2**. cdb는 Store WinDbg 경로에 존재
(`C:\Program Files\WindowsApps\Microsoft.WinDbg_*_arm64__*\{amd64,arm64,x86}\cdb.exe`); PATH엔 없어도
mcp-windbg가 자동 탐지하거나 `--cdb-path`로 지정 가능.

## 주의
- **인증 없음**: HTTP 포트에 닿는 누구나 cdb.exe를 구동할 수 있음. 반드시 host-only VM 망/실습망에서만 사용.
- 포트 8000은 흔히 쓰여 게스트에서 점유 중일 수 있음. 충돌 시 `--port` 변경 후 mcp.json/config.toml URL도 같이 변경.
