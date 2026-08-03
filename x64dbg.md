우리는 x64dbg MCP를 호스트 PC의 AI(Codex 또는 Claude)에서 게스트 PC의 x64dbg에 연결해서 쓰려고 한다. 목표는 게스트에서 실행 중인 x64dbg 플러그인이 HTTP 서버를 열고, 호스트의 MCP Python 서버가 그 HTTP 서버로 붙는 구조다.

이미 수정/빌드된 패치 파일을 사용한다.

공유 파일:
1. MCP_Plugins-hostguest-patched.zip
   - 안에 MCPx64dbg.dp32, MCPx64dbg.dp64가 들어있다.
2. x64dbgMCP-build1.1-hostguest-patched-clean.zip
   - 수정된 소스와 x64dbg.py가 들어있다.

중요한 구조:
- 게스트 PC: x64dbg 플러그인(.dp32/.dp64)을 설치한다.
- 호스트 PC: x64dbg.py를 MCP 서버로 실행한다.
- 호스트 MCP 서버는 http://GUEST_IP:8888 로 게스트 x64dbg 플러그인에 연결한다.

게스트 PC 설정 절차:
1. MCP_Plugins-hostguest-patched.zip 압축을 푼다.
2. 64비트 x64dbg용 플러그인 설치:
   MCPx64dbg.dp64 파일을 아래 폴더에 복사한다.
   x64dbg\release\x64\plugins\
3. 32비트 x32dbg용 플러그인 설치:
   MCPx64dbg.dp32 파일을 아래 폴더에 복사한다.
   x64dbg\release\x32\plugins\
4. 분석 대상이 64비트면 x64dbg.exe, 32비트면 x32dbg.exe를 실행한다.
5. x64dbg 로그 창(Alt+L)에서 플러그인 로드 로그를 확인한다.
   예: x64dbg HTTP Server plugin loaded
6. x64dbg command bar에서 외부 접속을 허용한다.
   httpbind 0.0.0.0
   *** 중요 ***: 이걸 안 하면 플러그인은 기본적으로 127.0.0.1:8888(로컬호스트 전용)에만
   바인딩된다. 이 경우 방화벽을 아무리 열어도 호스트에서 접속 불가다(소켓이 루프백만 받음).
   게스트에서 `netstat -ano | findstr :8888` 로 확인 시:
     127.0.0.1:8888 LISTENING  -> 잘못됨(외부 접속 안 됨). httpbind 0.0.0.0 필요.
     0.0.0.0:8888   LISTENING  -> 정상.
   httpbind은 저장되지 않아서 x64dbg 재시작 때마다 다시 127.0.0.1로 돌아간다.
   매번 입력하기 싫으면 아래 "영구 바인딩" 항목 참고(환경변수 X64DBG_BIND_ADDRESS).
7. 포트가 8888이 아니거나 명시하고 싶으면:
   httpport 8888

영구 바인딩(권장) — httpbind을 매번 안 치려면:
- 플러그인은 로드 시 환경변수 X64DBG_BIND_ADDRESS를 읽어 바인드 주소를 정한다.
- 게스트에서 한 번만 설정(관리자 아니어도 됨):
    setx X64DBG_BIND_ADDRESS 0.0.0.0
- setx는 "새로 뜨는 프로세스"에만 적용되므로, 이미 실행 중인 x64dbg는
  이번만 httpbind 0.0.0.0을 치거나 x64dbg를 완전히 재시작해야 한다.
- 재시작해도 여전히 127.0.0.1이면 explorer가 옛 환경블록을 캐싱한 것 —
  로그오프->로그인(또는 재부팅) 한 번이면 확실히 반영된다.
- (이 저장소 VM 172.16.217.129에는 이미 setx로 설정 완료된 상태.)
8. 게스트 Windows 방화벽에서 inbound TCP 8888을 허용한다.
   관리자 PowerShell:
   New-NetFirewallRule -DisplayName "x64dbg MCP TCP 8888" -Direction Inbound -Protocol TCP -LocalPort 8888 -Action Allow
9. 게스트 IP를 확인한다.
   ipconfig
   예: 192.168.233.128

호스트 PC 연결 테스트:

** 이 저장소의 실제 호스트는 macOS + Claude Code다 (아래 Windows/Codex 예시는 참고용). **
현재 VM IP는 172.16.217.129 (변동 가능 — 안 되면 게스트에서 ipconfig로 재확인).

[macOS 호스트 — 실제 사용]
1. TCP 연결 확인 (Windows의 Test-NetConnection 대신 nc):
     nc -z -G 3 172.16.217.129 8888   # succeeded! 나오면 정상
   참고: ping은 Windows가 ICMP를 막아 실패하는 게 정상. TCP 확인만 신뢰할 것.
   같은 VM의 다른 포트(예: radare2 9999)가 열려있는데 8888만 CLOSED면
   네트워크/방화벽 문제가 아니라 x64dbg 바인딩(127.0.0.1) 문제다. 위 6번 참고.
2. Python/의존성: 이 저장소 venv에 이미 requests + mcp 설치됨. 별도 설치 불필요.
     source /Users/endusdksla/study/rev/Malware/venv/bin/activate
3. x64dbg.py: 이미 생성되어 있음 (radare2_mcp.py 스타일, trust_env=False 패치 포함).
     /Users/endusdksla/study/rev/Malware/mcp/x64dbg.py
   원본 zip(src\x64dbg.py)이 시스템에 없어서, 플러그인 바이너리 MCPx64dbg.dp64에서
   HTTP API(56개 엔드포인트)를 리버싱해 직접 작성했다. GET 기반 REST 형식:
   경로=명령, 쿼리=파라미터. 친숙명 IsDebugging의 실제 경로는 /Is_Debugging(언더스코어).
4. CLI로 테스트 (venv python 사용):
     venv/bin/python3 mcp/x64dbg.py IsDebugging   --x64dbg-url http://172.16.217.129:8888
     venv/bin/python3 mcp/x64dbg.py GetModuleList --x64dbg-url http://172.16.217.129:8888
     venv/bin/python3 mcp/x64dbg.py ExecCommand --command "init" --x64dbg-url http://172.16.217.129:8888
   인자 없이 실행하면 사용 가능한 명령 목록이 출력된다.

[Windows 호스트 — 원본 참고용]
1. 호스트 PowerShell에서 TCP 연결 확인:
   Test-NetConnection -ComputerName GUEST_IP -Port 8888
   TcpTestSucceeded가 True면 네트워크/방화벽은 정상이다.
2. Python 의존성 설치:
   pip install mcp requests
3. x64dbg.py 경로를 준비한다.
   x64dbgMCP-build1.1-hostguest-patched-clean.zip 안의 src\x64dbg.py를 사용한다.
4. CLI로 테스트:
   python "C:\Path\To\x64dbg.py" GetModuleList --x64dbg-url "http://GUEST_IP:8888"
   또는:
   python "C:\Path\To\x64dbg.py" IsDebugging --x64dbg-url "http://GUEST_IP:8888"

Codex MCP 설정:
C:\Users\<USER>\.codex\config.toml 에 아래를 추가한다.

[mcp_servers.x64dbg]
command = 'C:\Path\To\Python\python.exe'
args = ['C:\Path\To\x64dbg.py', 'serve', '--x64dbg-url', 'http://GUEST_IP:8888']
startup_timeout_sec = 10
tool_timeout_sec = 60

예시:

[mcp_servers.x64dbg]
command = 'C:\Users\user\AppData\Local\Programs\Python\Python313\python.exe'
args = ['F:\codex-malware\x64dbgMCP-build1.1\src\x64dbg.py', 'serve', '--x64dbg-url', 'http://192.168.233.128:8888']
startup_timeout_sec = 10
tool_timeout_sec = 60

설정 후 Codex 앱/세션을 재시작한다.

Claude Desktop MCP 설정:
claude_desktop_config.json 의 mcpServers에 아래를 추가한다.

{
  "mcpServers": {
    "x64dbg": {
      "command": "C:\\Path\\To\\Python\\python.exe",
      "args": [
        "C:\\Path\\To\\x64dbg.py",
        "serve",
        "--x64dbg-url",
        "http://GUEST_IP:8888"
      ]
    }
  }
}

이미 다른 MCP 서버가 있으면 mcpServers 안에 x64dbg 항목만 추가한다.

Claude Code (macOS) MCP 설정 — 이 저장소의 실제 방식:
~/.claude/mcp.json 의 mcpServers에 아래를 추가한다 (radare2/jadx와 동일한 stdio 패턴).

  "x64dbg": {
    "command": "/Users/endusdksla/study/rev/Malware/venv/bin/python3",
    "args": [
      "/Users/endusdksla/study/rev/Malware/mcp/x64dbg.py",
      "serve",
      "--x64dbg-url", "http://172.16.217.129:8888"
    ],
    "timeout": 60
  }

- VM IP가 바뀌면 --x64dbg-url 값을 갱신한다.
- mcp.json 변경은 Claude Code 재시작 후에만 반영된다.

연결 확인용 AI 프롬프트:
"x64dbg MCP 연결을 확인해줘. IsDebugging, IsDebugActive, GetModuleList, GetRegisterDump를 호출해서 현재 디버깅 대상과 레지스터 상태를 요약해줘."

정상 연결 시 기대 결과:
- IsDebugging: true
- GetModuleList에서 현재 분석 대상 exe와 kernel32.dll, ntdll.dll 등이 보임
- GetRegisterDump에서 RIP/RSP/RAX 등 레지스터 값이 반환됨

주의:
- httpbind 0.0.0.0은 외부에서 x64dbg HTTP API에 접근 가능하게 만든다.
- 이 API는 ExecCommand 같은 디버거 명령 실행도 가능하므로 반드시 신뢰된 host-only VM 네트워크나 실습망에서만 사용한다.
- 가능하면 방화벽에서 호스트 IP만 TCP 8888 접근 허용하도록 제한한다.
- 요청이 프록시를 타면 실패할 수 있다. 우리가 패치한 x64dbg.py는 requests Session의 trust_env=False를 사용해서 시스템 프록시를 무시하도록 수정되어 있다. 반드시 패치된 x64dbg.py를 사용한다.