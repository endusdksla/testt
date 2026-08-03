#!/usr/bin/env python3
"""
x64dbg MCP 클라이언트
호스트 macOS에서 실행되는 MCP 서버.
게스트 Windows의 x64dbg HTTP Server 플러그인(MCPx64dbg.dp64/.dp32)으로 연결한다.

구조:
  Claude/Codex --stdio--> x64dbg.py --HTTP:8888--> x64dbg + MCPx64dbg 플러그인

플러그인 API는 GET 기반 REST 형식이다:
  경로   = 명령          (예: /GetModuleList, /Register/Get)
  쿼리   = 파라미터      (예: ?addr=0x...&size=64)
  응답   = JSON 또는 text/plain

패치 포인트: requests.Session.trust_env = False 로 시스템 프록시를 무시한다.
(프록시를 타면 게스트 접속이 실패할 수 있음)

사용법:
  # MCP 서버로 실행 (mcp.json에서 이 형태로 호출)
  python x64dbg.py serve --x64dbg-url http://172.16.217.129:8888

  # CLI 테스트
  python x64dbg.py IsDebugging      --x64dbg-url http://172.16.217.129:8888
  python x64dbg.py GetModuleList    --x64dbg-url http://172.16.217.129:8888
  python x64dbg.py ExecCommand --command "init" --x64dbg-url http://172.16.217.129:8888
"""
import sys
import json
import requests
from typing import Any

# 게스트 IP:포트 (CLAUDE.md 기준 현재 VM). --x64dbg-url 로 덮어쓸 수 있음.
DEFAULT_URL = "http://172.16.217.129:8888"

# 친숙한 명령 이름 -> 플러그인 엔드포인트 경로.
# (플러그인 바이너리 MCPx64dbg.dp64 문자열에서 추출)
ENDPOINTS = {
    # --- 상태 ---
    "IsDebugging":            "/Is_Debugging",
    "IsDebugActive":          "/IsDebugActive",
    "ExecCommand":            "/ExecCommand",          # ?command=
    # --- 레지스터 / 플래그 ---
    "GetRegisterDump":        "/RegisterDump",
    "RegisterGet":            "/Register/Get",         # ?register=
    "RegisterSet":            "/Register/Set",         # ?register=&value=
    "FlagGet":                "/Flag/Get",             # ?flag=
    "FlagSet":                "/Flag/Set",             # ?flag=&value=
    # --- 메모리 ---
    "MemoryRead":             "/Memory/Read",          # ?addr=&size=
    "MemoryWrite":            "/Memory/Write",         # ?addr=&data=
    "MemoryIsValidPtr":       "/Memory/IsValidPtr",    # ?addr=
    "MemoryGetProtect":       "/Memory/GetProtect",    # ?addr=
    "MemoryMap":              "/MemoryMap",
    "MemoryBase":             "/MemoryBase",           # ?addr=
    "MemoryRemoteAlloc":      "/Memory/RemoteAlloc",   # ?size=
    "MemoryRemoteFree":       "/Memory/RemoteFree",    # ?addr=
    # --- 실행 제어 ---
    "Run":                    "/Debug/Run",
    "Pause":                  "/Debug/Pause",
    "Stop":                   "/Debug/Stop",
    "StepIn":                 "/Debug/StepIn",
    "StepOver":               "/Debug/StepOver",
    "StepOut":                "/Debug/StepOut",
    # --- 브레이크포인트 ---
    "SetBreakpoint":          "/Debug/SetBreakpoint",           # ?addr=
    "DeleteBreakpoint":       "/Debug/DeleteBreakpoint",        # ?addr=
    "SetHardwareBreakpoint":  "/Debug/SetHardwareBreakpoint",   # ?addr=&type=
    "DeleteHardwareBreakpoint": "/Debug/DeleteHardwareBreakpoint",  # ?addr=
    "BreakpointList":         "/Breakpoint/List",
    # --- 디스어셈블 / 어셈블 ---
    "GetInstruction":         "/Disasm/GetInstruction",         # ?addr=
    "GetInstructionRange":    "/Disasm/GetInstructionRange",    # ?addr=&count=
    "Assemble":               "/Assembler/Assemble",            # ?addr=&instruction=
    "AssembleMem":            "/Assembler/AssembleMem",         # ?addr=&instruction=
    # --- 스택 ---
    "StackPush":              "/Stack/Push",           # ?value=
    "StackPop":               "/Stack/Pop",
    "StackPeek":              "/Stack/Peek",           # ?offset=
    # --- 모듈 / 심볼 / 스레드 ---
    "GetModuleList":          "/GetModuleList",
    "SymbolEnum":             "/SymbolEnum",           # ?module=&offset=&limit=
    "GetThreadList":          "/GetThreadList",
    "GetTebAddress":          "/GetTebAddress",        # ?tid=
    "GetCallStack":           "/GetCallStack",
    # --- 분석 보조 ---
    "ParseExpression":        "/Misc/ParseExpression", # ?expression=
    "RemoteGetProcAddress":   "/Misc/RemoteGetProcAddress",  # ?module=&api=
    "FindPattern":            "/Pattern/FindMem",      # ?start=&size=&pattern=
    "StringGetAt":            "/String/GetAt",         # ?addr=
    "XrefGet":                "/Xref/Get",             # ?addr=
    "XrefCount":              "/Xref/Count",           # ?addr=
    "GetBranchDestination":   "/GetBranchDestination", # ?addr=
    "LabelSet":               "/Label/Set",            # ?addr=&text=
    "LabelGet":               "/Label/Get",            # ?addr=
    "LabelList":              "/Label/List",
    "CommentSet":             "/Comment/Set",          # ?addr=&text=
    "CommentGet":             "/Comment/Get",          # ?addr=
    "EnumTcpConnections":     "/EnumTcpConnections",
}


class X64dbgMCP:
    def __init__(self, base_url: str = DEFAULT_URL):
        self.base_url = base_url.rstrip("/")
        self.session = requests.Session()
        self.session.trust_env = False  # 시스템 프록시 무시 (패치)

    def call(self, endpoint: str, **params) -> Any:
        """플러그인 HTTP API 호출. endpoint 는 '/GetModuleList' 형태의 경로."""
        # None 값 파라미터는 제거
        params = {k: v for k, v in params.items() if v is not None}
        url = self.base_url + endpoint
        try:
            resp = self.session.get(url, params=params, timeout=60)
            resp.raise_for_status()
        except requests.RequestException as e:
            return {"error": str(e)}
        text = resp.text
        try:
            return json.loads(text)
        except ValueError:
            return text

    def call_named(self, name: str, **params) -> Any:
        """친숙한 명령 이름(ENDPOINTS 키)으로 호출."""
        ep = ENDPOINTS.get(name)
        if ep is None:
            return {"error": f"Unknown command '{name}'. See ENDPOINTS."}
        return self.call(ep, **params)

    # --- 자주 쓰는 편의 메서드 ---
    def is_debugging(self):                    return self.call("/Is_Debugging")
    def is_debug_active(self):                 return self.call("/IsDebugActive")
    def exec_command(self, command: str):      return self.call("/ExecCommand", command=command)
    def get_register_dump(self):               return self.call("/RegisterDump")
    def get_register(self, register: str):     return self.call("/Register/Get", register=register)
    def set_register(self, register: str, value: str):
        return self.call("/Register/Set", register=register, value=value)
    def read_memory(self, addr: str, size: int = 64):
        return self.call("/Memory/Read", addr=addr, size=size)
    def write_memory(self, addr: str, data: str):
        return self.call("/Memory/Write", addr=addr, data=data)
    def memory_map(self):                      return self.call("/MemoryMap")
    def get_module_list(self):                 return self.call("/GetModuleList")
    def get_thread_list(self):                 return self.call("/GetThreadList")
    def get_call_stack(self):                  return self.call("/GetCallStack")
    def get_instruction(self, addr: str):      return self.call("/Disasm/GetInstruction", addr=addr)
    def get_instruction_range(self, addr: str, count: int = 10):
        return self.call("/Disasm/GetInstructionRange", addr=addr, count=count)
    def set_breakpoint(self, addr: str):       return self.call("/Debug/SetBreakpoint", addr=addr)
    def delete_breakpoint(self, addr: str):    return self.call("/Debug/DeleteBreakpoint", addr=addr)
    def breakpoint_list(self):                 return self.call("/Breakpoint/List")
    def run(self):                             return self.call("/Debug/Run")
    def pause(self):                           return self.call("/Debug/Pause")
    def stop(self):                            return self.call("/Debug/Stop")
    def step_in(self):                         return self.call("/Debug/StepIn")
    def step_over(self):                       return self.call("/Debug/StepOver")
    def step_out(self):                        return self.call("/Debug/StepOut")
    def parse_expression(self, expression: str):
        return self.call("/Misc/ParseExpression", expression=expression)
    def find_pattern(self, start: str, size: int, pattern: str):
        return self.call("/Pattern/FindMem", start=start, size=size, pattern=pattern)
    def memory_base(self, addr: str):          return self.call("/MemoryBase", addr=addr)
    def symbol_enum(self, module: str, offset: int = 0, limit: int = 100):
        return self.call("/SymbolEnum", module=module, offset=offset, limit=limit)
    def assemble(self, addr: str, instruction: str):
        return self.call("/Assembler/Assemble", addr=addr, instruction=instruction)
    def enum_tcp_connections(self):            return self.call("/EnumTcpConnections")


def build_server(base_url: str):
    """현재 설치된 mcp 패키지와 호환되는 FastMCP 서버를 구성한다."""
    from mcp.server import FastMCP

    dbg = X64dbgMCP(base_url)
    server = FastMCP("x64dbg")

    @server.tool()
    def is_debugging():
        """디버깅 세션이 열려 있는지 여부."""
        return dbg.is_debugging()

    @server.tool()
    def is_debug_active():
        """디버기가 활성(실행/일시정지) 상태인지 여부."""
        return dbg.is_debug_active()

    @server.tool()
    def exec_command(command: str):
        """x64dbg command bar에 임의 명령을 실행한다 (예: 'init', 'bp GetProcAddress')."""
        return dbg.exec_command(command)

    @server.tool()
    def get_register_dump():
        """전체 레지스터 덤프 (RIP/RSP/RAX 등)."""
        return dbg.get_register_dump()

    @server.tool()
    def get_register(register: str):
        """단일 레지스터 값 조회 (예: 'rip', 'rax')."""
        return dbg.get_register(register)

    @server.tool()
    def set_register(register: str, value: str):
        """레지스터 값 설정."""
        return dbg.set_register(register, value)

    @server.tool()
    def read_memory(addr: str, size: int = 64):
        """지정 주소에서 size 바이트 읽기 (16진 문자열 반환)."""
        return dbg.read_memory(addr, size)

    @server.tool()
    def write_memory(addr: str, data: str):
        """지정 주소에 16진 데이터 쓰기."""
        return dbg.write_memory(addr, data)

    @server.tool()
    def memory_map():
        """프로세스 메모리 맵 (페이지/보호속성)."""
        return dbg.memory_map()

    @server.tool()
    def get_module_list():
        """로드된 모듈 목록 (base/size/section)."""
        return dbg.get_module_list()

    @server.tool()
    def get_thread_list():
        """스레드 목록."""
        return dbg.get_thread_list()

    @server.tool()
    def get_call_stack():
        """현재 콜 스택."""
        return dbg.get_call_stack()

    @server.tool()
    def get_instruction(addr: str):
        """지정 주소의 단일 디스어셈블 명령."""
        return dbg.get_instruction(addr)

    @server.tool()
    def get_instruction_range(addr: str, count: int = 10):
        """지정 주소부터 count개 명령 디스어셈블 (1~100)."""
        return dbg.get_instruction_range(addr, count)

    @server.tool()
    def set_breakpoint(addr: str):
        """소프트웨어 브레이크포인트 설정."""
        return dbg.set_breakpoint(addr)

    @server.tool()
    def delete_breakpoint(addr: str):
        """브레이크포인트 제거."""
        return dbg.delete_breakpoint(addr)

    @server.tool()
    def breakpoint_list():
        """설정된 브레이크포인트 목록."""
        return dbg.breakpoint_list()

    @server.tool()
    def run():
        """디버기 실행(계속)."""
        return dbg.run()

    @server.tool()
    def pause():
        """디버기 일시정지."""
        return dbg.pause()

    @server.tool()
    def stop():
        """디버깅 종료."""
        return dbg.stop()

    @server.tool()
    def step_in():
        return dbg.step_in()

    @server.tool()
    def step_over():
        return dbg.step_over()

    @server.tool()
    def step_out():
        return dbg.step_out()

    @server.tool()
    def parse_expression(expression: str):
        """x64dbg 표현식 평가 (예: 'kernel32.GetProcAddress')."""
        return dbg.parse_expression(expression)

    @server.tool()
    def find_pattern(start: str, size: int, pattern: str):
        """메모리에서 바이트 패턴 검색 (예: pattern='48 8B ?? ??')."""
        return dbg.find_pattern(start, size, pattern)

    @server.tool()
    def memory_base(addr: str):
        """주소가 속한 모듈/할당의 베이스 주소."""
        return dbg.memory_base(addr)

    @server.tool()
    def symbol_enum(module: str, offset: int = 0, limit: int = 100):
        """모듈의 심볼(import/export) 열거."""
        return dbg.symbol_enum(module, offset, limit)

    @server.tool()
    def assemble(addr: str, instruction: str):
        """지정 주소에 명령 어셈블."""
        return dbg.assemble(addr, instruction)

    @server.tool()
    def enum_tcp_connections():
        """디버기의 TCP 연결 열거."""
        return dbg.enum_tcp_connections()

    return server


def parse_args(argv):
    """--x64dbg-url 를 뽑아내고, 나머지에서 명령/파라미터를 분리한다."""
    url = DEFAULT_URL
    positional = []
    params = {}
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--x64dbg-url":
            url = argv[i + 1]
            i += 2
        elif a.startswith("--x64dbg-url="):
            url = a.split("=", 1)[1]
            i += 1
        elif a.startswith("--"):
            key = a[2:]
            val = argv[i + 1] if i + 1 < len(argv) else ""
            params[key] = val
            i += 2
        else:
            positional.append(a)
            i += 1
    return url, positional, params


if __name__ == "__main__":
    url, positional, params = parse_args(sys.argv[1:])

    if positional and positional[0] == "serve":
        # MCP 서버 모드 (mcp.json 에서 호출)
        build_server(url).run()
    elif positional:
        # CLI 테스트 모드:  x64dbg.py <Command> [--key value ...]
        dbg = X64dbgMCP(url)
        result = dbg.call_named(positional[0], **params)
        print(json.dumps(result, indent=2, ensure_ascii=False)
              if isinstance(result, (dict, list)) else result)
    else:
        print(__doc__)
        print("사용 가능한 명령:")
        for name in sorted(ENDPOINTS):
            print(f"  {name:26s} -> {ENDPOINTS[name]}")
