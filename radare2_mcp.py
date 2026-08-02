#!/usr/bin/env python3
"""
Radare2 MCP 클라이언트
호스트 macOS에서 실행되는 MCP 서버
게스트 Windows의 radare2 HTTP API로 연결
"""
import sys
import requests
from typing import Any
from mcp.server import FastMCP

# 게스트 IP와 포트
# RADARE2_URL = "http://192.168.41.131:9999/mcp"
# RADARE2_URL = "http://172.16.217.128:9999/mcp"
RADARE2_URL = "http://172.16.217.129:9999/mcp"

class Radare2MCP:
    def __init__(self):
        self.session = requests.Session()
        self.session.trust_env = False  # 프록시 무시

    def call_remote(self, method: str, **params) -> Any:
        """게스트의 radare2 HTTP 서버 호출"""
        payload = {
            'method': method,
            'params': params
        }

        try:
            resp = self.session.post(RADARE2_URL, json=payload, timeout=60)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            return {'error': str(e)}

    def analyze(self, binary_path: str) -> dict:
        """바이너리 분석 시작"""
        return self.call_remote('analyze', path=binary_path)

    def get_functions(self) -> list:
        """함수 목록"""
        return self.call_remote('get_functions')

    def get_strings(self) -> list:
        """문자열 목록"""
        return self.call_remote('get_strings')

    def disassemble(self, address: str = '0x400000', count: int = 10) -> dict:
        """역어셈블"""
        return self.call_remote('disassemble', address=address, count=count)

    def run_command(self, commands: str) -> dict:
        """로드된 바이너리에 대해 임의의 radare2 명령 실행 (세미콜론으로 연결)"""
        return self.call_remote('run_command', commands=commands)

    def run_shell(self, command: str, timeout: int = 120) -> dict:
        """VM에서 임의의 셸 명령 실행"""
        return self.call_remote('run_shell', command=command, timeout=timeout)

    def list_files(self, directory: str = "C:\\") -> dict:
        """디렉토리의 파일 목록"""
        return self.call_remote('list_files', directory=directory)

    def search_binaries(self, directory: str = "C:\\", pattern: str = "*.exe") -> dict:
        """바이너리 파일 검색"""
        return self.call_remote('search_binaries', directory=directory, pattern=pattern)

def build_server() -> FastMCP:
    """현재 설치된 mcp 패키지와 호환되는 FastMCP 서버를 구성한다."""
    mcp = Radare2MCP()
    server = FastMCP("radare2")

    @server.tool()
    def analyze(binary_path: str):
        return mcp.analyze(binary_path)

    @server.tool()
    def get_functions():
        return mcp.get_functions()

    @server.tool()
    def get_strings():
        return mcp.get_strings()

    @server.tool()
    def disassemble(address: str = '0x400000', count: int = 10):
        return mcp.disassemble(address, count)

    @server.tool()
    def run_command(commands: str):
        return mcp.run_command(commands)

    @server.tool()
    def run_shell(command: str, timeout: int = 120):
        return mcp.run_shell(command, timeout)

    @server.tool()
    def list_files(directory: str = "C:\\"):
        return mcp.list_files(directory)

    @server.tool()
    def search_binaries(directory: str = "C:\\", pattern: str = "*.exe"):
        return mcp.search_binaries(directory, pattern)

    return server


# MCP 서버 진입점
if __name__ == '__main__':
    if len(sys.argv) > 1 and sys.argv[1] == 'serve':
        build_server().run()
    else:
        # CLI 테스트 모드
        mcp = Radare2MCP()
        binary = sys.argv[1] if len(sys.argv) > 1 else '/path/to/binary'

        print(f"[*] Analyzing {binary}")
        print(mcp.analyze(binary))

        print("[*] Functions:")
        funcs = mcp.get_functions()
        if isinstance(funcs, list):
            for f in funcs[:5]:
                print(f"  {f}")
        else:
            print(funcs)
