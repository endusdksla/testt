#!/usr/bin/env python3
"""
Radare2 HTTP 서버
Windows VM에서 실행되는 radare2를 HTTP API로 노출
"""
import json
import subprocess
import sys
import os
import glob
from http.server import HTTPServer, BaseHTTPRequestHandler

class Radare2Handler(BaseHTTPRequestHandler):
    current_binary = None  # 클래스 변수: 모든 요청 인스턴스가 공유
    current_bits = 32      # 자동 감지된 아키텍처 비트 수

    def do_POST(self):
        if self.path == '/mcp':
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode()

            try:
                request = json.loads(body)
                method = request.get('method')
                params = request.get('params', {})

                result = self.handle_mcp(method, params)

                self.send_response(200)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(result).encode())
            except Exception as e:
                self.send_response(400)
                self.send_header('Content-type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps({'error': str(e)}).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def _detect_bits(self, binary_path):
        """rabin2로 바이너리 아키텍처 비트 수 자동 감지"""
        try:
            cmd = f'rabin2.exe -Ij "{binary_path}"'
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
            info = json.loads(result.stdout)
            bits = info.get('info', {}).get('bits', 32)
            return int(bits)
        except Exception:
            return 32  # 감지 실패 시 32비트 기본값

    def _r2_cmd(self, commands, binary_path=None, bits=None):
        """radare2 명령 실행 헬퍼"""
        path = binary_path or Radare2Handler.current_binary
        b = bits or Radare2Handler.current_bits
        cmd = f'radare2.exe -2 -q -e asm.bits={b} -c "{commands}" "{path}"'
        return subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)

    def handle_mcp(self, method, params):
        """MCP 메서드 처리"""
        if method == 'analyze':
            binary_path = params.get('path')
            bits = params.get('bits', 0)  # 0 = 자동 감지

            if bits == 0:
                bits = self._detect_bits(binary_path)

            Radare2Handler.current_binary = binary_path
            Radare2Handler.current_bits = bits
            return {'status': f'Analyzing {binary_path}', 'bits': bits}

        elif method == 'get_functions':
            if not Radare2Handler.current_binary:
                return {'error': 'No binary loaded'}
            result = self._r2_cmd('aaa; aflj')
            try:
                return json.loads(result.stdout) if result.stdout.strip() else []
            except json.JSONDecodeError:
                return {'error': result.stderr or 'parse failed', 'raw': result.stdout[:500]}

        elif method == 'get_strings':
            if not Radare2Handler.current_binary:
                return {'error': 'No binary loaded'}
            # rabin2가 더 안정적 (radare2 izj는 64bit DLL에서 crash 가능)
            try:
                cmd = f'rabin2.exe -zzj "{Radare2Handler.current_binary}"'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=60)
                stdout = result.stdout or ''
                if stdout.strip():
                    data = json.loads(stdout)
                    return data.get('strings', data) if isinstance(data, dict) else data
                return []
            except json.JSONDecodeError:
                return {'error': 'parse failed', 'raw': (result.stdout or '')[:500]}
            except Exception as e:
                return {'error': str(e)}

        elif method == 'disassemble':
            if not Radare2Handler.current_binary:
                return {'error': 'No binary loaded'}
            address = params.get('address', '0x400000')
            count = params.get('count', 10)
            result = self._r2_cmd(f'aaa; pd {count} @ {address}')
            return {'disassembly': result.stdout, 'bits': Radare2Handler.current_bits, 'stderr': result.stderr}

        elif method == 'get_info':
            if not Radare2Handler.current_binary:
                return {'error': 'No binary loaded'}
            try:
                cmd = f'rabin2.exe -Ij "{Radare2Handler.current_binary}"'
                result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=30)
                info = json.loads(result.stdout)
                return {'info': info, 'bits': Radare2Handler.current_bits}
            except Exception as e:
                return {'error': str(e)}

        elif method == 'list_files':
            directory = params.get('directory', 'C:\\')
            try:
                files = []
                for item in os.listdir(directory):
                    path = os.path.join(directory, item)
                    is_dir = os.path.isdir(path)
                    files.append({'name': item, 'path': path, 'is_dir': is_dir})
                return {'files': files, 'directory': directory}
            except Exception as e:
                return {'error': str(e)}

        elif method == 'read_file':
            path = params.get('path')
            encoding = params.get('encoding', 'utf-8')
            try:
                with open(path, 'r', encoding=encoding, errors='replace') as f:
                    content = f.read()
                return {'content': content, 'path': path}
            except Exception as e:
                return {'error': str(e)}

        elif method == 'search_binaries':
            directory = params.get('directory', 'C:\\')
            pattern = params.get('pattern', '*.exe')
            try:
                search_path = os.path.join(directory, '**', pattern)
                results = []
                for filepath in glob.glob(search_path, recursive=True):
                    results.append({'path': filepath, 'name': os.path.basename(filepath)})
                return {'binaries': results}
            except Exception as e:
                return {'error': str(e)}

        else:
            return {'error': f'Unknown method: {method}'}

    def log_message(self, format, *args):
        pass  # 로그 억제

if __name__ == '__main__':
    server = HTTPServer(('0.0.0.0', 9999), Radare2Handler)
    print('[*] Radare2 HTTP Server listening on 0.0.0.0:9999')
    server.serve_forever()
