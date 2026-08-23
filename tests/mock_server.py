"""本地 mock 平台：按 api-doc.txt 实现 5 个接口，供单元测试与本地联调。

python -m tests.mock_server [port]
"""
from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

TOKEN = "mock-token"


def fresh_challenges() -> dict:
    """每次调用返回独立副本，避免测试间状态串扰。"""
    return {
        "mock_web_01": {
            "unique_code": "mock_web_01",
            "description": "mock：直接访问 /flag 即得",
            "difficulty": "easy",
            "level": 1,
            "total_score": 100,
            "flag_count": 1,
            "correct_flag_count": 0,
            "is_completed": False,
            "container_status": "stopped",
            "container_addr": [],
            "_flags": ["flag{mock_flag_01}"],
        },
        "mock_bin_01": {
            "unique_code": "mock_bin_01",
            "description": "mock：两 flag 题",
            "difficulty": "hard",
            "level": 1,
            "total_score": 500,
            "flag_count": 2,
            "correct_flag_count": 0,
            "is_completed": False,
            "container_status": "stopped",
            "container_addr": [],
            "_flags": ["flag{mock_flag_2a}", "flag{mock_flag_2b}"],
        },
    }


class Handler(BaseHTTPRequestHandler):
    def _auth(self) -> bool:
        return self.headers.get("BENCHMARK_TOKEN") == TOKEN

    def _send(self, code: int, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _err(self, status: int, code: str, msg: str):
        self._send(status, {"code": code, "message": msg, "detail": {}})

    def log_message(self, *a):  # 静音
        pass

    def do_GET(self):
        if not self._auth():
            return self._err(404, "task_not_found", "bad token")
        u = urlparse(self.path)
        if u.path == "/openapi/v1/challenges":
            out = [{k: v for k, v in c.items() if not k.startswith("_")} for c in self.server.state.values()]
            return self._send(200, out)
        if u.path == "/openapi/v1/challenges/hint":
            code = parse_qs(u.query).get("unique_code", [""])[0]
            c = self.server.state.get(code)
            if not c:
                return self._err(404, "challenge_not_found", code)
            if c["is_completed"]:
                return self._err(409, "invalid_state", "completed")
            return self._send(200, {"unique_code": code, "hint": "试试 /flag"})
        return self._err(404, "not_found", u.path)

    def do_POST(self):
        if not self._auth():
            return self._err(404, "task_not_found", "bad token")
        u = urlparse(self.path)
        if u.path == "/openapi/v1/challenges/start":
            code = parse_qs(u.query).get("unique_code", [""])[0]
            c = self.server.state.get(code)
            if not c:
                return self._err(404, "challenge_not_found", code)
            with self.server._lock:
                self.server.start_calls += 1
                if self.server.instance_limit:
                    active = sum(1 for x in self.server.state.values()
                                 if x["container_status"] == "available")
                    if active >= self.server.instance_limit:
                        return self._err(409, "invalid_state",
                                         "当前活跃的题目实例数已达到上限，需先关闭已有题目再启动新题目")
                c["container_status"] = "available"
                c["container_addr"] = ["127.0.0.1:31337"]
                return self._send(200, {"unique_code": code, "container_addr": c["container_addr"]})
        if u.path == "/openapi/v1/challenges/close":
            code = parse_qs(u.query).get("unique_code", [""])[0]
            c = self.server.state.get(code)
            if not c:
                return self._err(404, "challenge_not_found", code)
            c["container_status"] = "stopped"
            c["container_addr"] = []
            return self._send(200, {"unique_code": code, "closed": True})
        if u.path == "/openapi/v1/challenges/submit":
            length = int(self.headers.get("Content-Length", 0))
            body = json.loads(self.rfile.read(length) or b"{}")
            code = body.get("unique_code", "")
            flag = body.get("flag", "")
            c = self.server.state.get(code)
            if not c:
                return self._err(404, "challenge_not_found", code)
            if not (1 <= len(flag) <= 4096):
                return self._err(422, "validation", "flag length")
            with self.server._lock:  # 双 worker 并发提交相同 flag：幂等判定必须原子
                if flag in c["_flags"]:
                    idx = c["_flags"].index(flag)
                    already_key = f"_got_{idx}"
                    if c.get(already_key):
                        return self._err(409, "duplicate", "already submitted")
                    c[already_key] = True
                    c["correct_flag_count"] += 1
                    awarded = c["total_score"] // c["flag_count"]
                    if c["correct_flag_count"] >= c["flag_count"]:
                        c["is_completed"] = True
                    return self._send(200, {
                        "correct": True, "awarded": awarded,
                        "cumulative_score": awarded * c["correct_flag_count"],
                        "correct_flag_count": c["correct_flag_count"],
                        "total_flag_count": c["flag_count"],
                        "matched_flag_index": idx,
                    })
            return self._send(200, {
                "correct": False, "awarded": 0,
                "cumulative_score": 0,
                "correct_flag_count": c["correct_flag_count"],
                "total_flag_count": c["flag_count"],
                "matched_flag_index": None,
            })
        return self._err(404, "not_found", u.path)


def make_server(port: int = 0, instance_limit: int = 0) -> ThreadingHTTPServer:
    """instance_limit>0 时模拟平台"同时最多 N 个活跃实例"限制（start 超限返回 409）。"""
    srv = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    srv.state = fresh_challenges()
    srv.instance_limit = instance_limit
    srv.start_calls = 0  # start 接口调用计数（测试断言"无疯狂轮询"用）
    srv._lock = threading.Lock()
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


if __name__ == "__main__":
    import sys
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8899
    srv = make_server(port)
    print(f"mock platform on 127.0.0.1:{port}, token={TOKEN}")
    threading.Event().wait()
