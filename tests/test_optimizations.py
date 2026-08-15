"""针对本轮优化点的回归测试：解法清洗、超时分级、token 估算、预侦察解析、调度优先级。"""
import time

from agent.config import Config
from agent.recon import _parse_hosts
from agent.scheduler import _priority
from agent.tsec_api import Challenge
from agent.worker import Worker, _sanitize_step


def _mk_worker(**ch_fields):
    cfg = Config()
    w = Worker.__new__(Worker)
    w.cfg = cfg
    w.allow_extended = ch_fields.pop("allow_extended", False)
    w.first_attempt = ch_fields.pop("first_attempt", True)
    fields = {"unique_code": "a-01", "flag_count": 1,
              "total_score": 500, "difficulty": "easy"}
    fields.update(ch_fields)
    w.ch = Challenge.from_dict(fields)
    return w


# ---- 解法步骤清洗 ----

def test_sanitize_strips_old_cd_prefix():
    ws = "/app/runs/20260813-080000/a-14"
    step = "cd /Users/w/code/github/ithrael/bsrc-agent/runs/20260812-235128/a-14/work && curl -s http://10.0.0.1/"
    out = _sanitize_step(step, ws)
    assert out == "curl -s http://10.0.0.1/"


def test_sanitize_replaces_embedded_old_paths():
    ws = "/app/runs/20260813-080000/a-14"
    step = "cat /Users/w/code/github/ithrael/bsrc-agent/runs/20260812-235128/a-14/work/nmap.txt"
    out = _sanitize_step(step, ws)
    assert out == f"cat {ws}/nmap.txt"


def test_sanitize_keeps_relative_commands():
    out = _sanitize_step("curl -s http://10.0.0.1/login.php", "/some/ws")
    assert out == "curl -s http://10.0.0.1/login.php"


# ---- 超时分级 ----

def test_timeout_first_attempt_hard_fast_fail():
    """hard 首轮 20min 快速失败（P1，run 9054 复盘：40min 白耗，断点留 NOTES.md 进 retry 轮续跑）。"""
    w = _mk_worker(unique_code="b-02", flag_count=4, difficulty="hard")
    assert w._scaled_timeout_s() == 20 * 60


def test_timeout_retry_hard_40min():
    """retry 轮（first_attempt=False）hard 给足 40min 攻坚（run 9054 复盘 a-16 retry 轮解出）。"""
    w = _mk_worker(unique_code="b-02", flag_count=4, difficulty="hard", first_attempt=False)
    assert w._scaled_timeout_s() == 40 * 60


def test_timeout_easy_below_cap():
    w = _mk_worker(unique_code="a-01", flag_count=1, difficulty="easy")
    assert w._scaled_timeout_s() == 20 * 60


def test_completed_sol_timeout_cap_15min():
    """有完整解法的复现题：run() 把超时压到 15min（快速失败，把时间留给新题）。"""
    base = _mk_worker(unique_code="a-01", flag_count=1, difficulty="easy")._scaled_timeout_s()
    assert min(base, 15 * 60) == 15 * 60
    hard_base = _mk_worker(unique_code="b-01", flag_count=4, difficulty="hard")._scaled_timeout_s()
    assert min(hard_base, 15 * 60) == 15 * 60  # hard 复现题同样封顶


# ---- token 估算 ----

def test_est_tokens_counts_cjk_as_one_token_each():
    w = Worker.__new__(Worker)
    msg = {"role": "user", "content": "中文内容" * 1000}  # 4000 个 CJK 字符
    assert w._est_tokens(msg) >= 4000


def test_est_tokens_ascii_cheaper():
    w = Worker.__new__(Worker)
    msg = {"role": "user", "content": "ascii" * 1000}  # 5000 个 ascii 字符
    assert w._est_tokens(msg) < 4000


# ---- 预侦察 host 解析 ----

def test_parse_hosts_normalizes_addrs():
    assert _parse_hosts(["10.0.0.1:80", "10.0.0.2", "http://10.0.0.3:8080/x"]) == \
        ["10.0.0.1", "10.0.0.2", "10.0.0.3"]
    assert _parse_hosts(["10.0.0.1:80", "10.0.0.1:8080"]) == ["10.0.0.1"]


# ---- 调度优先级 ----

def _ch(code="a-01", score=500, difficulty="easy", flags=1):
    return Challenge.from_dict({
        "unique_code": code, "description": "", "difficulty": difficulty,
        "level": 1, "total_score": score, "flag_count": flags,
        "correct_flag_count": 0, "is_completed": False,
        "container_status": "stopped", "container_addr": [],
    })


def test_priority_known_completed_hard_is_boosted(monkeypatch):
    import agent.scheduler as sched
    monkeypatch.setattr(sched, "_LIB", {"b-01": {"completed": True}})
    hard = _ch("b-01", score=1200, difficulty="hard", flags=4)
    easy = _ch("a-02", score=500, difficulty="easy")
    # known hard: 1200/25*3 = 144 > easy: 500/4 = 125
    assert _priority(hard) < _priority(easy)  # 负值越小越优先


def test_priority_partial_boosted(monkeypatch):
    import agent.scheduler as sched
    monkeypatch.setattr(sched, "_LIB", {"b-02": {"partial": True}})
    partial = _ch("b-02", score=1200, difficulty="hard", flags=4)
    unknown_easy = _ch("a-02", score=500, difficulty="easy")
    # partial hard: 1200/25*2 = 96 < unknown easy: 125 —— 注意：easy 仍优先是合理的
    assert _priority(partial) < _priority(_ch("a-02", score=300, difficulty="easy"))
    assert _priority(partial) > _priority(unknown_easy)


def test_priority_round1_unknown_boosted(monkeypatch):
    """ROUND=1 覆盖优先：没碰过的题 ×5，压过 completed 复现题（解法留给第 2 轮收割）。"""
    import agent.scheduler as sched
    monkeypatch.setattr(sched, "_LIB", {"b-01": {"completed": True}})
    known = _ch("b-01", score=1200, difficulty="hard", flags=4)   # 1200/25*3 = 144
    unknown = _ch("a-02", score=500, difficulty="easy")           # 500/4*5 = 625
    assert _priority(unknown, round_num=1) < _priority(known, round_num=1)
    # ROUND=2 行为不变：completed 复现题仍优先
    assert _priority(known, round_num=2) < _priority(unknown, round_num=2)


def test_timeout_round1_short_cap():
    """ROUND=1 覆盖优先：无完整解法的题压到 20min（hard 首轮 20min 快速失败）；有解法的复现题不受影响。"""
    hard = _mk_worker(unique_code="b-02", flag_count=4, difficulty="hard")
    hard.cfg.round_num = 1
    assert hard._scaled_timeout_s(has_completed_sol=False) == 20 * 60
    easy = _mk_worker(unique_code="a-01", flag_count=1, difficulty="easy")
    easy.cfg.round_num = 1
    assert easy._scaled_timeout_s(has_completed_sol=False) == 20 * 60
    # 有完整解法：ROUND=1 不额外压（run() 里另有 15min 复现封顶）；hard 首轮仍 20min 封顶
    assert hard._scaled_timeout_s(has_completed_sol=True) == 20 * 60


def test_state_append_dedup(tmp_path):
    """STATE.md 追加去重：flag 进度/端口在输出里反复出现，只记一次。"""
    import threading
    w = Worker.__new__(Worker)
    w.state_path = str(tmp_path / "STATE.md")
    w._state_lock = threading.Lock()
    w._state_append("FACTS", "- flag 进度: 1/3")
    w._state_append("FACTS", "- flag 进度: 1/3")  # 重复：跳过
    w._state_append("FACTS", "- flag 进度: 2/3")
    content = open(w.state_path).read()
    assert content.count("- flag 进度: 1/3") == 1
    assert "- flag 进度: 2/3" in content
    assert "## FACTS" in content
