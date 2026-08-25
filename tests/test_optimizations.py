"""针对本轮优化点的回归测试：解法清洗、超时分级、token 估算、预侦察解析、调度优先级。"""
import os
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
    w.attempt = ch_fields.pop("attempt", 0)
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
    """hard 首轮 25min；多 flag 大题 45min（12641 复盘：25min 浅拿即轮转，
    b 系列剩面插队攻坚 1.5h 零产出；12464 一次性窗口 +2550）。"""
    w = _mk_worker(unique_code="b-02", flag_count=4, difficulty="hard", attempt=0)
    assert w._scaled_timeout_s() == 45 * 60
    single = _mk_worker(unique_code="c-02", flag_count=1, difficulty="hard", attempt=0)
    assert single._scaled_timeout_s() == 25 * 60


def _give_progress(w):
    """给 worker 一个带 RELAY 内容的临时工作区（模拟有断点）。"""
    import tempfile
    d = tempfile.mkdtemp()
    w.ws = d
    w.notes_path = os.path.join(d, "NOTES.md")
    with open(os.path.join(d, "RELAY.md"), "w") as f:
        f.write("# 接力块\n已达成原语: SSRF→内网可达\n")
    return w


def test_timeout_retry_hard_tiered():
    """hard retry 分级（run 12464 复盘）：有断点 35/40min，无断点 12min 快验轮。"""
    import os as _os
    w = _give_progress(_mk_worker(unique_code="b-02", flag_count=4, difficulty="hard", attempt=1))
    assert w._scaled_timeout_s() == 35 * 60
    w = _give_progress(_mk_worker(unique_code="b-02", flag_count=4, difficulty="hard", attempt=2))
    assert w._scaled_timeout_s() == 40 * 60
    # 无断点（不设工作区）：快验轮
    w2 = _mk_worker(unique_code="b-02", flag_count=4, difficulty="hard", attempt=2)
    assert w2._scaled_timeout_s() == 12 * 60


def test_timeout_easy_below_cap():
    """easy 首轮 8min（AePis 复盘：easy/medium 全扫 <2h，首轮快速轮转）。"""
    w = _mk_worker(unique_code="a-01", flag_count=1, difficulty="easy")
    assert w._scaled_timeout_s() == 8 * 60


def test_completed_sol_timeout_cap():
    """有完整解法的复现题快速止损：单 flag 5min，多 flag 10min。"""
    easy = _mk_worker(unique_code="a-01", flag_count=1, difficulty="easy")
    assert easy._scaled_timeout_s(has_completed_sol=True) == 5 * 60
    hard = _mk_worker(unique_code="b-01", flag_count=4, difficulty="hard")
    assert hard._scaled_timeout_s(has_completed_sol=True) == 10 * 60


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
    assert _priority(hard) < _priority(easy)  # 已有完整解法优先复现


def test_priority_partial_boosted(monkeypatch):
    import agent.scheduler as sched
    monkeypatch.setattr(sched, "_LIB", {"b-02": {"partial": True}})
    partial = _ch("b-02", score=1200, difficulty="hard", flags=4)
    unknown_easy = _ch("a-02", score=500, difficulty="easy")
    # 题数目标：只剩一面的题优先于 partial 多 flag 题，不再按分值押注大题。
    assert _priority(unknown_easy) < _priority(partial)
    assert _priority(_ch("a-02", score=300, difficulty="easy")) < _priority(partial)


def test_priority_round1_unknown_boosted(monkeypatch):
    """ROUND=1 覆盖优先：没碰过的题压过 completed 复现题。"""
    import agent.scheduler as sched
    monkeypatch.setattr(sched, "_LIB", {"b-01": {"completed": True}})
    known = _ch("b-01", score=1200, difficulty="hard", flags=4)
    unknown = _ch("a-02", score=500, difficulty="easy")
    assert _priority(unknown, round_num=1) < _priority(known, round_num=1)
    # ROUND=2 行为不变：completed 复现题仍优先
    assert _priority(known, round_num=2) < _priority(unknown, round_num=2)


def test_timeout_round1_short_cap():
    """ROUND=1 仍沿用快速轮转预算（45min 多 flag 预算被 cap 到 30）；
    完整解法题走更短复现预算。"""
    hard = _mk_worker(unique_code="b-02", flag_count=4, difficulty="hard")
    hard.cfg.round_num = 1
    assert hard._scaled_timeout_s(has_completed_sol=False) == 30 * 60
    easy = _mk_worker(unique_code="a-01", flag_count=1, difficulty="easy")
    easy.cfg.round_num = 1
    assert easy._scaled_timeout_s(has_completed_sol=False) == 8 * 60
    assert hard._scaled_timeout_s(has_completed_sol=True) == 10 * 60


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


# ---- 蒸馏块 vs 断点判定闭环（12464 止损保护被 12641 蒸馏架空的修复） ----

def test_relay_block_empty_variants():
    """空块判定：三行/六行全「无」= 空；空 lines 恒不触发；有实质行 = 非空。"""
    assert Worker._relay_block_empty(["已达成原语: 无", "已证死路: 无", "下一步: 无"], 3)
    assert Worker._relay_block_empty(["已达成原语: 无"] * 6, 6)
    assert not Worker._relay_block_empty([], 3)                    # all([]) 老坑
    assert not Worker._relay_block_empty(["已达成原语: RCE on web-1"], 3)
    # 六行版：只看前 3 行会漏掉后 3 行的实质内容
    assert not Worker._relay_block_empty(
        ["已达成原语: 无", "已证死路: 无", "下一步: 无",
         "内网拓扑: 10.0.0.5:8080, 10.0.0.6:22", "已拿主机与凭据: 无", "可复用文件: 无"], 6)


def test_has_progress_ignores_empty_distill_block():
    """全「无」蒸馏块不算断点：retry 不拿满预算（12min 快验），no_progress 熔断可触发。"""
    import tempfile
    w = _mk_worker(unique_code="b-02", flag_count=4, difficulty="hard", attempt=2)
    d = tempfile.mkdtemp()
    w.ws = d
    w.notes_path = os.path.join(d, "NOTES.md")
    with open(os.path.join(d, "RELAY.md"), "w") as f:
        f.write("# 接力块（跨线共享）\n"
                "## 会话蒸馏（11:00:00）\n"
                "已达成原语: 无\n内网拓扑: 无\n已证死路: 无\n下一步: 无\n")
    assert not w._has_progress()
    assert w._scaled_timeout_s() == 12 * 60          # 快验轮，不是 40min 满预算


def test_has_progress_counts_distill_with_real_content():
    """蒸馏块里有实质内容（拓扑/凭据）算真断点：拿满预算续跑。"""
    import tempfile
    w = _mk_worker(unique_code="b-02", flag_count=4, difficulty="hard", attempt=2)
    d = tempfile.mkdtemp()
    w.ws = d
    w.notes_path = os.path.join(d, "NOTES.md")
    with open(os.path.join(d, "RELAY.md"), "w") as f:
        f.write("# 接力块（跨线共享）\n"
                "## 会话蒸馏（11:00:00）\n"
                "已达成原语: SSRF→内网可达\n内网拓扑: 10.0.0.5:8080\n"
                "已拿主机与凭据: 无\n已证死路: 泛微路径 — 不存在\n下一步: 打 10.0.0.5\n")
    assert w._has_progress()
    assert w._scaled_timeout_s() == 40 * 60


# ---- 格式拒绝不烧错提额度 ----

def test_record_reject_keeps_wrong_budget():
    """格式闸门拒绝（从未打平台）只记 tried：不进连错/累计错提，auto 通道熔断额度不烧。"""
    from agent.flagger import FlagSubmitter
    s = FlagSubmitter("x-01", 1, wrong_cap=2)
    s.record_reject("flag{placeholder}")
    assert s.wrong_streak == 0
    assert s.wrong_total == 0
    assert "flag{placeholder}" in s.tried       # 防重复尝试
    # 真实错提 2 次后才熔断 auto 通道
    s.record("flag{aaaaaaaaaaaa1}", False, 0)
    s.record("flag{bbbbbbbbbbbb2}", False, 0)
    assert s.wrong_total == 2
    assert not s.should_try("flag{cccccccccccc3}", auto=True)


# ---- 预侦察地址解析（scheme 剥离） ----

def test_addr_host_port_tolerates_scheme():
    from agent.recon import _addr_host_port
    assert _addr_host_port("http://10.0.0.3:8080/x") == ("10.0.0.3", 8080)
    assert _addr_host_port("10.0.0.1:80") == ("10.0.0.1", 80)
    assert _addr_host_port("10.0.0.2") is None
    assert _addr_host_port("https://h:8443") == ("h", 8443)
