from agent.prompts import build_system, playbook_for
from agent.scheduler import _priority
from agent.tsec_api import Challenge


def test_playbook_match():
    assert "Web" in playbook_for("a-13")
    assert "二进制" in playbook_for("f2-05")
    assert "多阶段" in playbook_for("b-02")
    assert "云攻击" in playbook_for("d-01")
    assert "对抗规避" in playbook_for("e3-04")
    # 百度靶场专项：AI（g）/ 区块链（h）
    assert "AI 应用" in playbook_for("g-01")
    assert "区块链" in playbook_for("h-01")
    # 无匹配时回退 Web playbook（百度靶场 Web 占 67%）
    assert "Web" in playbook_for("zzz")


def test_playbook_description_fallback():
    """题目前缀未知时按描述关键词匹配：AI/区块链兜底。"""
    assert "AI 应用" in playbook_for("x-01", "某智能体 agent 应用存在 prompt 注入漏洞")
    assert "区块链" in playbook_for("x-02", "以太坊智能合约的访问控制缺陷")
    assert "Web" in playbook_for("x-03", "SQL 注入")  # 无关描述回退 Web


def test_build_system_contains_challenge_info():
    s = build_system("a-01", "测试描述", ["10.0.0.1:80"], 2, 0, 500, "hard")
    assert "a-01" in s and "10.0.0.1:80" in s and "2 面 flag" in s


def _mk(code, score, diff, flags=1):
    return Challenge(code, None, diff, 1, score, flags, 0, False, "stopped", [])


def test_priority_single_flag_before_multi_flag(monkeypatch):
    import agent.scheduler as sched
    monkeypatch.setattr(sched, "_LIB", {})  # 现场解模式：无解法库（solutions.json 可能被跑分回写）
    easy = _mk("d-01", 200, "easy")
    hard = _mk("a-01", 500, "hard")
    multi = _mk("b-01", 1200, "hard", flags=4)
    ordered = sorted([hard, easy, multi], key=_priority)
    assert ordered[0].unique_code == "d-01"  # 目标是单位墙钟解出更多完整题
    assert _priority(easy) < _priority(hard) < _priority(multi)


def test_killchain_playbook_stage_gates():
    """b 系列 playbook：阶段门流程 + 台账/工具/穿透全部就位（通用 tradecraft，无题目先验）。"""
    from agent.prompts import PLAYBOOKS
    pb = PLAYBOOKS["b"]
    assert "阶段门" in pb
    for gate in ("门1", "门2", "门3", "门4"):
        assert gate in pb, gate
    assert "HOSTS.md" in pb and "台账" in pb
    assert "flag_sweep.sh" in pb and "creds_replay.sh" in pb
    assert "chisel" in pb and "ssh -D" in pb
    assert "空等" in pb  # 横向线开工纪律
