from agent.flagger import FlagSubmitter, extract_flags, plausible_flag


def test_extract_basic():
    out = extract_flags("恭喜！flag{sql_master_2024} 就在表里")
    assert out == ["flag{sql_master_2024}"]


def test_extract_multiple_and_dedup():
    text = "FLAG{ABC-123} 和 flag{abc}，重复 FLAG{ABC-123}"
    flags = extract_flags(text)
    assert flags == ["FLAG{ABC-123}", "flag{abc}"]


def test_extract_uuid_form():
    assert extract_flags("flag-123e4567-e89b-12d3-a456-426614174000") == \
        ["flag-123e4567-e89b-12d3-a456-426614174000"]


def test_extract_none():
    assert extract_flags("没有 flag 的普通输出 flag 不完整{") == []


def test_plausible_accepts_platform_forms():
    """平台实测两形态：flag{UUID} / flag{含数字 leetspeak}（+ flag-UUID 裸形态兜底）。"""
    assert plausible_flag("flag{509672c2-5854-47ff-bbab-da37ecd3472f}")
    assert plausible_flag("flag{x73a_f31st3l_k3y_5ch3d_fr0m_fw}")
    assert plausible_flag("flag{mock_flag_01}")
    assert plausible_flag("flag-123e4567-e89b-12d3-a456-426614174000")


def test_plausible_rejects_junk():
    """run 10282 复盘 111 次错提的典型垃圾形态，全部拦在提交前。"""
    for junk in ("flag{...}", "flag{test_flag}", "flag{this_is_the_flag}",
                 "flag{placeholder}", "flag{example}", "flag{a}",  # 过短/无数字
                 "FLAG{ABC-123}", "KEY{secret_stuff_1}", "tsec{fake-guess}",
                 "flag{,.txt}", "flag{hexhex...}", "flag{}", ""):
        assert not plausible_flag(junk), junk


def test_should_try_gates_format():
    """should_try 收口格式闸门：所有提交通道（含调度器直连 api.submit_flag）统一拦截。"""
    s = FlagSubmitter("x", expected_flags=2)
    assert not s.should_try("flag{fake_guess_no_digit}")
    assert not s.should_try("flag{...}")
    assert s.should_try("flag{a1b2c3d4}")
    s.record("flag{a1b2c3d4}", True, 50)
    assert not s.should_try("flag{a1b2c3d4}")  # 去重仍生效


def test_submitter_dedup_and_complete():
    s = FlagSubmitter("x", expected_flags=2)
    assert s.should_try("flag{a1b2c3d4}")
    s.record("flag{a1b2c3d4}", True, 50)
    assert not s.should_try("flag{a1b2c3d4}")
    assert not s.completed
    s.record("flag{b2c3d4e5}", True, 50)
    assert s.completed
    assert s.score == 100


def test_submitter_reuses_platform_progress():
    """重试/并行任务继承平台已有进度；duplicate 不能把计数重复加满。"""
    s = FlagSubmitter("x", expected_flags=3, initial_correct_count=2)
    assert not s.completed
    s.record("flag{old}", True, 0)
    assert s.correct_count == 2
    s.record("flag{new}", True, 100, correct_count=3)
    assert s.completed


def test_auto_channel_wrong_cap_fuse():
    """run 12464 复盘：auto 通道（正则捕获）累计错提 ≥cap 熔断；显式通道不熔断。"""
    s = FlagSubmitter("x", expected_flags=1, wrong_cap=3)
    for i in range(3):
        assert s.should_try(f"flag{{{chr(97 + i)}1b2c3d4}}", auto=True)
        s.record(f"flag{{{chr(97 + i)}1b2c3d4}}", False, 0)
    # auto 通道熔断
    assert not s.should_try("flag{z9y8x7w6}", auto=True)
    # 显式通道（LLM submit_flag 调用）仍放行——c-02 错 23 次仍解出的教训
    assert s.should_try("flag{z9y8x7w6}")
    # 正确提交不受影响：显式通道提交正确后 completed
    s.record("flag{z9y8x7w6}", True, 100, correct_count=1)
    assert s.completed
    # wrong_total 不因正确提交清零（auto 通道保持关闭）
    assert s.wrong_total == 3
    assert not s.should_try("flag{q1w2e3r4t5}", auto=True)
