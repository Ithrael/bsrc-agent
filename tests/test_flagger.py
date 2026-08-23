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
