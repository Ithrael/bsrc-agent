from agent.flagger import FlagSubmitter, extract_flags


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


def test_submitter_dedup_and_complete():
    s = FlagSubmitter("x", expected_flags=2)
    assert s.should_try("flag{a}")
    s.record("flag{a}", True, 50)
    assert not s.should_try("flag{a}")
    assert not s.completed
    s.record("flag{b}", True, 50)
    assert s.completed
    assert s.score == 100
