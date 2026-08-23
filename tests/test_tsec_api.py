import pytest

from agent.tsec_api import ApiError, TsecClient
from tests.mock_server import TOKEN, make_server


@pytest.fixture
def server():
    srv = make_server()
    yield srv
    srv.shutdown()


@pytest.fixture
def client(server):
    host, port = server.server_address
    return TsecClient(f"http://{host}:{port}", TOKEN)


@pytest.mark.asyncio
async def test_list_start_submit_close(client):
    lst = await client.list_challenges()
    assert len(lst) == 2
    c = next(x for x in lst if x.unique_code == "mock_web_01")
    assert c.remaining_flags == 1

    addrs = await client.start_challenge("mock_web_01")
    assert addrs == ["127.0.0.1:31337"]

    wrong = await client.submit_flag("mock_web_01", "flag{nope}")
    assert not wrong.correct

    ok = await client.submit_flag("mock_web_01", "flag{mock_flag_01}")
    assert ok.correct and ok.awarded == 100

    with pytest.raises(ApiError) as ei:
        await client.submit_flag("mock_web_01", "flag{mock_flag_01}")
    assert ei.value.code == "duplicate"

    with pytest.raises(ApiError) as ei2:
        await client.get_hint("mock_web_01")  # 已通关不允许
    assert ei2.value.code == "invalid_state"

    assert await client.close_challenge("mock_web_01")
    await client.close()


@pytest.mark.asyncio
async def test_bad_token(server):
    host, port = server.server_address
    bad = TsecClient(f"http://{host}:{port}", "wrong")
    with pytest.raises(ApiError) as ei:
        await bad.list_challenges()
    assert ei.value.code == "task_not_found"
    await bad.close()


@pytest.mark.asyncio
async def test_unknown_challenge(client):
    with pytest.raises(ApiError) as ei:
        await client.start_challenge("no_such")
    assert ei.value.code == "challenge_not_found"
    await client.close()
