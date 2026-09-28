"""并发刷新同一刷新令牌：只能有一个成功，其余全部拒绝。"""

from __future__ import annotations

import threading
from collections import Counter

import pytest

from auth_app.errors import AuthError


def _gather(env, token, n_threads):
    results: list[tuple[str, str]] = []
    barrier = threading.Barrier(n_threads)

    def worker():
        barrier.wait()  # 尽量让所有线程同时发起刷新
        try:
            pair = env.service.refresh(token)
            results.append(("ok", pair.refresh_token))
        except AuthError as exc:
            results.append(("fail", exc.code))

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    return results


@pytest.mark.parametrize("n_threads", [5, 20, 50])
def test_concurrent_refresh_only_one_wins(env, n_threads):
    pair = env.service.login("viewer", "viewer123")
    results = _gather(env, pair.refresh_token, n_threads)

    counter = Counter(status for status, _ in results)
    assert counter["ok"] == 1, f"成功数应为 1，实际：{counter}"
    assert counter["fail"] == n_threads - 1

    # 所有失败必须是可解释的认证错误（重放/会话撤销），不能是 500
    for status, code in results:
        if status == "fail":
            assert code in {"refresh_token_reused", "session_revoked"}

    # 获胜者签发的新令牌各不重复；失败者没有产生任何额外令牌
    winning_tokens = [tok for status, tok in results if status == "ok"]
    assert len(set(winning_tokens)) == 1

    # 会话已因并发重放尝试被撤销
    sessions = env.service.list_sessions("u_viewer")
    assert all(s["revoked"] for s in sessions)

    reuse_events = [e for e in env.service.audit.entries()
                    if e["event"] == "refresh_token_reuse_detected"]
    assert len(reuse_events) == n_threads - 1


def test_concurrent_refresh_over_http_has_single_winner(env):
    """通过 HTTP 入口并发，结论与服务层一致。"""
    pair = env.service.login("bob", "bob123")
    n = 16
    barrier = threading.Barrier(n)
    outcomes: list[int] = []
    lock = threading.Lock()

    def worker():
        barrier.wait()
        r = env.client.post("/auth/refresh",
                            json={"refresh_token": pair.refresh_token})
        with lock:
            outcomes.append(r.status_code)

    threads = [threading.Thread(target=worker) for _ in range(n)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert outcomes.count(200) == 1
    assert outcomes.count(401) == n - 1
