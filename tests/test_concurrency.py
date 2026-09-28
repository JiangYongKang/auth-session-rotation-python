"""并发场景：多个请求同时拿同一个刷新令牌刷新。

不变量：恰好一个成功，其余全部被拒绝；成功后再重放旧令牌必触发重用撤销。
"""

from __future__ import annotations

import logging
import threading

import pytest

from authapp.errors import RefreshTokenReused

logger = logging.getLogger("auth-tests")


def test_concurrent_refresh_single_winner(service):
    pair = service.login("alice", "password123")
    n_threads = 32
    barrier = threading.Barrier(n_threads)  # 尽量让所有线程同时进入临界区

    successes: list = []
    failures: list[Exception] = []
    lock = threading.Lock()

    def worker() -> None:
        barrier.wait()
        try:
            result = service.refresh(pair.refresh_token)
            with lock:
                successes.append(result)
        except Exception as exc:  # noqa: BLE001 - 需要收集所有失败类型
            with lock:
                failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(n_threads)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    logger.info(
        "并发刷新结果: 成功=%d 失败=%d, 失败码=%s",
        len(successes),
        len(failures),
        sorted({type(f).__name__ for f in failures}),
    )

    assert len(successes) == 1, f"期望恰好 1 个成功，实际 {len(successes)}"
    assert len(failures) == n_threads - 1
    # 因为失败的请求拿的是同一个"已被消费"的令牌，全部按重用处理
    assert all(isinstance(f, RefreshTokenReused) for f in failures)

    # 并发重放后，会话必然已撤销；轮换出的新令牌也不能用
    session = service.store.get_session(pair.session_id)
    assert session.revoked is True
    assert session.revoke_reason == "refresh_token_reuse"

    rotated = successes[0]
    from authapp.errors import SessionRevoked

    with pytest.raises(SessionRevoked):
        service.refresh(rotated.refresh_token)

    # 审计：恰好一次 refresh_success
    assert service.audit.names().count("refresh_success") == 1


def test_concurrent_refresh_each_with_distinct_tokens(service):
    """对照场景：各自持有不同会话令牌的并发刷新互不影响。"""
    pairs = [service.login("alice", "password123") for _ in range(8)]
    results: dict[int, object] = {}
    errors: list[Exception] = []
    barrier = threading.Barrier(len(pairs))
    lock = threading.Lock()

    def worker(idx: int, token: str) -> None:
        barrier.wait()
        try:
            with lock:
                results[idx] = service.refresh(token)
        except Exception as exc:  # noqa: BLE001
            with lock:
                errors.append(exc)

    threads = [
        threading.Thread(target=worker, args=(i, p.refresh_token))
        for i, p in enumerate(pairs)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert errors == []
    assert len(results) == len(pairs)
