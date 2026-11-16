from __future__ import annotations

import asyncio

from app.workers import tasks


def test_worker_coroutines_reuse_one_event_loop(monkeypatch) -> None:
    monkeypatch.setattr(tasks, "_worker_event_loop", None)
    monkeypatch.setattr(tasks, "_worker_event_loop_pid", None)

    async def current_loop_id() -> int:
        return id(asyncio.get_running_loop())

    try:
        first = tasks._run_coroutine(current_loop_id())
        second = tasks._run_coroutine(current_loop_id())

        assert first == second
    finally:
        loop = tasks._worker_event_loop
        if loop is not None and not loop.is_closed():
            loop.close()
        monkeypatch.setattr(tasks, "_worker_event_loop", None)
        monkeypatch.setattr(tasks, "_worker_event_loop_pid", None)
