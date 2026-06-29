from __future__ import annotations

import threading
from collections import deque
from datetime import UTC, datetime
from typing import Any, Callable

from scanner.models import ExecutionLogEntry, LogLevel, PhaseName

MAX_LOG_ENTRIES = 200


class WebExecutionManager:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._workers: dict[str, threading.Thread] = {}
        self._cancel_events: dict[str, threading.Event] = {}
        self._logs: dict[str, deque[ExecutionLogEntry]] = {}

    def is_active(self, run_id: str) -> bool:
        with self._lock:
            worker = self._workers.get(run_id)
            return worker is not None and worker.is_alive()

    def is_cancel_requested(self, run_id: str) -> bool:
        with self._lock:
            event = self._cancel_events.get(run_id)
            return event.is_set() if event is not None else False

    def request_cancel(self, run_id: str) -> bool:
        with self._lock:
            event = self._cancel_events.get(run_id)
            if event is None:
                return False
            event.set()
            return True

    def append_log(
        self,
        run_id: str,
        message: str,
        *,
        level: LogLevel = "info",
        module: PhaseName | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        entry = ExecutionLogEntry(
            timestamp=datetime.now(UTC),
            level=level,
            message=message,
            module=module,
            data=data or {},
        )
        with self._lock:
            self._logs.setdefault(run_id, deque(maxlen=MAX_LOG_ENTRIES)).append(entry)

    def get_logs(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            entries = list(self._logs.get(run_id, ()))
        return [entry.model_dump(mode="json") for entry in entries]

    def start(self, run_id: str, target: Callable[[], object]) -> bool:
        with self._lock:
            existing = self._workers.get(run_id)
            if existing is not None and existing.is_alive():
                return False
            self._cancel_events[run_id] = threading.Event()
            self._logs.setdefault(run_id, deque(maxlen=MAX_LOG_ENTRIES))

            worker = threading.Thread(
                target=self._run_worker,
                args=(run_id, target),
                daemon=True,
                name=f"scanner-ui-{run_id}",
            )
            self._workers[run_id] = worker
            worker.start()
        self.append_log(run_id, "Execution worker started")
        return True

    def _run_worker(self, run_id: str, target: Callable[[], object]) -> None:
        try:
            target()
        except Exception as exc:
            self.append_log(run_id, f"Execution worker crashed: {exc}", level="error")
        finally:
            with self._lock:
                current = self._workers.get(run_id)
                if current is threading.current_thread():
                    self._workers.pop(run_id, None)
                self._cancel_events.pop(run_id, None)
            self.append_log(run_id, "Execution worker stopped")
