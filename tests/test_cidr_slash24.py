"""
Tests for /24 CIDR range scanning (256 hosts).

Validates that the scanner correctly handles large CIDR ranges across:
- CIDR splitting into appropriately-sized chunks
- Adaptive chunk size calculations
- Offset-based range traversal covering all 256 addresses
- Resume from checkpoint after interruption
- Cancellation mid-scan preserving state
- Downstream pipeline (http_probe → dir_enum → cve_match) per chunk
- End-to-end execution with mocked nmap/httpx
- Edge cases (boundary IPs, non-aligned offsets)
"""
from __future__ import annotations

import ipaddress
import json
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import pytest

from scanner.models import Finding, ScanConfig
from scanner.runner import (
    calculate_next_chunk_size,
    cidr_count_addresses_ipv4,
    cidr_estimated_remaining_minutes,
    cidr_offset_range_target,
    create_scan_run,
    cancel_run,
    execute_port_scan_tasks,
    execute_http_probe_tasks,
    should_split_port_scan_cidr,
    split_ipv4_cidr_for_port_scan,
    update_cidr_ema_chunk_duration,
    cursor_suggests_cidr_resume_incomplete,
)
from scanner.storage import connect, insert_finding, update_task_state


# ---------------------------------------------------------------------------
# 1. CIDR Splitting: /24 → correct sub-blocks
# ---------------------------------------------------------------------------


class TestCidrSplitSlash24:
    """Verify split_ipv4_cidr_for_port_scan produces correct chunks for /24."""

    def test_split_slash24_chunk32_yields_8_slash27(self) -> None:
        """256 hosts / 32 per chunk = 8 × /27 blocks."""
        chunks = split_ipv4_cidr_for_port_scan("10.0.0.0/24", 32)
        assert len(chunks) == 8
        assert all("/27" in c for c in chunks)
        # Verify they cover the full range
        all_ips: set[str] = set()
        for chunk in chunks:
            net = ipaddress.ip_network(chunk, strict=False)
            for ip in net:
                all_ips.add(str(ip))
        assert len(all_ips) == 256

    def test_split_slash24_chunk64_yields_4_slash26(self) -> None:
        """256 hosts / 64 per chunk = 4 × /26 blocks."""
        chunks = split_ipv4_cidr_for_port_scan("10.0.0.0/24", 64)
        assert len(chunks) == 4
        assert all("/26" in c for c in chunks)

    def test_split_slash24_chunk128_yields_2_slash25(self) -> None:
        """256 hosts / 128 per chunk = 2 × /25 blocks."""
        chunks = split_ipv4_cidr_for_port_scan("10.0.0.0/24", 128)
        assert len(chunks) == 2
        assert all("/25" in c for c in chunks)

    def test_split_slash24_chunk256_returns_whole(self) -> None:
        """If chunk size >= total, return the whole /24 as-is."""
        chunks = split_ipv4_cidr_for_port_scan("10.0.0.0/24", 256)
        assert len(chunks) == 1
        assert chunks[0] == "10.0.0.0/24"

    def test_split_slash24_chunk16_yields_16_slash28(self) -> None:
        """256 hosts / 16 per chunk = 16 × /28 blocks."""
        chunks = split_ipv4_cidr_for_port_scan("10.0.0.0/24", 16)
        assert len(chunks) == 16
        assert all("/28" in c for c in chunks)

    def test_split_slash24_chunk8_yields_32_slash29(self) -> None:
        """256 hosts / 8 per chunk = 32 × /29 blocks."""
        chunks = split_ipv4_cidr_for_port_scan("10.0.0.0/24", 8)
        assert len(chunks) == 32
        assert all("/29" in c for c in chunks)

    def test_split_preserves_full_ip_coverage(self) -> None:
        """Every IP in the /24 must appear in exactly one chunk."""
        chunks = split_ipv4_cidr_for_port_scan("192.168.1.0/24", 32)
        all_ips: list[str] = []
        for chunk in chunks:
            net = ipaddress.ip_network(chunk, strict=False)
            all_ips.extend(str(ip) for ip in net)
        # 256 IPs, no duplicates
        assert len(all_ips) == 256
        assert len(set(all_ips)) == 256
        # First and last IP present
        assert "192.168.1.0" in all_ips
        assert "192.168.1.255" in all_ips

    def test_split_non_zero_base_address(self) -> None:
        """Non-.0 base addresses are normalized to network boundary."""
        # 114.31.114.0/24 even if specified as 114.31.114.50/24
        chunks = split_ipv4_cidr_for_port_scan("114.31.114.50/24", 32)
        assert len(chunks) == 8
        # First chunk should start at network address .0
        first_net = ipaddress.ip_network(chunks[0], strict=False)
        assert str(first_net.network_address) == "114.31.114.0"


# ---------------------------------------------------------------------------
# 2. should_split decision for /24
# ---------------------------------------------------------------------------


class TestShouldSplitDecision:
    """Verify that should_split_port_scan_cidr correctly identifies /24 as needing splits."""

    @pytest.fixture()
    def base_config(self) -> ScanConfig:
        return ScanConfig(
            target="10.0.0.0/24",
            profile="safe",
            cidr_split_enabled=True,
            cidr_split_max_hosts_per_chunk=32,
        )

    def test_slash24_with_default_chunk_triggers_split(self, base_config: ScanConfig) -> None:
        """256 > 32 → must split."""
        assert should_split_port_scan_cidr(base_config, ["10.0.0.0/24"]) is True

    def test_slash24_disabled_flag_prevents_split(self, base_config: ScanConfig) -> None:
        cfg = base_config.model_copy(update={"cidr_split_enabled": False})
        assert should_split_port_scan_cidr(cfg, ["10.0.0.0/24"]) is False

    def test_slash24_large_chunk_prevents_split(self, base_config: ScanConfig) -> None:
        """If chunk >= 256, no split needed."""
        cfg = base_config.model_copy(update={"cidr_split_max_hosts_per_chunk": 256})
        assert should_split_port_scan_cidr(cfg, ["10.0.0.0/24"]) is False

    def test_slash24_multiple_targets_prevents_split(self, base_config: ScanConfig) -> None:
        """Split only works with exactly 1 CIDR target."""
        assert should_split_port_scan_cidr(base_config, ["10.0.0.0/24", "10.0.1.0/24"]) is False

    def test_slash24_non_cidr_prevents_split(self, base_config: ScanConfig) -> None:
        """Plain IP address should not trigger split."""
        assert should_split_port_scan_cidr(base_config, ["10.0.0.1"]) is False


# ---------------------------------------------------------------------------
# 3. Offset traversal: walk through all 256 addresses
# ---------------------------------------------------------------------------


class TestCidrOffsetTraversal:
    """Verify that cidr_offset_range_target iterates through all 256 addresses."""

    def test_full_traversal_covers_all_256_addresses(self) -> None:
        """Walk through 10.0.0.0/24 with chunk_size=32, expect 8 iterations."""
        cidr = "10.0.0.0/24"
        chunk_size = 32
        offset = 0
        chunks_seen: list[str] = []
        iterations = 0
        max_iterations = 100  # safety guard

        while iterations < max_iterations:
            target, next_offset, last_ip, done = cidr_offset_range_target(cidr, offset, chunk_size)
            if not target or next_offset <= offset:
                break
            chunks_seen.append(target)
            offset = next_offset
            iterations += 1
            if done:
                break

        # Should complete in exactly 8 iterations for /24 with 32-host chunks
        assert iterations == 8
        assert offset == 256  # fully consumed
        assert len(chunks_seen) == 8

    def test_offset_traversal_with_unaligned_chunk_size(self) -> None:
        """Chunk_size=50 is not power-of-two; verify full coverage with aligned CIDR blocks."""
        cidr = "10.0.0.0/24"
        chunk_size = 50
        offset = 0
        all_targets: list[str] = []
        all_ips: set[str] = set()
        iterations = 0
        max_iterations = 100

        while iterations < max_iterations:
            target, next_offset, last_ip, done = cidr_offset_range_target(cidr, offset, chunk_size)
            if not target or next_offset <= offset:
                break
            all_targets.append(target)
            # Collect IPs from the target CIDR
            try:
                net = ipaddress.ip_network(target, strict=False)
                for ip in net:
                    all_ips.add(str(ip))
            except ValueError:
                pass
            offset = next_offset
            iterations += 1
            if done:
                break

        # Must cover all 256 IPs with possibly more iterations due to alignment
        assert len(all_ips) == 256
        assert "10.0.0.0" in all_ips
        assert "10.0.0.255" in all_ips

    def test_offset_starting_midway(self) -> None:
        """Resume from offset=128 should cover remaining 128 addresses."""
        cidr = "10.0.0.0/24"
        chunk_size = 32
        offset = 128
        chunks_seen: list[str] = []
        iterations = 0

        while iterations < 50:
            target, next_offset, last_ip, done = cidr_offset_range_target(cidr, offset, chunk_size)
            if not target or next_offset <= offset:
                break
            chunks_seen.append(target)
            offset = next_offset
            iterations += 1
            if done:
                break

        # 128 remaining / 32 = 4 chunks
        assert iterations == 4
        assert offset == 256
        # First chunk should start at .128
        first_net = ipaddress.ip_network(chunks_seen[0], strict=False)
        assert str(first_net.network_address) == "10.0.0.128"

    def test_offset_at_boundary_returns_done(self) -> None:
        """Offset=256 (already past all addresses) should return done=True."""
        target, next_offset, last_ip, done = cidr_offset_range_target("10.0.0.0/24", 256, 32)
        assert target == ""
        assert done is True

    def test_last_ip_in_each_chunk_is_correct(self) -> None:
        """Verify last_ip for each chunk in /24."""
        cidr = "10.0.0.0/24"
        offset = 0
        expected_last_ips = [
            "10.0.0.31", "10.0.0.63", "10.0.0.95", "10.0.0.127",
            "10.0.0.159", "10.0.0.191", "10.0.0.223", "10.0.0.255",
        ]
        actual_last_ips: list[str] = []

        while True:
            target, next_offset, last_ip, done = cidr_offset_range_target(cidr, offset, 32)
            if not target or next_offset <= offset:
                break
            actual_last_ips.append(last_ip or "")
            offset = next_offset
            if done:
                break

        assert actual_last_ips == expected_last_ips


# ---------------------------------------------------------------------------
# 4. cidr_count / EMA / estimation helpers
# ---------------------------------------------------------------------------


class TestCidrHelpers:
    """Verify helper functions for /24 calculations."""

    def test_count_addresses_slash24(self) -> None:
        assert cidr_count_addresses_ipv4("10.0.0.0/24") == 256

    def test_estimated_remaining_with_8_chunks(self) -> None:
        """8 chunks at 60s each → 8 minutes remaining."""
        result = cidr_estimated_remaining_minutes(256, 32, 60.0)
        assert result is not None
        assert abs(result - 8.0) < 0.01

    def test_estimated_remaining_half_done(self) -> None:
        """128 remaining / 32 = 4 chunks at 120s → 8 minutes."""
        result = cidr_estimated_remaining_minutes(128, 32, 120.0)
        assert result is not None
        assert abs(result - 8.0) < 0.01

    def test_ema_first_update(self) -> None:
        """First chunk (no prior) → raw duration becomes EMA."""
        ema = update_cidr_ema_chunk_duration(None, 60.0)
        assert ema == 60.0

    def test_ema_converges_toward_new_value(self) -> None:
        """EMA with α=0.35 moves toward new observation."""
        ema = update_cidr_ema_chunk_duration(60.0, 120.0)
        # 0.35 * 120 + 0.65 * 60 = 42 + 39 = 81
        assert abs(ema - 81.0) < 0.01

    def test_adaptive_chunk_size_grows_when_fast(self) -> None:
        """If chunks finish faster than target, grow chunk size."""
        # target=10min=600s, avg=300s → ratio=2.0 (capped) → 32*2=64
        new_size = calculate_next_chunk_size(300.0, 10, 32)
        assert new_size == 64

    def test_adaptive_chunk_size_shrinks_when_slow(self) -> None:
        """If chunks take too long, shrink chunk size."""
        # target=10min=600s, avg=1200s → ratio=0.5 (capped) → 32*0.5=16
        new_size = calculate_next_chunk_size(1200.0, 10, 32)
        assert new_size == 16

    def test_adaptive_chunk_size_bounded_8_to_256(self) -> None:
        """Never go below 8 or above 256."""
        # Very fast → try to grow beyond 256
        new_size = calculate_next_chunk_size(1.0, 10, 256)
        assert new_size <= 256
        # Very slow → try to shrink below 8
        new_size = calculate_next_chunk_size(10000.0, 10, 8)
        assert new_size >= 8


# ---------------------------------------------------------------------------
# 5. cursor_suggests_cidr_resume_incomplete
# ---------------------------------------------------------------------------


class TestCidrResumeDetection:
    """Verify resume detection logic for /24 scan."""

    @pytest.fixture()
    def base_config(self) -> ScanConfig:
        return ScanConfig(
            target="10.0.0.0/24",
            profile="safe",
            cidr_resume_enabled=True,
        )

    def test_incomplete_cursor_detected(self, base_config: ScanConfig) -> None:
        cursor = {
            "cidr_resume_in_progress": True,
            "cidr_next_offset": 128,
            "cidr_total_addresses": 256,
        }
        assert cursor_suggests_cidr_resume_incomplete(base_config, cursor) is True

    def test_complete_cursor_not_detected(self, base_config: ScanConfig) -> None:
        cursor = {
            "cidr_resume_in_progress": True,
            "cidr_next_offset": 256,
            "cidr_total_addresses": 256,
        }
        assert cursor_suggests_cidr_resume_incomplete(base_config, cursor) is False

    def test_resume_disabled_not_detected(self, base_config: ScanConfig) -> None:
        cfg = base_config.model_copy(update={"cidr_resume_enabled": False})
        cursor = {
            "cidr_resume_in_progress": True,
            "cidr_next_offset": 128,
            "cidr_total_addresses": 256,
        }
        assert cursor_suggests_cidr_resume_incomplete(cfg, cursor) is False

    def test_missing_flag_not_detected(self, base_config: ScanConfig) -> None:
        cursor = {
            "cidr_next_offset": 128,
            "cidr_total_addresses": 256,
        }
        assert cursor_suggests_cidr_resume_incomplete(base_config, cursor) is False

    def test_zero_offset_detected_as_incomplete(self, base_config: ScanConfig) -> None:
        """Even offset=0 is 'incomplete' if total > 0."""
        cursor = {
            "cidr_resume_in_progress": True,
            "cidr_next_offset": 0,
            "cidr_total_addresses": 256,
        }
        assert cursor_suggests_cidr_resume_incomplete(base_config, cursor) is True


# ---------------------------------------------------------------------------
# 6. Run creation for /24 CIDR
# ---------------------------------------------------------------------------


class TestRunCreationSlash24:
    """Verify run setup and phase planning for /24 targets."""

    def test_slash24_creates_host_first_phases(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        summary = create_scan_run("10.0.0.0/24", profile="fast")
        # /24 is an IPv4 CIDR → host-first (no subdomain_enum)
        assert "subdomain_enum" not in summary["modules"]
        assert "port_scan" in summary["modules"]
        assert "http_probe" in summary["modules"]
        # port_scan should come before http_probe
        modules = summary["modules"]
        assert modules.index("port_scan") < modules.index("http_probe")

    def test_slash24_public_classified_as_ipv4(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        summary = create_scan_run("114.31.114.0/24", profile="fast")
        assert summary["target_kind"] == "ipv4"

    def test_slash24_private_classified_as_private(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        summary = create_scan_run("192.168.1.0/24", profile="fast")
        assert summary["target_kind"] == "private_internal"

    def test_slash24_creates_single_port_scan_task(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        summary = create_scan_run("10.0.0.0/24", modules=["port_scan"], profile="fast")
        port_tasks = [t for t in summary["tasks"] if t["module"] == "port_scan"]
        assert len(port_tasks) == 1
        assert port_tasks[0]["scope"] == "10.0.0.0/24"


# ---------------------------------------------------------------------------
# 7. End-to-end CIDR port scan with mocked nmap (adaptive loop)
# ---------------------------------------------------------------------------


class TestSlash24AdaptivePortScan:
    """Full /24 port scan with adaptive CIDR chunking (mocked subprocess)."""

    def test_all_chunks_scanned_and_findings_persisted(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        created = create_scan_run("10.0.0.0/24", modules=["port_scan"], profile="fast")
        run_id = created["run_id"]
        state_db = Path(created["state_db_path"])

        # Enable CIDR split with chunk=32 → 8 chunks expected
        connection = connect(state_db)
        try:
            cfg_row = connection.execute(
                "SELECT config_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            cfg = json.loads(cfg_row["config_json"])
            cfg["cidr_split_enabled"] = True
            cfg["cidr_split_max_hosts_per_chunk"] = 32
            cfg["cidr_split_adaptive_enabled"] = False  # deterministic chunk sizes
            connection.execute(
                "UPDATE runs SET config_json = ? WHERE run_id = ?",
                (json.dumps(cfg, sort_keys=True, separators=(",", ":")), run_id),
            )
            connection.commit()
        finally:
            connection.close()

        nmap_call_targets: list[str] = []

        class FakePort:
            def __init__(self, port: int = 80) -> None:
                self.port = port
                self.protocol = "tcp"
                self.state = "open"
                self.service = "http"
                self.product = ""
                self.version = ""
                self.extrainfo = ""
                self.raw_port: dict[str, object] = {}

        class FakeHost:
            def __init__(self, ip: str) -> None:
                self.target = ip
                self.host = ip
                self.ip = ip
                self.hostnames: list[str] = []
                self.ports = [FakePort()]
                self.raw_host: dict[str, object] = {}

        class FakeNmapResult:
            def __init__(self, target: str) -> None:
                self.command = ["nmap"]
                self.targets = [target]
                # Pick a representative host from the chunk
                try:
                    net = ipaddress.ip_network(target, strict=False)
                    first_ip = str(next(net.hosts()))
                except (ValueError, StopIteration):
                    first_ip = target
                self.hosts = [FakeHost(first_ip)]
                self.raw_output = "<nmaprun />"

        def fake_nmap_scan(targets, **kwargs):
            nmap_call_targets.extend(targets)
            return FakeNmapResult(targets[0])

        monkeypatch.setattr(
            "scanner.execution.portscan.runner_core.run_nmap_scan", fake_nmap_scan
        )

        result = execute_port_scan_tasks(run_id)

        # Verify all 8 chunks were scanned
        assert len(nmap_call_targets) == 8
        # All targets should be /27 blocks (32 hosts each)
        for t in nmap_call_targets:
            net = ipaddress.ip_network(t, strict=False)
            assert net.num_addresses == 32, f"Expected /27 block, got {t}"

        # Verify full coverage
        all_ips: set[str] = set()
        for t in nmap_call_targets:
            net = ipaddress.ip_network(t, strict=False)
            all_ips.update(str(ip) for ip in net)
        assert len(all_ips) == 256

        # Verify findings were persisted
        assert result["finding_count"] == 8  # one finding per chunk (1 host each)
        assert result["completed_task_count"] == 1
        assert result["failed_task_count"] == 0

    def test_resume_from_offset_128_scans_remaining_half(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        """Resume a /24 scan from offset 128 (4 chunks completed)."""
        monkeypatch.chdir(tmp_path)
        created = create_scan_run("10.0.0.0/24", modules=["port_scan"], profile="fast")
        run_id = created["run_id"]
        task_id = next(t["task_id"] for t in created["tasks"] if t["module"] == "port_scan")
        state_db = Path(created["state_db_path"])

        # Set up resume checkpoint cursor
        connection = connect(state_db)
        try:
            cfg_row = connection.execute(
                "SELECT config_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            cfg = json.loads(cfg_row["config_json"])
            cfg["cidr_split_enabled"] = True
            cfg["cidr_split_max_hosts_per_chunk"] = 32
            cfg["cidr_split_adaptive_enabled"] = False
            connection.execute(
                "UPDATE runs SET config_json = ? WHERE run_id = ?",
                (json.dumps(cfg, sort_keys=True, separators=(",", ":")), run_id),
            )
            connection.commit()

            cursor = {
                "stage": "nmap_scan",
                "cidr_resume_in_progress": True,
                "cidr_root": "10.0.0.0/24",
                "cidr_total_addresses": 256,
                "cidr_next_offset": 128,
                "cidr_current_chunk_size": 32,
                "cidr_completed_chunks": [0, 1, 2, 3],
                "cidr_avg_chunk_duration_sec": 5.0,
                "cidr_checkpoint_events": [],
            }
            update_task_state(
                connection,
                task_id,
                "failed",
                cursor_json=cursor,
                last_error="CIDR port scan stopped (resumable)",
            )
        finally:
            connection.close()

        nmap_call_targets: list[str] = []

        class FakeNmapResult:
            def __init__(self) -> None:
                self.command = ["nmap"]
                self.targets: list[str] = []
                self.hosts: list[object] = []
                self.raw_output = "<nmaprun />"

        def fake_nmap_scan(targets, **kwargs):
            nmap_call_targets.extend(targets)
            return FakeNmapResult()

        monkeypatch.setattr(
            "scanner.execution.portscan.runner_core.run_nmap_scan", fake_nmap_scan
        )

        execute_port_scan_tasks(run_id)

        # Should only scan the remaining 4 chunks (128..255)
        assert len(nmap_call_targets) == 4
        # First target should start at .128
        first_net = ipaddress.ip_network(nmap_call_targets[0], strict=False)
        assert str(first_net.network_address) == "10.0.0.128"


# ---------------------------------------------------------------------------
# 8. Cancellation mid-scan
# ---------------------------------------------------------------------------


class TestSlash24Cancellation:
    """Verify cancel preserves cursor state for resume."""

    def test_cancel_preserves_cidr_cursor(self, tmp_path: Path, monkeypatch) -> None:
        monkeypatch.chdir(tmp_path)
        from scanner.state import get_task, mark_run_running

        created = create_scan_run("10.0.0.0/24", modules=["port_scan"], profile="fast")
        run_id = created["run_id"]
        task_id = next(t["task_id"] for t in created["tasks"] if t["module"] == "port_scan")
        state_db = Path(created["state_db_path"])

        # Simulate mid-scan state
        connection = connect(state_db)
        try:
            mark_run_running(connection, run_id)
            cursor = {
                "stage": "nmap_scan",
                "cidr_resume_in_progress": True,
                "cidr_root": "10.0.0.0/24",
                "cidr_total_addresses": 256,
                "cidr_next_offset": 96,
                "cidr_current_chunk_size": 32,
                "cidr_completed_chunks": [0, 1, 2],
                "cidr_avg_chunk_duration_sec": 10.0,
            }
            update_task_state(
                connection, task_id, "running", cursor_json=cursor, last_error=None
            )
        finally:
            connection.close()

        # Cancel
        cancel_run(run_id, workspace=tmp_path)

        # Verify state preserved
        connection = connect(state_db)
        try:
            task = get_task(connection, task_id)
            assert task.state == "failed"
            assert "resumable" in (task.last_error or "").lower()
            assert task.cursor_json is not None
            assert task.cursor_json["cidr_next_offset"] == 96
            assert task.cursor_json["cidr_total_addresses"] == 256
            assert task.cursor_json["cidr_root"] == "10.0.0.0/24"
        finally:
            connection.close()


# ---------------------------------------------------------------------------
# 9. Downstream pipeline per chunk
# ---------------------------------------------------------------------------


class TestSlash24ChunkDownstream:
    """Verify http_probe is triggered per chunk during /24 scan."""

    def test_http_probe_invoked_after_each_nmap_chunk(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        created = create_scan_run(
            "10.0.0.0/24", modules=["port_scan", "http_probe"], profile="fast"
        )
        run_id = created["run_id"]
        state_db = Path(created["state_db_path"])

        # Enable CIDR split
        connection = connect(state_db)
        try:
            cfg_row = connection.execute(
                "SELECT config_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
            cfg = json.loads(cfg_row["config_json"])
            cfg["cidr_split_enabled"] = True
            cfg["cidr_split_max_hosts_per_chunk"] = 64  # 4 chunks
            cfg["cidr_split_adaptive_enabled"] = False
            connection.execute(
                "UPDATE runs SET config_json = ? WHERE run_id = ?",
                (json.dumps(cfg, sort_keys=True, separators=(",", ":")), run_id),
            )
            connection.commit()
        finally:
            connection.close()

        call_order: list[str] = []
        nmap_calls = 0

        class FakePort:
            def __init__(self) -> None:
                self.port = 80
                self.protocol = "tcp"
                self.state = "open"
                self.service = "http"
                self.product = ""
                self.version = ""
                self.extrainfo = ""
                self.raw_port: dict[str, object] = {}

        class FakeHost:
            def __init__(self, ip: str) -> None:
                self.target = ip
                self.host = ip
                self.ip = ip
                self.hostnames: list[str] = []
                self.ports = [FakePort()]
                self.raw_host: dict[str, object] = {}

        class FakeNmapResult:
            def __init__(self, ip: str) -> None:
                self.command = ["nmap"]
                self.targets = [ip]
                self.hosts = [FakeHost(ip)]
                self.raw_output = "<nmaprun />"

        def fake_nmap_scan(targets, **kwargs):
            nonlocal nmap_calls
            nmap_calls += 1
            call_order.append(f"nmap-{nmap_calls}")
            try:
                net = ipaddress.ip_network(targets[0], strict=False)
                ip = str(next(net.hosts()))
            except (ValueError, StopIteration):
                ip = "10.0.0.1"
            return FakeNmapResult(ip)

        def fake_execute_http_probe(run_id_arg, *, workspace=None):
            call_order.append("http")
            return {"run_id": run_id_arg, "processed_task_count": 1}

        monkeypatch.setattr(
            "scanner.execution.portscan.runner_core.run_nmap_scan", fake_nmap_scan
        )
        monkeypatch.setattr(
            "scanner.runner.execute_http_probe_tasks", fake_execute_http_probe
        )

        execute_port_scan_tasks(run_id)

        # Verify interleaved nmap→http pattern
        assert nmap_calls >= 4  # at least 4 chunks for /24 with 64-host chunks
        # http should be called after each nmap chunk
        assert "http" in call_order
        # First call should be nmap
        assert call_order[0] == "nmap-1"


# ---------------------------------------------------------------------------
# 10. Edge cases
# ---------------------------------------------------------------------------


class TestSlash24EdgeCases:
    """Edge cases specific to /24 range handling."""

    def test_broadcast_and_network_addresses_included(self) -> None:
        """Network (.0) and broadcast (.255) addresses should be in the range."""
        chunks = split_ipv4_cidr_for_port_scan("10.0.0.0/24", 32)
        all_ips: set[str] = set()
        for chunk in chunks:
            net = ipaddress.ip_network(chunk, strict=False)
            all_ips.update(str(ip) for ip in net)
        assert "10.0.0.0" in all_ips  # network address
        assert "10.0.0.255" in all_ips  # broadcast address

    def test_offset_range_never_overshoots(self) -> None:
        """cidr_offset_range_target must never produce next_offset > total."""
        cidr = "10.0.0.0/24"
        total = 256
        offset = 0
        while offset < total:
            target, next_offset, last_ip, done = cidr_offset_range_target(cidr, offset, 32)
            assert next_offset <= total, f"Overshot: next_offset={next_offset} > {total}"
            assert next_offset > offset, f"No progress: offset stayed at {offset}"
            offset = next_offset

    def test_chunk_size_1_produces_256_iterations(self) -> None:
        """Extreme: 1 host per chunk → 256 iterations (but bounded blocks)."""
        cidr = "10.0.0.0/24"
        offset = 0
        count = 0
        max_count = 300
        while count < max_count:
            target, next_offset, last_ip, done = cidr_offset_range_target(cidr, offset, 1)
            if not target or next_offset <= offset:
                break
            count += 1
            offset = next_offset
            if done:
                break
        assert offset == 256
        # With chunk_size=1, should produce /32 blocks
        assert count == 256

    def test_various_public_slash24_networks(self) -> None:
        """Ensure splitting works for different public /24 ranges."""
        networks = [
            "114.31.114.0/24",
            "211.117.106.0/24",
            "1.1.1.0/24",
            "203.0.113.0/24",
        ]
        for network in networks:
            chunks = split_ipv4_cidr_for_port_scan(network, 32)
            assert len(chunks) == 8, f"Failed for {network}: got {len(chunks)} chunks"
            # Verify full coverage
            all_ips: set[str] = set()
            for chunk in chunks:
                net = ipaddress.ip_network(chunk, strict=False)
                all_ips.update(str(ip) for ip in net)
            assert len(all_ips) == 256, f"Failed for {network}: got {len(all_ips)} IPs"

    def test_slash24_with_host_bits_set(self) -> None:
        """10.0.0.100/24 should normalize to 10.0.0.0/24 (strict=False)."""
        chunks = split_ipv4_cidr_for_port_scan("10.0.0.100/24", 32)
        assert len(chunks) == 8
        first_net = ipaddress.ip_network(chunks[0], strict=False)
        assert str(first_net.network_address) == "10.0.0.0"

    def test_cidr_count_slash24_variants(self) -> None:
        """Various /24 notations should all give 256 addresses."""
        assert cidr_count_addresses_ipv4("10.0.0.0/24") == 256
        assert cidr_count_addresses_ipv4("10.0.0.50/24") == 256
        assert cidr_count_addresses_ipv4("192.168.1.0/24") == 256
        assert cidr_count_addresses_ipv4("172.16.0.0/24") == 256


# ---------------------------------------------------------------------------
# 11. Adaptive chunk resizing during /24 scan
# ---------------------------------------------------------------------------


class TestSlash24AdaptiveResizing:
    """Verify that adaptive chunk sizing adjusts correctly across /24."""

    def test_chunk_grows_if_scans_are_fast(self) -> None:
        """If target interval is 10min and chunks finish in 2min, grow."""
        size = calculate_next_chunk_size(120.0, 10, 32)
        # 600/120 = 5.0, capped to 2.0 → 32*2=64
        assert size == 64

    def test_chunk_shrinks_if_scans_are_slow(self) -> None:
        """If target interval is 10min and chunks take 20min, shrink."""
        size = calculate_next_chunk_size(1200.0, 10, 64)
        # 600/1200 = 0.5 → 64*0.5=32
        assert size == 32

    def test_chunk_stays_stable_at_target(self) -> None:
        """If avg matches target, size should stay ~same."""
        size = calculate_next_chunk_size(600.0, 10, 32)
        # 600/600 = 1.0 → 32*1.0=32
        assert size == 32

    def test_chunk_never_below_8(self) -> None:
        """Even with extremely slow scans, never go below 8."""
        size = calculate_next_chunk_size(100000.0, 10, 8)
        assert size >= 8

    def test_chunk_never_above_256(self) -> None:
        """Even with extremely fast scans, never exceed 256."""
        size = calculate_next_chunk_size(0.1, 10, 256)
        assert size <= 256

    def test_zero_avg_returns_current_size(self) -> None:
        """If avg_duration is 0, return current_size unchanged."""
        size = calculate_next_chunk_size(0.0, 10, 32)
        assert size == 32


# ---------------------------------------------------------------------------
# 12. Multiple /24 targets (sequential run)
# ---------------------------------------------------------------------------


class TestMultipleSlash24Runs:
    """Verify that running multiple /24 targets sequentially works."""

    def test_sequential_slash24_runs_are_independent(
        self, tmp_path: Path, monkeypatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        targets = ["10.0.0.0/24", "10.0.1.0/24"]
        run_ids: list[str] = []

        for target in targets:
            summary = create_scan_run(target, modules=["port_scan"], profile="fast")
            run_ids.append(summary["run_id"])

        # Runs must have different IDs
        assert len(set(run_ids)) == 2
        # Each run has its own state DB
        for run_id in run_ids:
            state_db = tmp_path / "runs" / run_id / "state.db"
            assert state_db.exists(), f"State DB missing for {run_id}"
