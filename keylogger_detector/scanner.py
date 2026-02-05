"""Scanning logic for potential keylogger activity."""

from __future__ import annotations

import json
import time
from dataclasses import asdict
from datetime import datetime
from typing import Iterable

import psutil

from .config import (
    CPU_PERCENT_THRESHOLD,
    DEFAULT_SAMPLE_INTERVAL,
    EXFILTRATION_PORTS,
    MEMORY_PERCENT_THRESHOLD,
    SUSPICIOUS_KEYWORDS,
)
from .models import NetworkFinding, ProcessFinding, ScanReport, summarize_reasons


def _match_keywords(text: str, keywords: Iterable[str]) -> list[str]:
    lowered = text.lower()
    return [keyword for keyword in keywords if keyword in lowered]


def _process_cpu_samples(sample_interval: float) -> dict[int, float]:
    processes = []
    for proc in psutil.process_iter():
        try:
            proc.cpu_percent(None)
            processes.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    time.sleep(sample_interval)

    cpu_samples: dict[int, float] = {}
    for proc in processes:
        try:
            cpu_samples[proc.pid] = proc.cpu_percent(None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return cpu_samples


def scan_processes(sample_interval: float = DEFAULT_SAMPLE_INTERVAL) -> list[ProcessFinding]:
    cpu_samples = _process_cpu_samples(sample_interval)
    findings: list[ProcessFinding] = []

    for proc in psutil.process_iter(
        ["pid", "name", "username", "memory_percent", "exe", "cmdline"]
    ):
        try:
            info = proc.info
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

        reasons: list[str] = []
        name = info.get("name") or ""
        cmdline = info.get("cmdline") or []
        exe = info.get("exe")
        username = info.get("username")
        memory_percent = info.get("memory_percent")
        cpu_percent = cpu_samples.get(proc.pid)

        keyword_hits = _match_keywords(" ".join([name, *cmdline]), SUSPICIOUS_KEYWORDS)
        if keyword_hits:
            reasons.append(f"Keyword match: {', '.join(keyword_hits)}")

        if cpu_percent is not None and cpu_percent >= CPU_PERCENT_THRESHOLD:
            reasons.append(f"High CPU usage: {cpu_percent:.1f}%")

        if memory_percent is not None and memory_percent >= MEMORY_PERCENT_THRESHOLD:
            reasons.append(f"High memory usage: {memory_percent:.1f}%")

        if reasons:
            findings.append(
                ProcessFinding(
                    pid=proc.pid,
                    name=name,
                    username=username,
                    cpu_percent=cpu_percent,
                    memory_percent=memory_percent,
                    cmdline=cmdline,
                    exe=exe,
                    reasons=summarize_reasons(reasons),
                )
            )

    return findings


def scan_network() -> list[NetworkFinding]:
    findings: list[NetworkFinding] = []

    for connection in psutil.net_connections(kind="inet"):
        laddr = connection.laddr
        raddr = connection.raddr
        if not laddr or not raddr:
            continue
        local_port = laddr.port
        remote_port = raddr.port

        if local_port not in EXFILTRATION_PORTS and remote_port not in EXFILTRATION_PORTS:
            continue

        process_name = None
        if connection.pid:
            try:
                process_name = psutil.Process(connection.pid).name()
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                process_name = None

        findings.append(
            NetworkFinding(
                pid=connection.pid,
                process_name=process_name,
                local_address=f"{laddr.ip}:{laddr.port}",
                remote_address=f"{raddr.ip}:{raddr.port}",
                status=connection.status,
                reason="Potential data exfiltration port usage",
            )
        )

    return findings


def run_scan(sample_interval: float = DEFAULT_SAMPLE_INTERVAL) -> ScanReport:
    started_at = datetime.utcnow()
    process_findings = scan_processes(sample_interval)
    network_findings = scan_network()
    ended_at = datetime.utcnow()
    return ScanReport(
        started_at=started_at,
        ended_at=ended_at,
        process_findings=process_findings,
        network_findings=network_findings,
    )


def report_to_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=True)
