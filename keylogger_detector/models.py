"""Dataclasses for scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Iterable


@dataclass
class ProcessFinding:
    pid: int
    name: str
    username: str | None
    cpu_percent: float | None
    memory_percent: float | None
    cmdline: list[str]
    exe: str | None
    reasons: list[str] = field(default_factory=list)


@dataclass
class NetworkFinding:
    pid: int | None
    process_name: str | None
    local_address: str
    remote_address: str
    status: str
    reason: str


@dataclass
class ScanReport:
    started_at: datetime
    ended_at: datetime
    process_findings: list[ProcessFinding] = field(default_factory=list)
    network_findings: list[NetworkFinding] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "started_at": self.started_at.isoformat(),
            "ended_at": self.ended_at.isoformat(),
            "process_findings": [
                {
                    "pid": finding.pid,
                    "name": finding.name,
                    "username": finding.username,
                    "cpu_percent": finding.cpu_percent,
                    "memory_percent": finding.memory_percent,
                    "cmdline": finding.cmdline,
                    "exe": finding.exe,
                    "reasons": finding.reasons,
                }
                for finding in self.process_findings
            ],
            "network_findings": [
                {
                    "pid": finding.pid,
                    "process_name": finding.process_name,
                    "local_address": finding.local_address,
                    "remote_address": finding.remote_address,
                    "status": finding.status,
                    "reason": finding.reason,
                }
                for finding in self.network_findings
            ],
        }


def summarize_reasons(reasons: Iterable[str]) -> list[str]:
    return sorted(set(reasons))
