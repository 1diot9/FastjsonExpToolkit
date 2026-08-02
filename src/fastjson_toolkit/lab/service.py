"""Start / stop / status for Docker labs."""

from __future__ import annotations

import subprocess
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal

from fastjson_toolkit.config import project_root
from fastjson_toolkit.lab.catalog import LabSpec, all_labs, get_lab
from fastjson_toolkit.lab.docker_env import (
    DockerEnvironment,
    PortCheck,
    check_ports,
    compose_argv,
    container_running,
    detect_docker_environment,
)

LabState = Literal["running", "partial", "stopped", "unknown"]


@dataclass
class LabStatus:
    id: str
    name: str
    description: str
    category: str
    compose_rel: str
    services: list[str]
    ports: list[int]
    container_names: list[str]
    endpoints: list[str]
    notes: str
    state: LabState
    containers_running: dict[str, bool | None]
    port_checks: list[PortCheck]
    can_start: bool
    can_stop: bool
    blockers: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return data


@dataclass
class LabActionResult:
    ok: bool
    lab_id: str
    action: str
    message: str
    state: LabState | None = None
    logs: list[str] = field(default_factory=list)
    port_checks: list[PortCheck] = field(default_factory=list)
    docker: DockerEnvironment | None = None
    status: LabStatus | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "lab_id": self.lab_id,
            "action": self.action,
            "message": self.message,
            "state": self.state,
            "logs": self.logs,
            "port_checks": [asdict(p) for p in self.port_checks],
            "docker": asdict(self.docker) if self.docker else None,
            "status": self.status.to_dict() if self.status else None,
        }


def _compose_dir(lab: LabSpec) -> Path:
    return project_root().joinpath(*lab.compose_rel.split("/"))


def _tail_lines(text: str, limit: int = 80) -> list[str]:
    lines = [ln.rstrip() for ln in (text or "").splitlines() if ln.strip()]
    if len(lines) <= limit:
        return lines
    return lines[-limit:]


def _run_compose(
    lab: LabSpec,
    args: list[str],
    *,
    env: DockerEnvironment,
    timeout: float = 600.0,
) -> tuple[int, list[str]]:
    cwd = _compose_dir(lab)
    if not cwd.is_dir():
        raise FileNotFoundError(f"compose 目录不存在: {cwd}")
    compose_file = cwd / "docker-compose.yml"
    if not compose_file.is_file():
        raise FileNotFoundError(f"缺少 docker-compose.yml: {compose_file}")

    cmd = [*compose_argv(env), *args]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            shell=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or "") + "\n" + (exc.stderr or "")
        return 124, _tail_lines(str(out) + f"\n超时 ({timeout:.0f}s): {' '.join(cmd)}")
    except OSError as exc:
        return 1, [f"执行失败: {exc}"]

    merged = "\n".join(
        part for part in (proc.stdout or "", proc.stderr or "") if part
    )
    return proc.returncode, _tail_lines(merged)


def docker_status() -> DockerEnvironment:
    return detect_docker_environment()


def describe_lab(lab: LabSpec, *, env: DockerEnvironment | None = None) -> LabStatus:
    env = env or detect_docker_environment()
    containers: dict[str, bool | None] = {}
    for name in lab.container_names:
        if not env.docker_running:
            containers[name] = None
        else:
            containers[name] = container_running(name)

    running_flags = [v for v in containers.values() if v is True]
    known_false = [v for v in containers.values() if v is False]
    if running_flags and len(running_flags) == len(lab.container_names):
        state: LabState = "running"
    elif running_flags:
        state = "partial"
    elif known_false and len(known_false) == len(lab.container_names):
        state = "stopped"
    elif not env.docker_running:
        state = "unknown"
    else:
        state = "stopped"

    owned_ports = set(lab.ports) if state in ("running", "partial") else set()
    # Also treat ports as owned if containers report running even when connect fails
    if any(containers.values()):
        owned_ports = set(lab.ports)

    port_checks = check_ports(lab.ports, owned_ports=owned_ports)

    blockers: list[str] = []
    if not env.ready:
        blockers.extend(env.errors or ["Docker / Compose 未就绪"])

    foreign = [
        p for p in port_checks if p.occupied and not p.owned_by_lab and state == "stopped"
    ]
    if foreign:
        ports = ", ".join(str(p.port) for p in foreign)
        blockers.append(f"端口已被占用: {ports}")

    can_start = env.ready and state != "running" and not foreign
    # allow start when partial (retry) if no foreign ports
    if state == "partial" and env.ready and not foreign:
        can_start = True
    can_stop = env.ready and state in ("running", "partial")

    return LabStatus(
        id=lab.id,
        name=lab.name,
        description=lab.description,
        category=lab.category,
        compose_rel=lab.compose_rel,
        services=list(lab.services),
        ports=list(lab.ports),
        container_names=list(lab.container_names),
        endpoints=list(lab.endpoints),
        notes=lab.notes,
        state=state,
        containers_running=containers,
        port_checks=port_checks,
        can_start=can_start,
        can_stop=can_stop,
        blockers=blockers,
    )


def list_lab_status(*, env: DockerEnvironment | None = None) -> list[LabStatus]:
    env = env or detect_docker_environment()
    return [describe_lab(lab, env=env) for lab in all_labs()]


def start_lab(lab_id: str, *, build: bool = True, timeout: float = 600.0) -> LabActionResult:
    lab = get_lab(lab_id)
    if lab is None:
        return LabActionResult(
            ok=False,
            lab_id=lab_id,
            action="start",
            message=f"未知靶场 id: {lab_id}",
        )

    env = detect_docker_environment()
    if not env.ready:
        return LabActionResult(
            ok=False,
            lab_id=lab_id,
            action="start",
            message="Docker 环境未就绪，无法启动靶场",
            logs=env.errors,
            docker=env,
            status=describe_lab(lab, env=env),
        )

    status = describe_lab(lab, env=env)
    if status.state == "running":
        return LabActionResult(
            ok=True,
            lab_id=lab_id,
            action="start",
            message="靶场已在运行",
            state=status.state,
            port_checks=status.port_checks,
            docker=env,
            status=status,
        )

    foreign = [
        p
        for p in status.port_checks
        if p.occupied and not p.owned_by_lab
    ]
    if foreign and status.state == "stopped":
        ports = ", ".join(str(p.port) for p in foreign)
        return LabActionResult(
            ok=False,
            lab_id=lab_id,
            action="start",
            message=f"端口占用冲突，请先释放: {ports}",
            state=status.state,
            port_checks=status.port_checks,
            docker=env,
            status=status,
        )

    args = ["up", "-d"]
    if build:
        args.insert(1, "--build")
    args.extend(lab.services)

    code, logs = _run_compose(lab, args, env=env, timeout=timeout)
    new_status = describe_lab(lab, env=env)
    ok = code == 0 and new_status.state in ("running", "partial")
    if code == 0 and new_status.state != "running":
        # compose succeeded but container not yet healthy / still starting
        ok = True
        message = "已提交启动；容器可能仍在初始化，请稍后刷新状态"
    elif ok:
        message = "靶场启动成功"
    else:
        message = f"启动失败（exit={code}）"

    return LabActionResult(
        ok=ok,
        lab_id=lab_id,
        action="start",
        message=message,
        state=new_status.state,
        logs=logs,
        port_checks=new_status.port_checks,
        docker=env,
        status=new_status,
    )


def stop_lab(lab_id: str, *, remove: bool = True, timeout: float = 180.0) -> LabActionResult:
    lab = get_lab(lab_id)
    if lab is None:
        return LabActionResult(
            ok=False,
            lab_id=lab_id,
            action="stop",
            message=f"未知靶场 id: {lab_id}",
        )

    env = detect_docker_environment()
    if not env.ready:
        return LabActionResult(
            ok=False,
            lab_id=lab_id,
            action="stop",
            message="Docker 环境未就绪，无法停止靶场",
            logs=env.errors,
            docker=env,
            status=describe_lab(lab, env=env),
        )

    status = describe_lab(lab, env=env)
    if status.state == "stopped":
        return LabActionResult(
            ok=True,
            lab_id=lab_id,
            action="stop",
            message="靶场已停止",
            state=status.state,
            port_checks=status.port_checks,
            docker=env,
            status=status,
        )

    # Prefer stop+rm for shared root compose so sibling services stay up.
    # Subdirectory labs can use down.
    if lab.compose_rel == "lab":
        args = ["stop", *lab.services]
        code, logs = _run_compose(lab, args, env=env, timeout=timeout)
        if code == 0 and remove:
            rm_code, rm_logs = _run_compose(
                lab, ["rm", "-f", *lab.services], env=env, timeout=60.0
            )
            logs = logs + rm_logs
            code = rm_code if rm_code != 0 else code
    else:
        args = ["down"] if remove else ["stop", *lab.services]
        code, logs = _run_compose(lab, args, env=env, timeout=timeout)

    new_status = describe_lab(lab, env=env)
    ok = code == 0 and new_status.state == "stopped"
    return LabActionResult(
        ok=ok or (code == 0),
        lab_id=lab_id,
        action="stop",
        message="靶场已停止" if new_status.state == "stopped" else f"停止完成（exit={code}）",
        state=new_status.state,
        logs=logs,
        port_checks=new_status.port_checks,
        docker=env,
        status=new_status,
    )
