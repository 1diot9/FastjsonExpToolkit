"""Start / stop / status for Docker labs."""

from __future__ import annotations

import os
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
    container_published_ports,
    container_running,
    detect_docker_environment,
)

LabState = Literal["running", "partial", "stopped", "unknown"]


@dataclass
class LabPortInfo:
    key: str
    label: str
    default: int
    value: int
    editable: bool = True


@dataclass
class LabStatus:
    id: str
    name: str
    description: str
    category: str
    compose_rel: str
    services: list[str]
    ports: list[int]
    default_ports: list[int]
    port_infos: list[LabPortInfo]
    container_names: list[str]
    endpoints: list[str]
    notes: str
    state: LabState
    containers_running: dict[str, bool | None]
    port_checks: list[PortCheck]
    can_start: bool
    can_stop: bool
    blockers: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


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
    ports: dict[str, int] = field(default_factory=dict)

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
            "ports": self.ports,
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
    extra_env: dict[str, str] | None = None,
) -> tuple[int, list[str]]:
    cwd = _compose_dir(lab)
    if not cwd.is_dir():
        raise FileNotFoundError(f"compose 目录不存在: {cwd}")
    compose_file = cwd / "docker-compose.yml"
    if not compose_file.is_file():
        raise FileNotFoundError(f"缺少 docker-compose.yml: {compose_file}")

    cmd = [*compose_argv(env), *args]
    run_env = os.environ.copy()
    if extra_env:
        run_env.update(extra_env)
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
            env=run_env,
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


def _live_port_map(lab: LabSpec) -> dict[str, int] | None:
    """Resolve actual published host ports from running containers."""
    if not lab.container_names:
        return None
    published = container_published_ports(lab.container_names[0])
    if not published:
        return None
    resolved: dict[str, int] = {}
    for spec in lab.port_specs:
        host = published.get(spec.container_port)
        if host is None:
            return None
        resolved[spec.key] = host
    return resolved


def _normalize_port_overrides(
    lab: LabSpec,
    ports: dict[str, int] | list[int] | None,
) -> dict[str, int]:
    if ports is None:
        return lab.resolve_ports()
    if isinstance(ports, list):
        if len(ports) != len(lab.port_specs):
            raise ValueError(
                f"端口数量不匹配：需要 {len(lab.port_specs)} 个，收到 {len(ports)}"
            )
        overrides = {spec.key: int(port) for spec, port in zip(lab.port_specs, ports)}
        return lab.resolve_ports(overrides)
    if isinstance(ports, dict):
        cleaned = {str(k): int(v) for k, v in ports.items()}
        return lab.resolve_ports(cleaned)
    raise ValueError("ports 须为对象或整数数组")


def _validate_port_values(port_map: dict[str, int]) -> list[str]:
    errors: list[str] = []
    seen: set[int] = set()
    for key, port in port_map.items():
        if port < 1 or port > 65535:
            errors.append(f"{key}={port} 非法")
            continue
        if port in seen:
            errors.append(f"端口重复: {port}")
        seen.add(port)
    return errors


def describe_lab(
    lab: LabSpec,
    *,
    env: DockerEnvironment | None = None,
    desired_ports: dict[str, int] | None = None,
) -> LabStatus:
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

    live = _live_port_map(lab) if state in ("running", "partial") else None
    port_map = live or desired_ports or lab.resolve_ports()
    host_ports = lab.ports_list(port_map)

    owned_ports: set[int] = set()
    if state in ("running", "partial"):
        owned_ports = set(host_ports)

    port_checks = check_ports(host_ports, owned_ports=owned_ports)

    blockers: list[str] = []
    warnings: list[str] = []
    if not env.ready:
        blockers.extend(env.errors or ["Docker / Compose 未就绪"])

    foreign = [
        p
        for p in port_checks
        if p.occupied and not p.owned_by_lab and state == "stopped"
    ]
    if foreign:
        ports = ", ".join(str(p.port) for p in foreign)
        warnings.append(f"默认/当前端口占用: {ports}（可在启动前改端口）")

    # Allow start even when default ports conflict — user can edit ports.
    can_start = env.ready and state != "running"
    if state == "partial" and env.ready:
        can_start = True
    can_stop = env.ready and state in ("running", "partial")

    port_infos = [
        LabPortInfo(
            key=spec.key,
            label=spec.label,
            default=spec.default,
            value=port_map[spec.key],
            editable=state == "stopped",
        )
        for spec in lab.port_specs
    ]

    return LabStatus(
        id=lab.id,
        name=lab.name,
        description=lab.description,
        category=lab.category,
        compose_rel=lab.compose_rel,
        services=list(lab.services),
        ports=host_ports,
        default_ports=list(lab.default_ports),
        port_infos=port_infos,
        container_names=list(lab.container_names),
        endpoints=lab.endpoints_for(port_map),
        notes=lab.notes,
        state=state,
        containers_running=containers,
        port_checks=port_checks,
        can_start=can_start,
        can_stop=can_stop,
        blockers=blockers,
        warnings=warnings,
    )


def list_lab_status(*, env: DockerEnvironment | None = None) -> list[LabStatus]:
    env = env or detect_docker_environment()
    return [describe_lab(lab, env=env) for lab in all_labs()]


def start_lab(
    lab_id: str,
    *,
    build: bool = True,
    timeout: float = 600.0,
    ports: dict[str, int] | list[int] | None = None,
) -> LabActionResult:
    lab = get_lab(lab_id)
    if lab is None:
        return LabActionResult(
            ok=False,
            lab_id=lab_id,
            action="start",
            message=f"未知靶场 id: {lab_id}",
        )

    try:
        port_map = _normalize_port_overrides(lab, ports)
    except ValueError as exc:
        return LabActionResult(
            ok=False,
            lab_id=lab_id,
            action="start",
            message=str(exc),
        )

    value_errors = _validate_port_values(port_map)
    if value_errors:
        return LabActionResult(
            ok=False,
            lab_id=lab_id,
            action="start",
            message="；".join(value_errors),
            ports=port_map,
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
            status=describe_lab(lab, env=env, desired_ports=port_map),
            ports=port_map,
        )

    status = describe_lab(lab, env=env, desired_ports=port_map)
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
            ports={p.key: p.value for p in status.port_infos},
        )

    host_ports = lab.ports_list(port_map)
    port_checks = check_ports(host_ports, owned_ports=set())
    foreign = [p for p in port_checks if p.occupied]
    if foreign and status.state == "stopped":
        ports_txt = ", ".join(str(p.port) for p in foreign)
        return LabActionResult(
            ok=False,
            lab_id=lab_id,
            action="start",
            message=f"端口占用冲突，请改端口后重试: {ports_txt}",
            state=status.state,
            port_checks=port_checks,
            docker=env,
            status=describe_lab(lab, env=env, desired_ports=port_map),
            ports=port_map,
        )

    args = ["up", "-d"]
    if build:
        args.insert(1, "--build")
    args.extend(lab.services)

    code, logs = _run_compose(
        lab,
        args,
        env=env,
        timeout=timeout,
        extra_env=lab.compose_env(port_map),
    )
    new_status = describe_lab(lab, env=env, desired_ports=port_map)
    ok = code == 0 and new_status.state in ("running", "partial")
    if code == 0 and new_status.state != "running":
        ok = True
        message = "已提交启动；容器可能仍在初始化，请稍后刷新状态"
    elif ok:
        used = ", ".join(
            f"{info.label}={info.value}" for info in new_status.port_infos
        )
        message = f"靶场启动成功（{used}）"
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
        ports={p.key: p.value for p in new_status.port_infos},
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
    # Pass default compose env so interpolation still works if compose re-reads file.
    extra_env = lab.compose_env()
    if lab.compose_rel == "lab":
        args = ["stop", *lab.services]
        code, logs = _run_compose(
            lab, args, env=env, timeout=timeout, extra_env=extra_env
        )
        if code == 0 and remove:
            rm_code, rm_logs = _run_compose(
                lab,
                ["rm", "-f", *lab.services],
                env=env,
                timeout=60.0,
                extra_env=extra_env,
            )
            logs = logs + rm_logs
            code = rm_code if rm_code != 0 else code
    else:
        args = ["down"] if remove else ["stop", *lab.services]
        code, logs = _run_compose(
            lab, args, env=env, timeout=timeout, extra_env=extra_env
        )

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
