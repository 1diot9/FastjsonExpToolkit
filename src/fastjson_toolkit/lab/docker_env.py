"""Docker / Compose availability and host port checks."""

from __future__ import annotations

import shutil
import socket
import subprocess
from dataclasses import dataclass, field
from typing import Sequence


@dataclass
class DockerEnvironment:
    docker_installed: bool
    docker_running: bool
    compose_available: bool
    compose_backend: str | None  # "docker compose" | "docker-compose"
    docker_version: str | None = None
    compose_version: str | None = None
    engine_info: str | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def ready(self) -> bool:
        return self.docker_installed and self.docker_running and self.compose_available


@dataclass
class PortCheck:
    port: int
    host: str
    occupied: bool
    owned_by_lab: bool = False
    detail: str = ""


def _run(
    cmd: list[str],
    *,
    timeout: float = 15.0,
    cwd: str | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        cwd=cwd,
        shell=False,
    )


def _first_line(text: str) -> str:
    for line in (text or "").splitlines():
        line = line.strip()
        if line:
            return line
    return ""


def detect_docker_environment() -> DockerEnvironment:
    errors: list[str] = []
    docker_bin = shutil.which("docker")
    compose_legacy = shutil.which("docker-compose")

    if not docker_bin:
        errors.append("未找到 docker 可执行文件，请安装 Docker Desktop / Docker Engine")
        return DockerEnvironment(
            docker_installed=False,
            docker_running=False,
            compose_available=False,
            compose_backend=None,
            errors=errors,
        )

    docker_version: str | None = None
    try:
        ver = _run([docker_bin, "version", "--format", "{{.Client.Version}}"], timeout=10)
        if ver.returncode == 0 and ver.stdout.strip():
            docker_version = ver.stdout.strip()
        else:
            # fallback plain version
            ver2 = _run([docker_bin, "--version"], timeout=10)
            docker_version = _first_line(ver2.stdout) or None
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"执行 docker version 失败: {exc}")
        return DockerEnvironment(
            docker_installed=True,
            docker_running=False,
            compose_available=False,
            compose_backend=None,
            docker_version=None,
            errors=errors,
        )

    docker_running = False
    engine_info: str | None = None
    try:
        info = _run(
            [docker_bin, "info", "--format", "{{.ServerVersion}}"],
            timeout=12,
        )
        if info.returncode == 0 and info.stdout.strip():
            docker_running = True
            engine_info = f"Server {info.stdout.strip()}"
        else:
            err = (info.stderr or info.stdout or "").strip()
            errors.append(
                err or "Docker daemon 未运行（请启动 Docker Desktop / dockerd）"
            )
    except (OSError, subprocess.TimeoutExpired) as exc:
        errors.append(f"执行 docker info 失败: {exc}")

    compose_backend: str | None = None
    compose_version: str | None = None
    if docker_running:
        try:
            plugin = _run([docker_bin, "compose", "version"], timeout=10)
            if plugin.returncode == 0:
                compose_backend = "docker compose"
                compose_version = _first_line(plugin.stdout) or _first_line(plugin.stderr)
        except (OSError, subprocess.TimeoutExpired):
            pass

        if compose_backend is None and compose_legacy:
            try:
                legacy = _run([compose_legacy, "version"], timeout=10)
                if legacy.returncode == 0:
                    compose_backend = "docker-compose"
                    compose_version = _first_line(legacy.stdout) or _first_line(
                        legacy.stderr
                    )
            except (OSError, subprocess.TimeoutExpired):
                pass

        if compose_backend is None:
            errors.append("未找到 docker compose / docker-compose")

    return DockerEnvironment(
        docker_installed=True,
        docker_running=docker_running,
        compose_available=compose_backend is not None,
        compose_backend=compose_backend,
        docker_version=docker_version,
        compose_version=compose_version,
        engine_info=engine_info,
        errors=errors,
    )


def compose_argv(env: DockerEnvironment | None = None) -> list[str]:
    """Return argv prefix for compose commands, e.g. ['docker','compose']."""
    env = env or detect_docker_environment()
    if env.compose_backend == "docker compose":
        docker_bin = shutil.which("docker") or "docker"
        return [docker_bin, "compose"]
    if env.compose_backend == "docker-compose":
        legacy = shutil.which("docker-compose") or "docker-compose"
        return [legacy]
    raise RuntimeError("Docker Compose 不可用")


def is_port_listening(port: int, host: str = "127.0.0.1", timeout: float = 0.5) -> bool:
    """True if something accepts TCP connections on host:port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        try:
            return s.connect_ex((host, port)) == 0
        except OSError:
            return False


def is_port_bound(port: int, host: str = "0.0.0.0") -> bool:
    """
    True if the host cannot bind the TCP port (likely already reserved).
    Prefer this for Docker publish conflict checks on Windows.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((host, port))
        except OSError:
            return True
    return False


def is_port_occupied(port: int, host: str = "127.0.0.1") -> bool:
    """Occupied if listening or bind to 0.0.0.0 fails."""
    if is_port_listening(port, host=host):
        return True
    if is_port_bound(port, host="0.0.0.0"):
        return True
    # Also check loopback-only listeners that may not block 0.0.0.0 on some stacks
    return is_port_bound(port, host=host)


def check_ports(
    ports: Sequence[int],
    *,
    host: str = "127.0.0.1",
    owned_ports: set[int] | None = None,
) -> list[PortCheck]:
    owned = owned_ports or set()
    results: list[PortCheck] = []
    for port in ports:
        occupied = is_port_occupied(port, host=host)
        ours = occupied and port in owned
        if not occupied:
            detail = "空闲"
        elif ours:
            detail = "已被本靶场占用"
        else:
            detail = "已被其他进程占用"
        results.append(
            PortCheck(
                port=port,
                host=host,
                occupied=occupied,
                owned_by_lab=ours,
                detail=detail,
            )
        )
    return results


def container_running(name: str, *, timeout: float = 10.0) -> bool | None:
    """
    Return True/False if inspect succeeds; None if docker unavailable / error.
    """
    docker_bin = shutil.which("docker")
    if not docker_bin:
        return None
    try:
        proc = _run(
            [
                docker_bin,
                "inspect",
                "-f",
                "{{.State.Running}}",
                name,
            ],
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return False
    return proc.stdout.strip().lower() == "true"
