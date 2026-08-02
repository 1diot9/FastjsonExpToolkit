"""Local Docker lab lifecycle helpers."""

from fastjson_toolkit.lab.catalog import LabPortSpec, LabSpec, all_labs, get_lab
from fastjson_toolkit.lab.docker_env import DockerEnvironment, detect_docker_environment
from fastjson_toolkit.lab.service import (
    LabActionResult,
    LabStatus,
    describe_lab,
    docker_status,
    list_lab_status,
    start_lab,
    stop_lab,
)

__all__ = [
    "DockerEnvironment",
    "LabActionResult",
    "LabPortSpec",
    "LabSpec",
    "LabStatus",
    "all_labs",
    "describe_lab",
    "detect_docker_environment",
    "docker_status",
    "get_lab",
    "list_lab_status",
    "start_lab",
    "stop_lab",
]
