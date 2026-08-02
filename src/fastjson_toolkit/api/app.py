"""FastAPI application."""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from scalar_fastapi import Theme, get_scalar_api_reference

from fastjson_toolkit import __version__
from fastjson_toolkit.api.schemas import (
    DepsRequest,
    DetectRequest,
    HealthResponse,
    SettingsResponse,
    SettingsUpdateRequest,
    SettingsUpdateResponse,
    VersionRequest,
)
from fastjson_toolkit.config import (
    load_dotenv,
    mask_secret,
    normalize_ceye_identifier,
    resolve_dotenv_path,
    update_dotenv,
)
from fastjson_toolkit.deps import DepsResult, FastjsonDepsDetector, default_catalog
from fastjson_toolkit.detect import DetectResult, FastjsonDetector
from fastjson_toolkit.detect.probes import all_probes
from fastjson_toolkit.dnslog import CeyeClient, CeyeConfig
from fastjson_toolkit.version import FastjsonVersionDetector, VersionResult, all_version_probes

API_DESCRIPTION = """
FastjsonExpToolkit 后端 API：识别、版本探测、依赖探测、设置与探针编排。

## 文档入口

| 路径 | 说明 |
|------|------|
| `/api/docs` | **Scalar**（推荐） |
| `/api/swagger` | Swagger UI |
| `/api/redoc` | ReDoc |
| `/api/openapi.json` | OpenAPI JSON |
"""


def _settings_response() -> SettingsResponse:
    cfg = CeyeConfig.from_env()
    env_path = resolve_dotenv_path()
    if cfg is None:
        return SettingsResponse(
            ceye_token_set=False,
            ceye_token_masked="",
            ceye_identifier="",
            ceye_domain="",
            env_path=str(env_path),
        )
    try:
        identifier, domain = normalize_ceye_identifier(cfg.domain)
    except ValueError:
        identifier, domain = cfg.domain.split(".", 1)[0], cfg.domain
    return SettingsResponse(
        ceye_token_set=True,
        ceye_token_masked=mask_secret(cfg.token),
        ceye_identifier=identifier,
        ceye_domain=domain,
        env_path=str(env_path),
    )


def create_app() -> FastAPI:
    load_dotenv()
    app = FastAPI(
        title="FastjsonExpToolkit API",
        version=__version__,
        description=API_DESCRIPTION,
        docs_url="/api/swagger",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        swagger_ui_parameters={"persistAuthorization": True},
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    @app.get("/api/docs", include_in_schema=False)
    def api_docs():
        """Scalar API Reference（第三方文档 UI）。"""
        return get_scalar_api_reference(
            openapi_url=app.openapi_url,
            title=f"{app.title} · Docs",
            theme=Theme.KEPLER,
            dark_mode=True,
            hide_download_button=False,
            show_sidebar=True,
            default_open_all_tags=True,
        )

    @app.get(
        "/api/health",
        response_model=HealthResponse,
        tags=["system"],
        summary="健康检查",
    )
    def health() -> HealthResponse:
        cfg = CeyeConfig.from_env()
        return HealthResponse(
            status="ok",
            version=__version__,
            ceye_configured=cfg is not None,
            ceye_domain=cfg.domain if cfg else None,
        )

    @app.get(
        "/api/settings",
        response_model=SettingsResponse,
        tags=["settings"],
        summary="读取 CEYE 设置",
    )
    def get_settings() -> SettingsResponse:
        return _settings_response()

    @app.put(
        "/api/settings",
        response_model=SettingsUpdateResponse,
        tags=["settings"],
        summary="保存 CEYE 设置",
    )
    def update_settings(req: SettingsUpdateRequest) -> SettingsUpdateResponse:
        try:
            identifier, domain = normalize_ceye_identifier(req.ceye_identifier)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        current = CeyeConfig.from_env()
        token = (req.ceye_token or "").strip()
        if not token:
            token = current.token if current else ""
        if not token:
            raise HTTPException(status_code=400, detail="请填写 CEYE Token")

        env_path = update_dotenv(
            {
                "CEYE_TOKEN": token,
                "CEYE_DOMAIN": domain,
            }
        )
        return SettingsUpdateResponse(
            ok=True,
            message=f"已写入 {env_path}",
            settings=SettingsResponse(
                ceye_token_set=True,
                ceye_token_masked=mask_secret(token),
                ceye_identifier=identifier,
                ceye_domain=domain,
                env_path=str(env_path),
            ),
        )

    @app.post(
        "/api/settings/ceye-test",
        tags=["settings"],
        summary="测试 CEYE API",
    )
    def test_ceye() -> dict[str, Any]:
        cfg = CeyeConfig.from_env()
        if cfg is None:
            raise HTTPException(status_code=400, detail="未配置 CEYE Token")
        try:
            with CeyeClient(cfg) as client:
                records = client.query("dns", filter_text="")
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"CEYE 连接失败: {exc}") from exc
        return {
            "ok": True,
            "domain": cfg.domain,
            "record_count": len(records),
            "message": "CEYE API 可用",
        }

    @app.get(
        "/api/probes",
        tags=["detect"],
        summary="列出识别探针",
    )
    def list_probes(dnslog: str | None = None) -> list[dict[str, Any]]:
        return [
            {
                "id": p.id,
                "category": p.category,
                "description": p.description,
                "prefer_typed": p.prefer_typed,
                "dns_related": p.dns_related,
                "payload": p.payload,
                "weight": p.weight,
                "non_exclusive": p.non_exclusive,
            }
            for p in all_probes(dnslog)
        ]

    @app.post(
        "/api/detect",
        response_model=DetectResult,
        tags=["detect"],
        summary="Fastjson 识别",
    )
    def detect(req: DetectRequest) -> DetectResult:
        target = req.target.strip()
        if not target:
            raise HTTPException(status_code=400, detail="target 不能为空")

        ceye_cfg = None
        if req.include_dns and req.use_ceye:
            env_cfg = CeyeConfig.from_env()
            token = req.ceye_token or (env_cfg.token if env_cfg else None)
            domain = req.ceye_domain or (env_cfg.domain if env_cfg else "hpdth2.ceye.io")
            if token:
                ceye_cfg = CeyeConfig(token=token, domain=domain)

        detector = FastjsonDetector(
            timeout=req.timeout,
            headers=req.headers or None,
            proxy=req.proxy,
            verify_tls=not req.insecure,
            dnslog_host=req.dnslog,
            ceye=ceye_cfg,
            ceye_wait=req.ceye_wait,
            timing_threshold_ms=req.timing_threshold_ms,
            content_type=req.content_type,
        )
        try:
            return detector.detect(target, include_dns=req.include_dns)
        except Exception as exc:  # noqa: BLE001 — surface to client
            raise HTTPException(status_code=502, detail=f"探测失败: {exc}") from exc
        finally:
            detector.close()

    @app.get(
        "/api/version/probes",
        tags=["version"],
        summary="列出版本探针",
    )
    def list_version_probes(dnslog: str | None = None) -> list[dict[str, Any]]:
        hosts = None
        if dnslog:
            from fastjson_toolkit.version.probes import validate_dns_host

            try:
                base = validate_dns_host(dnslog)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc)) from exc
            hosts = {
                "le47": f"le47.{base}",
                "le68": f"le68.{base}",
                "d80a": f"d80a.{base}",
                "d80b": f"d80b.{base}",
            }
        return [
            {
                "id": p.id,
                "category": p.category,
                "description": p.description,
                "dns_related": p.dns_related,
                "dns_tags": list(p.dns_tags),
                "payload": p.payload,
            }
            for p in all_version_probes(hosts)
        ]

    @app.post(
        "/api/version",
        response_model=VersionResult,
        tags=["version"],
        summary="Fastjson 版本探测",
    )
    def version_detect(req: VersionRequest) -> VersionResult:
        target = req.target.strip()
        if not target:
            raise HTTPException(status_code=400, detail="target 不能为空")

        ceye_cfg = None
        if req.include_dns and req.use_ceye:
            env_cfg = CeyeConfig.from_env()
            token = req.ceye_token or (env_cfg.token if env_cfg else None)
            domain = req.ceye_domain or (env_cfg.domain if env_cfg else "hpdth2.ceye.io")
            if token:
                ceye_cfg = CeyeConfig(token=token, domain=domain)

        detector = FastjsonVersionDetector(
            timeout=req.timeout,
            headers=req.headers or None,
            proxy=req.proxy,
            verify_tls=not req.insecure,
            dnslog_host=req.dnslog,
            ceye=ceye_cfg,
            ceye_wait=req.ceye_wait,
            content_type=req.content_type,
        )
        try:
            return detector.detect(target, include_dns=req.include_dns)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"版本探测失败: {exc}") from exc
        finally:
            detector.close()

    @app.get(
        "/api/deps/catalog",
        tags=["deps"],
        summary="列出内置依赖探测类目录",
    )
    def list_deps_catalog() -> list[dict[str, Any]]:
        return [
            {
                "class": e.clazz,
                "description": e.description,
                "category": e.category,
            }
            for e in default_catalog()
        ]

    @app.post(
        "/api/deps",
        response_model=DepsResult,
        tags=["deps"],
        summary="Fastjson 依赖探测",
    )
    def deps_detect(req: DepsRequest) -> DepsResult:
        target = req.target.strip()
        if not target:
            raise HTTPException(status_code=400, detail="target 不能为空")

        method = (req.method or "character").strip().lower()
        if method not in ("character", "dns"):
            raise HTTPException(
                status_code=400, detail="method 仅支持 character 或 dns"
            )

        ceye_cfg = None
        if method == "dns" and req.use_ceye:
            env_cfg = CeyeConfig.from_env()
            token = req.ceye_token or (env_cfg.token if env_cfg else None)
            domain = req.ceye_domain or (env_cfg.domain if env_cfg else "hpdth2.ceye.io")
            if token:
                ceye_cfg = CeyeConfig(token=token, domain=domain)

        detector = FastjsonDepsDetector(
            timeout=req.timeout,
            headers=req.headers or None,
            proxy=req.proxy,
            verify_tls=not req.insecure,
            dnslog_host=req.dnslog,
            ceye=ceye_cfg,
            ceye_wait=req.ceye_wait,
            content_type=req.content_type,
            concurrency=req.concurrency,
        )
        try:
            return detector.scan(
                target,
                method=method,
                classes=req.classes or None,
                categories=req.categories or None,
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"依赖探测失败: {exc}") from exc
        finally:
            detector.close()

    return app


app = create_app()
