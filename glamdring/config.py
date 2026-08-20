"""Configuracion por variables de entorno, con carga opcional de ``.env``.

Se lee el ``.env`` a mano en vez de depender de pydantic-settings: son treinta
lineas, elimina una dependencia y hace explicito el orden de precedencia
(entorno real > .env > valor por defecto), que es justo lo que hay que poder
razonar cuando algo no coge las credenciales.

Ningun secreto se expone por la API: ``public_status()`` solo dice si un
conector esta configurado, nunca con que.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
SAMPLES_DIR = BASE_DIR / "samples"


def load_dotenv(path: Optional[Path] = None) -> Dict[str, str]:
    """Carga ``.env`` sin pisar lo que ya venga del entorno real."""
    env_path = path or (BASE_DIR / ".env")
    loaded: Dict[str, str] = {}
    if not env_path.exists():
        return loaded
    for line in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        loaded[key] = value
        os.environ.setdefault(key, value)
    return loaded


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip()


def _env_bool(name: str, default: bool = False) -> bool:
    value = _env(name).lower()
    if not value:
        return default
    return value in ("1", "true", "yes", "on", "si")


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name) or default)
    except ValueError:
        return default


@dataclass
class SplunkConfig:
    url: str = ""            # https://splunk.corp:8089
    token: str = ""          # token de autenticacion (Splunk <token>)
    username: str = ""
    password: str = ""
    verify_tls: bool = True  # los on-prem suelen llevar certificado autofirmado
    app: str = "search"

    @property
    def configured(self) -> bool:
        return bool(self.url and (self.token or (self.username and self.password)))


@dataclass
class SentinelConfig:
    workspace_id: str = ""
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.workspace_id)


@dataclass
class QRadarConfig:
    url: str = ""            # https://qradar.corp
    token: str = ""          # cabecera SEC
    api_version: str = "20.0"
    verify_tls: bool = True

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)


@dataclass
class Settings:
    splunk: SplunkConfig = field(default_factory=SplunkConfig)
    sentinel: SentinelConfig = field(default_factory=SentinelConfig)
    qradar: QRadarConfig = field(default_factory=QRadarConfig)

    query_timeout: int = 120       # segundos por consulta al SIEM
    max_results: int = 50_000      # tope duro de eventos por consulta
    max_graph_nodes: int = 1_500   # por encima, el navegador sufre
    allow_file_paths: bool = False  # permitir ingesta desde rutas del servidor

    def public_status(self) -> Dict[str, Any]:
        """Lo que la API puede contar del estado sin filtrar credenciales."""
        return {
            "splunk": {"configured": self.splunk.configured, "url": _host_of(self.splunk.url)},
            "sentinel": {"configured": self.sentinel.configured,
                         "workspace": _mask(self.sentinel.workspace_id)},
            "qradar": {"configured": self.qradar.configured, "url": _host_of(self.qradar.url)},
            "files": {"configured": True},
        }


def _host_of(url: str) -> str:
    if not url:
        return ""
    return url.split("//")[-1].split("/")[0]


def _mask(value: str) -> str:
    if not value:
        return ""
    return f"{value[:4]}...{value[-4:]}" if len(value) > 10 else "***"


def load_settings() -> Settings:
    load_dotenv()
    return Settings(
        splunk=SplunkConfig(
            url=_env("SPLUNK_URL"),
            token=_env("SPLUNK_TOKEN"),
            username=_env("SPLUNK_USERNAME"),
            password=_env("SPLUNK_PASSWORD"),
            verify_tls=_env_bool("SPLUNK_VERIFY_TLS", True),
            app=_env("SPLUNK_APP", "search"),
        ),
        sentinel=SentinelConfig(
            workspace_id=_env("SENTINEL_WORKSPACE_ID"),
            tenant_id=_env("AZURE_TENANT_ID"),
            client_id=_env("AZURE_CLIENT_ID"),
            client_secret=_env("AZURE_CLIENT_SECRET"),
        ),
        qradar=QRadarConfig(
            url=_env("QRADAR_URL"),
            token=_env("QRADAR_TOKEN"),
            api_version=_env("QRADAR_API_VERSION", "20.0"),
            verify_tls=_env_bool("QRADAR_VERIFY_TLS", True),
        ),
        query_timeout=_env_int("GLAMDRING_QUERY_TIMEOUT", 120),
        max_results=_env_int("GLAMDRING_MAX_RESULTS", 50_000),
        max_graph_nodes=_env_int("GLAMDRING_MAX_GRAPH_NODES", 1_500),
        allow_file_paths=_env_bool("GLAMDRING_ALLOW_FILE_PATHS", False),
    )


SETTINGS = load_settings()
