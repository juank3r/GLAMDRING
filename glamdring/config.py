"""Configuracion por variables de entorno, con carga opcional de ``.env``.

Se lee el ``.env`` a mano en vez de depender de pydantic-settings: son treinta
lineas, elimina una dependencia y hace explicito el orden de precedencia
(entorno real > .env > valor por defecto), que es justo lo que hay que poder
razonar cuando algo no coge las credenciales.

Ningun secreto se expone por la API: ``public_status()`` solo dice si un
conector esta configurado, nunca con que.
"""

from __future__ import annotations

import importlib.util
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Optional

from .receive import (ENVIOS_POR_MINUTO, MAX_BYTES_ENVIO, ReceiveConfig,
                      parse_keys)

BASE_DIR = Path(__file__).resolve().parent.parent
WEB_DIR = BASE_DIR / "web"
SAMPLES_DIR = BASE_DIR / "samples"


def _valor_de(bruto: str) -> str:
    """El valor de una linea del .env, sin el comentario que venga detras.

    UN COMENTARIO EN LINEA APAGABA LA VERIFICACION DE TLS. Antes esto era
    `bruto.strip().strip('"').strip("'")` sin cortar en '#', asi que:

        SPLUNK_VERIFY_TLS=1       # comentario   ->  "1 # comentario"

    y `_env_bool` no reconoce esa cadena, con lo que cae al valor por defecto
    del parametro. En los limites numericos eso degrada de forma benigna, pero
    en el TLS es FAIL-OPEN: el token de servicio del SIEM se entrega en claro al
    primer intermediario que haya por el camino, y el resultado de la consulta se
    puede manipular sin que nada lo indique.

    Y el agravante: el propio .env.example enseñaba ese estilo en cuatro lineas,
    asi que no era un uso raro sino el que documentabamos nosotros.

    Un '#' con comillas alrededor SI es parte del valor: una contrasena puede
    llevarlo, y cortar ahi seria romper credenciales validas.
    """
    texto = bruto.strip()
    if texto[:1] in ("\"", "'"):
        comilla = texto[0]
        cierre = texto.find(comilla, 1)
        if cierre > 0:
            return texto[1:cierre]
        return texto[1:]
    # Sin comillas: el comentario empieza en el primer '#' precedido de espacio,
    # o al principio. Un '#' pegado a un caracter es parte del valor.
    for i, caracter in enumerate(texto):
        if caracter == "#" and (i == 0 or texto[i - 1].isspace()):
            return texto[:i].strip()
    return texto


def load_dotenv(path: Optional[Path] = None) -> Dict[str, str]:
    """Lee ``.env`` y devuelve lo que hay dentro. NO toca os.environ.

    Antes hacia ``os.environ.setdefault(key, value)`` por cada linea, y eso
    metia los tokens de los SIEM en el entorno del proceso: los heredaba
    cualquier subproceso que se lanzara desde aqui, y aparecian en cualquier
    volcado de entorno. El fichero se lee para configurar esta aplicacion, no
    para contaminar todo lo que cuelgue de ella.

    La precedencia se resuelve en ``_env``: entorno real primero, .env despues.
    """
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
        value = _valor_de(value)
        loaded[key] = value
    return loaded


# Lo leido del .env, sin volcarlo al entorno del proceso. Lo rellena
# load_settings() al arrancar.
_DOTENV: Dict[str, str] = {}


def _env(name: str, default: str = "") -> str:
    """Valor de configuracion. Entorno real primero, .env despues.

    Ese orden es el que permite sobrescribir el fichero desde fuera sin
    editarlo, que es como se despliega esto en un servidor.

    Antes la precedencia se conseguia con os.environ.setdefault al leer el
    fichero, y el efecto secundario era meter los tokens de los SIEM en el
    entorno del proceso: los heredaba cualquier subproceso y salian en
    cualquier volcado. Ahora el .env se queda en este diccionario.
    """
    valor = os.environ.get(name)
    if valor is None:
        valor = _DOTENV.get(name, default)
    return (valor or "").strip()


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


def _sdk_azure_disponible() -> bool:
    """True si estan los SDK de Azure, SIN importarlos.

    find_spec mira si el modulo existe y no ejecuta nada suyo. Importar
    azure.identity de verdad aqui costaria casi un segundo en el arranque, y por
    una pregunta que se hace solo para pintar un semaforo.
    """
    return all(importlib.util.find_spec(m) is not None
               for m in ("azure.identity", "azure.monitor.query"))


@dataclass
class SentinelConfig:
    workspace_id: str = ""
    tenant_id: str = ""
    client_id: str = ""
    client_secret: str = ""

    @property
    def explicit_credentials(self) -> bool:
        """Las tres variables que exige la via REST."""
        return bool(self.tenant_id and self.client_id and self.client_secret)

    @property
    def configured(self) -> bool:
        """Si hay ALGUNA via viable, no solo si hay workspace.

        Antes esto era ``bool(self.workspace_id)`` y con eso el semaforo se
        ponia verde poniendo un identificador de workspace y nada mas. Sin SDK
        instalado y sin las variables de Entra ID no hay ninguna forma de
        autenticarse, asi que la consulta fallaba siempre: el analista escribia
        su KQL, esperaba, y recibia un error de credenciales que el semaforo
        llevaba rato asegurando que no existia.
        """
        if not self.workspace_id:
            return False
        if self.explicit_credentials:
            return True
        # Sin credenciales explicitas la unica via es el SDK, que sabe sacarlas
        # de az login o de una identidad administrada.
        return _sdk_azure_disponible()


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
class NetskopeConfig:
    url: str = ""            # https://<tenant>.goskope.com
    token: str = ""          # cabecera Netskope-Api-Token
    # El nombre del iterador. Netskope lleva LA CUENTA por este nombre, asi que
    # dos herramientas con el mismo nombre se pisan el puntero: cada una recibe
    # los eventos que la otra no ha visto y ninguna los ve todos. Por eso el
    # valor por defecto es propio y no algo generico.
    iterator: str = "glamdring"

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)


@dataclass
class ZscalerZpaConfig:
    """Solo ZPA. Los logs web de ZIA no salen por API: los empuja NSS al
    receptor, que es el motivo por el que existe POST /api/receive/{fuente}."""

    url: str = ""            # https://config.private.zscaler.com
    client_id: str = ""
    client_secret: str = ""
    customer_id: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.url and self.client_id and self.client_secret and self.customer_id)


@dataclass
class Settings:
    splunk: SplunkConfig = field(default_factory=SplunkConfig)
    sentinel: SentinelConfig = field(default_factory=SentinelConfig)
    qradar: QRadarConfig = field(default_factory=QRadarConfig)
    netskope: NetskopeConfig = field(default_factory=NetskopeConfig)
    zscaler_zpa: ZscalerZpaConfig = field(default_factory=ZscalerZpaConfig)
    receive: ReceiveConfig = field(default_factory=ReceiveConfig)

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
            "netskope": {"configured": self.netskope.configured,
                         "url": _host_of(self.netskope.url)},
            "zscaler_zpa": {"configured": self.zscaler_zpa.configured,
                            "url": _host_of(self.zscaler_zpa.url)},
            # Los NOMBRES de las fuentes que pueden empujar, nunca sus claves.
            "receive": {"configured": self.receive.enabled,
                        "sources": list(self.receive.sources())},
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
    _DOTENV.clear()
    _DOTENV.update(load_dotenv())
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
        netskope=NetskopeConfig(
            url=_env("NETSKOPE_URL"),
            token=_env("NETSKOPE_TOKEN"),
            iterator=_env("NETSKOPE_ITERATOR", "glamdring"),
        ),
        zscaler_zpa=ZscalerZpaConfig(
            url=_env("ZPA_URL", "https://config.private.zscaler.com"),
            client_id=_env("ZPA_CLIENT_ID"),
            client_secret=_env("ZPA_CLIENT_SECRET"),
            customer_id=_env("ZPA_CUSTOMER_ID"),
        ),
        receive=ReceiveConfig(
            keys=parse_keys(_env("GLAMDRING_RECEIVE_KEYS")),
            max_bytes=_env_int("GLAMDRING_RECEIVE_MAX_BYTES", MAX_BYTES_ENVIO),
            per_minute=_env_int("GLAMDRING_RECEIVE_PER_MINUTE", ENVIOS_POR_MINUTO),
        ),
        query_timeout=_env_int("GLAMDRING_QUERY_TIMEOUT", 120),
        max_results=_env_int("GLAMDRING_MAX_RESULTS", 50_000),
        max_graph_nodes=_env_int("GLAMDRING_MAX_GRAPH_NODES", 1_500),
        allow_file_paths=_env_bool("GLAMDRING_ALLOW_FILE_PATHS", False),
    )


SETTINGS = load_settings()
