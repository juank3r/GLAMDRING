"""Registro de conectores.

Se instancian de forma perezosa para que importar el paquete no obligue a tener
instalados los SDK de Azure ni httpx: un despliegue que solo use ficheros no
deberia necesitarlos.
"""

from __future__ import annotations

from typing import Dict, List

from .base import Connector, ConnectorError
from .files import FileConnector
from .qradar import QRadarConnector
from .sentinel import SentinelConnector
from .splunk import SplunkConnector

_FACTORIES = {
    "splunk": SplunkConnector,
    "sentinel": SentinelConnector,
    "qradar": QRadarConnector,
    "files": FileConnector,
}

_CACHE: Dict[str, Connector] = {}


def get_connector(name: str) -> Connector:
    key = (name or "").strip().lower()
    if key not in _FACTORIES:
        raise ConnectorError("registry", f"Conector desconocido: '{name}'. "
                                         f"Disponibles: {', '.join(sorted(_FACTORIES))}.")
    if key not in _CACHE:
        _CACHE[key] = _FACTORIES[key]()
    return _CACHE[key]


def describe_all() -> List[dict]:
    return [get_connector(name).describe() for name in sorted(_FACTORIES)]


def reset_cache() -> None:
    """Fuerza a releer la configuracion (util en tests)."""
    _CACHE.clear()


__all__ = [
    "Connector",
    "ConnectorError",
    "FileConnector",
    "SplunkConnector",
    "SentinelConnector",
    "QRadarConnector",
    "get_connector",
    "describe_all",
    "reset_cache",
]
