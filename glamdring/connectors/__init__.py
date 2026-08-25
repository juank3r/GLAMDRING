"""Registro de conectores.

Se instancian de forma perezosa para que importar el paquete no obligue a tener
instalados los SDK de Azure ni httpx: un despliegue que solo use ficheros no
deberia necesitarlos.

Y se GUARDAN, que ahora importa mas que antes: desde el contrato v2 un conector
mantiene abierto su cliente HTTP entre consultas. Por eso hay ``close_all``, que
llama el apagado de la aplicacion.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Dict, List

from .base import Connector, ConnectorError, FetchResult, Health, HttpConnector
from .files import FileConnector
from .qradar import QRadarConnector
from .sentinel import SentinelConnector
from .splunk import SplunkConnector

log = logging.getLogger("glamdring.connectors")

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


async def ping_all() -> Dict[str, dict]:
    """Comprueba todos a la vez.

    En paralelo y no en serie: son cuatro llamadas de red independientes, y
    encadenarlas convertiria un semaforo de medio segundo en uno de cuarenta
    cuando dos SIEM esten caidos y haya que esperar a que agoten su tiempo.
    """
    nombres = sorted(_FACTORIES)
    resultados = await asyncio.gather(
        *(get_connector(nombre).ping() for nombre in nombres),
        return_exceptions=True,
    )

    salida: Dict[str, dict] = {}
    for nombre, resultado in zip(nombres, resultados):
        if isinstance(resultado, BaseException):
            # Un ping que revienta es un conector caido, no un fallo del
            # servidor: se cuenta como rojo y se sigue con los demas.
            log.warning("El ping de %s lanzo %s", nombre, resultado)
            salida[nombre] = Health(ok=False, detail=f"Error comprobando: {resultado}",
                                    probed=True).as_dict()
        else:
            salida[nombre] = resultado.as_dict()
    return salida


async def close_all() -> None:
    """Cierra los clientes HTTP abiertos. Lo llama el apagado de la aplicacion."""
    conectores = list(_CACHE.values())
    _CACHE.clear()
    for conector in conectores:
        try:
            await conector.close()
        except Exception:  # pragma: no cover - cerrar no debe romper el apagado
            log.debug("Fallo cerrando el conector %s", getattr(conector, "name", "?"))


def reset_cache() -> None:
    """Fuerza a releer la configuracion (util en tests).

    Version sincrona: solo suelta las referencias. Si hubiera clientes abiertos
    hay que preferir ``close_all``, que ademas los cierra.
    """
    _CACHE.clear()


__all__ = [
    "Connector",
    "ConnectorError",
    "FetchResult",
    "Health",
    "HttpConnector",
    "FileConnector",
    "SplunkConnector",
    "SentinelConnector",
    "QRadarConnector",
    "get_connector",
    "describe_all",
    "ping_all",
    "close_all",
    "reset_cache",
]
