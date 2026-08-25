"""Receptor de logs: la mitad de la ingesta que no se puede consultar.

``POST /api/receive/{fuente}`` con la clave de esa fuente en la cabecera
``X-Glamdring-Key``. Acepta lo mismo que la subida de ficheros -JSON, NDJSON,
CEF, LEEF, syslog- porque es lo que mandan NSS, los reenviadores y los webhooks.

Quien empuja no es una persona con un navegador: es un proceso que reintenta
solo. Por eso los codigos de respuesta importan mas de lo normal.

    401  clave o fuente incorrecta        no reintentes, arregla la clave
    413  envio demasiado grande           trocealo
    429  demasiados envios                reintenta mas tarde
    503  receptor sin configurar          no reintentes
"""

from __future__ import annotations

import logging
from typing import Any, Dict

from fastapi import APIRouter, Header, HTTPException, Request

from ..config import SETTINGS
from ..connectors import ConnectorError, FileConnector
from ..receive import ReceiveError, RateLimiter, authorize
from ..store import STORE
from .routes_ingest import _ingest_records

router = APIRouter(prefix="/api", tags=["receive"])
log = logging.getLogger("glamdring.receive")

# Compartido por todo el proceso: el limite es por fuente, no por conexion.
_LIMITADOR = RateLimiter(SETTINGS.receive.per_minute)

TROZO_BYTES = 256 * 1024


async def _leer_acotado(request: Request, tope: int) -> bytes:
    """Lee el cuerpo cortando EN CUANTO se pasa del limite.

    A trozos y no de una: mirar el tamano despues de ``await request.body()`` es
    comprobarlo cuando el envio ya esta entero en memoria, o sea cuando ya da
    igual. Y no vale fiarse de Content-Length, que lo pone quien envia y puede
    mentir o no venir (Transfer-Encoding: chunked). Lo unico que cuenta es lo
    que llega de verdad.
    """
    trozos = []
    leidos = 0
    async for trozo in request.stream():
        leidos += len(trozo)
        if leidos > tope:
            raise ReceiveError(413, f"Envio demasiado grande: el limite son "
                                    f"{tope // (1024 * 1024)} MB. Trocea el lote.")
        trozos.append(trozo)
    return b"".join(trozos)


@router.post("/receive/{fuente}")
async def receive(
    fuente: str,
    request: Request,
    x_glamdring_key: str = Header(default=""),
) -> Dict[str, Any]:
    """Recibe un lote de logs empujado por una fuente registrada."""
    config = SETTINGS.receive

    try:
        # Autorizar ANTES de leer el cuerpo. Al reves, cualquiera sin clave
        # podria hacernos tragar 50 MB por envio hasta tumbar el proceso: el
        # trabajo caro estaria hecho cuando llegase el 401.
        nombre = authorize(config, fuente, x_glamdring_key)
        _LIMITADOR.check(nombre)
        cuerpo = await _leer_acotado(request, config.max_bytes)
    except ReceiveError as exc:
        raise HTTPException(status_code=exc.status, detail=exc.message) from exc

    if not cuerpo:
        raise HTTPException(status_code=400, detail="Envio vacio.")

    texto = cuerpo.decode("utf-8", errors="replace")
    try:
        registros, formato = FileConnector().read_text(texto)
    except ConnectorError as exc:
        # El contenido NO se devuelve en el error ni se registra: viene de un
        # log, y un log lleva dentro precisamente lo que no se debe copiar a
        # otro sitio.
        log.warning("Envio de '%s' ilegible (%d bytes).", nombre, len(cuerpo))
        raise HTTPException(status_code=400, detail=exc.message) from exc

    resultado = _ingest_records(registros, f"receive:{nombre}")
    resultado["source"] = nombre
    resultado["format"] = formato
    resultado["events"] = len(STORE)
    log.info("Recibidos %d registros de '%s' (%s), %d normalizados.",
             resultado["read"], nombre, formato, resultado["normalized"])
    return resultado


@router.get("/receive")
def receive_status() -> Dict[str, Any]:
    """Que fuentes pueden empujar. Los NOMBRES, nunca las claves."""
    config = SETTINGS.receive
    return {
        "enabled": config.enabled,
        "sources": list(config.sources()),
        "limits": {
            "maxBytes": config.max_bytes,
            "perMinute": config.per_minute,
        },
    }
