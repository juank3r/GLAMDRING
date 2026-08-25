"""Conector a IBM QRadar (Ariel + ofensas).

Ariel no es sincrono: se crea una busqueda, se sondea hasta que termina y
entonces se piden los resultados. Los tres pasos estan aqui porque separarlos no
aporta nada: fuera de este fichero nadie sabe que existe un ``search_id``.

Autenticacion por cabecera ``SEC`` con un token de servicio. La cabecera
``Version`` es obligatoria y determina el esquema de respuesta, asi que se fija
por configuracion en lugar de dejarla a lo que traiga el servidor por defecto.
"""

from __future__ import annotations

import asyncio
import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from ..config import SETTINGS, QRadarConfig
from .base import PING_TIMEOUT, ConnectorError, FetchResult, Health, HttpConnector

_POLL_SECONDS = 1.5
_TERMINAL_ERROR_STATES = {"ERROR", "CANCELED"}

# Content-Range: items 0-49/1000
_RANGO = re.compile(r"items\s+\d+\s*-\s*\d+\s*/\s*(\d+)", re.IGNORECASE)


class QRadarConnector(HttpConnector):
    name = "qradar"
    query_language = "AQL"
    example_query = (
        "SELECT starttime, sourceip, destinationip, username, qidname(qid), magnitude, "
        "categoryname(category) FROM events LAST 24 HOURS LIMIT 5000"
    )

    def __init__(self, config: Optional[QRadarConfig] = None) -> None:
        super().__init__()
        self.config = config or SETTINGS.qradar

    @property
    def configured(self) -> bool:
        return self.config.configured

    def _headers(self) -> Dict[str, str]:
        return {
            "SEC": self.config.token,
            "Version": self.config.api_version,
            "Accept": "application/json",
        }

    def _client_kwargs(self) -> Dict[str, Any]:
        return {
            "verify": self.config.verify_tls,
            "timeout": SETTINGS.query_timeout,
            "headers": self._headers(),
        }

    async def fetch(
        self,
        query: str,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 10_000,
        cursor: Optional[str] = None,
    ) -> FetchResult:
        if not self.configured:
            raise ConnectorError(self.name, "QRadar no esta configurado (QRADAR_URL / QRADAR_TOKEN).")

        aql = _apply_window(query.strip(), time_from, time_to)
        base = self.config.url.rstrip("/")
        tope = max(1, min(limit, SETTINGS.max_results))
        client = self._client()

        # Las ofensas se piden por su propio endpoint, no por Ariel.
        if aql.lower().startswith("offenses"):
            return await self._fetch_offenses(client, base, tope)

        create = await client.post(f"{base}/api/ariel/searches",
                                   params={"query_expression": aql})
        if create.status_code >= 400:
            raise ConnectorError(self.name, f"AQL rechazada: {create.text[:300]}",
                                 status=create.status_code)
        search_id = create.json().get("search_id")
        if not search_id:
            raise ConnectorError(self.name, "QRadar no devolvio search_id.")

        status = await self._wait(client, base, search_id)
        if status in _TERMINAL_ERROR_STATES:
            raise ConnectorError(self.name, f"La busqueda termino en estado {status}.")

        # items=0-tope son tope+1 elementos: el ultimo es el testigo que dice si
        # habia mas. Se descarta al entregar.
        results = await client.get(
            f"{base}/api/ariel/searches/{search_id}/results",
            headers={"Range": f"items=0-{tope}"},
        )
        if results.status_code >= 400:
            raise ConnectorError(self.name, f"HTTP {results.status_code}: {results.text[:300]}",
                                 status=results.status_code)
        payload = results.json()
        total = _total_de(results.headers.get("Content-Range"))

        # La clave del array depende de si se consultaron events o flows.
        for key in ("events", "flows", "records", "assets"):
            filas = payload.get(key)
            if isinstance(filas, list):
                limpias = [row for row in filas if isinstance(row, dict)]
                return FetchResult(
                    records=limpias[:tope],
                    truncated=len(limpias) > tope or (total is not None and total > tope),
                    total=total,
                )

        return FetchResult(
            records=[],
            warnings=["La respuesta de QRadar no traia events, flows, records ni assets."],
        )

    async def _wait(self, client, base: str, search_id: str) -> str:
        """Sondea hasta COMPLETED, error o agotar el tiempo de la consulta."""
        deadline = asyncio.get_event_loop().time() + SETTINGS.query_timeout
        status = "WAIT"
        while asyncio.get_event_loop().time() < deadline:
            response = await client.get(f"{base}/api/ariel/searches/{search_id}")
            if response.status_code >= 400:
                raise ConnectorError(self.name, f"Error sondeando la busqueda: {response.text[:200]}",
                                     status=response.status_code)
            status = str(response.json().get("status", "")).upper()
            if status in ("COMPLETED", *_TERMINAL_ERROR_STATES):
                return status
            await asyncio.sleep(_POLL_SECONDS)
        raise ConnectorError(self.name, f"La busqueda no termino en {SETTINGS.query_timeout}s (estado {status}).")

    async def _fetch_offenses(self, client, base: str, tope: int) -> FetchResult:
        response = await client.get(
            f"{base}/api/siem/offenses",
            headers={"Range": f"items=0-{tope}"},
            params={"filter": "status=OPEN", "sort": "-magnitude"},
        )
        if response.status_code >= 400:
            raise ConnectorError(self.name, f"HTTP {response.status_code}: {response.text[:300]}",
                                 status=response.status_code)
        payload = response.json()
        total = _total_de(response.headers.get("Content-Range"))
        if not isinstance(payload, list):
            return FetchResult(records=[], total=total,
                               warnings=["QRadar no devolvio una lista de ofensas."])
        limpias = [item for item in payload if isinstance(item, dict)]
        return FetchResult(
            records=limpias[:tope],
            truncated=len(limpias) > tope or (total is not None and total > tope),
            total=total,
        )

    async def ping(self) -> Health:
        if not self.configured:
            return Health(ok=False, detail="Sin credenciales configuradas.", probed=False)

        import httpx

        # /api/system/about exige el token y no toca Ariel: no lanza busqueda ni
        # deja rastro en la consola de QRadar.
        url = f"{self.config.url.rstrip('/')}/api/system/about"
        arranque = time.monotonic()
        client = self._client()
        try:
            response = await client.get(url, timeout=PING_TIMEOUT)
        except httpx.HTTPError as exc:
            return Health(ok=False, detail=f"No responde: {exc}", probed=True)

        tardanza = int((time.monotonic() - arranque) * 1000)
        if response.status_code in (401, 403):
            return Health(ok=False, detail="Token SEC rechazado por QRadar.",
                          probed=True, latency_ms=tardanza)
        if response.status_code == 422:
            # QRadar responde 422 cuando la cabecera Version no es una de las
            # que soporta. Merece mensaje propio: es lo mas facil de dejar mal
            # puesto y el 422 a secas no lo sugiere.
            return Health(ok=False,
                          detail=f"QRADAR_API_VERSION '{self.config.api_version}' no la admite este servidor.",
                          probed=True, latency_ms=tardanza)
        if response.status_code >= 400:
            return Health(ok=False, detail=f"HTTP {response.status_code}.",
                          probed=True, latency_ms=tardanza)
        return Health(ok=True, detail="Responde.", probed=True, latency_ms=tardanza)


def _total_de(cabecera: Optional[str]) -> Optional[int]:
    """Saca el total de un Content-Range de QRadar, si viene.

    Es el unico de los cuatro SIEM que dice cuantos habia en realidad, y por eso
    se aprovecha: permite contar "de 40.000" en vez de solo "hay mas".
    """
    if not cabecera:
        return None
    encontrado = _RANGO.search(cabecera)
    if not encontrado:
        return None
    try:
        return int(encontrado.group(1))
    except ValueError:  # pragma: no cover
        return None


def _apply_window(aql: str, time_from: Optional[datetime], time_to: Optional[datetime]) -> str:
    """Anade la ventana temporal si la AQL no trae ya una clausula propia.

    Se respeta lo que escriba el analista: si ya puso ``LAST 2 HOURS`` o un
    ``START/STOP``, sobrescribirlo seria desconcertante.
    """
    lowered = aql.lower()
    if " last " in lowered or " start " in lowered or "stop " in lowered:
        return aql
    if not (time_from and time_to):
        return aql
    start_ms = int(time_from.timestamp() * 1000)
    stop_ms = int(time_to.timestamp() * 1000)
    return f"{aql} START {start_ms} STOP {stop_ms}"
