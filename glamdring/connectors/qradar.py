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
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..config import SETTINGS, QRadarConfig
from .base import Connector, ConnectorError

_POLL_SECONDS = 1.5
_TERMINAL_ERROR_STATES = {"ERROR", "CANCELED"}


class QRadarConnector(Connector):
    name = "qradar"
    query_language = "AQL"
    example_query = (
        "SELECT starttime, sourceip, destinationip, username, qidname(qid), magnitude, "
        "categoryname(category) FROM events LAST 24 HOURS LIMIT 5000"
    )

    def __init__(self, config: Optional[QRadarConfig] = None) -> None:
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

    async def fetch(
        self,
        query: str,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 10_000,
    ) -> List[Dict[str, Any]]:
        if not self.configured:
            raise ConnectorError(self.name, "QRadar no esta configurado (QRADAR_URL / QRADAR_TOKEN).")

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise ConnectorError(self.name, "Falta la dependencia 'httpx'.") from exc

        aql = _apply_window(query.strip(), time_from, time_to)
        base = self.config.url.rstrip("/")

        async with httpx.AsyncClient(verify=self.config.verify_tls,
                                     timeout=SETTINGS.query_timeout,
                                     headers=self._headers()) as client:
            # Las ofensas se piden por su propio endpoint, no por Ariel.
            if aql.lower().startswith("offenses"):
                return await self._fetch_offenses(client, base, limit)

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

            results = await client.get(
                f"{base}/api/ariel/searches/{search_id}/results",
                headers={**self._headers(), "Range": f"items=0-{max(limit - 1, 0)}"},
            )
            if results.status_code >= 400:
                raise ConnectorError(self.name, f"HTTP {results.status_code}: {results.text[:300]}",
                                     status=results.status_code)
            payload = results.json()

        # La clave del array depende de si se consultaron events o flows.
        for key in ("events", "flows", "records", "assets"):
            rows = payload.get(key)
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)][:limit]
        return []

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

    async def _fetch_offenses(self, client, base: str, limit: int) -> List[Dict[str, Any]]:
        response = await client.get(
            f"{base}/api/siem/offenses",
            headers={**self._headers(), "Range": f"items=0-{max(limit - 1, 0)}"},
            params={"filter": "status=OPEN", "sort": "-magnitude"},
        )
        if response.status_code >= 400:
            raise ConnectorError(self.name, f"HTTP {response.status_code}: {response.text[:300]}",
                                 status=response.status_code)
        payload = response.json()
        return [item for item in payload if isinstance(item, dict)][:limit] if isinstance(payload, list) else []


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
