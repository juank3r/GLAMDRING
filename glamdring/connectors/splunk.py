"""Conector a Splunk por la REST API de busqueda.

Se usa el modo ``oneshot``: Splunk ejecuta la busqueda y devuelve los resultados
en la misma peticion, sin crear un job que haya que sondear. Es lo adecuado para
consultas acotadas de investigacion; para busquedas de horas habria que pasar a
``exec_mode=normal`` mas polling de ``/services/search/jobs/{sid}``.

``output_mode=json`` devuelve ``{"results": [...]}`` con los campos ya extraidos
por Splunk, que es exactamente lo que espera el normalizador.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..config import SETTINGS, SplunkConfig
from .base import Connector, ConnectorError


class SplunkConnector(Connector):
    name = "splunk"
    query_language = "SPL"
    example_query = 'index=wineventlog EventCode IN (4624,4625,4688) | head 5000'

    def __init__(self, config: Optional[SplunkConfig] = None) -> None:
        self.config = config or SETTINGS.splunk

    @property
    def configured(self) -> bool:
        return self.config.configured

    def _headers(self) -> Dict[str, str]:
        if self.config.token:
            # Los tokens de Splunk van con el esquema 'Splunk', no 'Bearer'.
            return {"Authorization": f"Splunk {self.config.token}"}
        return {}

    def _auth(self):
        if self.config.token:
            return None
        return (self.config.username, self.config.password)

    async def fetch(
        self,
        query: str,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 10_000,
    ) -> List[Dict[str, Any]]:
        if not self.configured:
            raise ConnectorError(self.name, "Splunk no esta configurado (SPLUNK_URL / SPLUNK_TOKEN).")

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise ConnectorError(self.name, "Falta la dependencia 'httpx'.") from exc

        spl = query.strip()
        if not spl.startswith(("search ", "|", "search\n")):
            # La REST API exige el 'search' explicito; la barra de la UI lo pone sola.
            spl = f"search {spl}"

        endpoint = f"{self.config.url.rstrip('/')}/servicesNS/-/{self.config.app}/search/jobs/export"
        data = {
            "search": spl,
            "output_mode": "json",
            "count": str(min(limit, SETTINGS.max_results)),
        }
        if time_from:
            data["earliest_time"] = time_from.isoformat()
        if time_to:
            data["latest_time"] = time_to.isoformat()

        async with httpx.AsyncClient(verify=self.config.verify_tls,
                                     timeout=SETTINGS.query_timeout) as client:
            try:
                response = await client.post(endpoint, data=data,
                                             headers=self._headers(), auth=self._auth())
            except httpx.HTTPError as exc:
                raise ConnectorError(self.name, f"No se pudo conectar: {exc}") from exc

            if response.status_code >= 400:
                raise ConnectorError(
                    self.name,
                    f"HTTP {response.status_code}: {response.text[:300]}",
                    status=response.status_code,
                )
            return _parse_export(response.text, limit)


def _parse_export(text: str, limit: int) -> List[Dict[str, Any]]:
    """El endpoint /export devuelve NDJSON: un objeto por linea.

    Cada linea util trae ``{"preview": false, "result": {...}}``. Las lineas de
    tipo ``preview: true`` son resultados parciales y se descartan para no
    duplicar; las de ``lastrow`` no aportan datos.
    """
    import json

    out: List[Dict[str, Any]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            continue
        if not isinstance(payload, dict):
            continue
        if payload.get("preview") is True:
            continue
        result = payload.get("result")
        if isinstance(result, dict):
            out.append(result)
        elif "results" in payload and isinstance(payload["results"], list):
            out.extend(item for item in payload["results"] if isinstance(item, dict))
        if len(out) >= limit:
            break
    return out
