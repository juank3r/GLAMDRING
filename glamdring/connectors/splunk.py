"""Conector a Splunk por la REST API de busqueda.

Se usa el endpoint ``/search/jobs/export``: Splunk ejecuta la busqueda y va
devolviendo los resultados en la misma peticion, sin crear un job que haya que
sondear. Es lo adecuado para consultas acotadas de investigacion; para busquedas
de horas habria que pasar a ``exec_mode=normal`` mas polling de
``/services/search/jobs/{sid}``.

``output_mode=json`` devuelve NDJSON con los campos ya extraidos por Splunk, que
es exactamente lo que espera el normalizador.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..config import SETTINGS, SplunkConfig
from .base import PING_TIMEOUT, ConnectorError, FetchResult, Health, HttpConnector


class SplunkConnector(HttpConnector):
    name = "splunk"
    query_language = "SPL"
    example_query = 'index=wineventlog EventCode IN (4624,4625,4688) | head 5000'

    def __init__(self, config: Optional[SplunkConfig] = None) -> None:
        super().__init__()
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

    def _client_kwargs(self) -> Dict[str, Any]:
        return {
            "verify": self.config.verify_tls,
            "timeout": SETTINGS.query_timeout,
            "headers": self._headers(),
            "auth": self._auth(),
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
            raise ConnectorError(self.name, "Splunk no esta configurado (SPLUNK_URL / SPLUNK_TOKEN).")

        import httpx

        spl = query.strip()
        if not spl.startswith(("search ", "|", "search\n")):
            # La REST API exige el 'search' explicito; la barra de la UI lo pone sola.
            spl = f"search {spl}"

        tope = max(1, min(limit, SETTINGS.max_results))

        # Se pide UNO MAS de los que se van a entregar. Es la unica forma de
        # saber si el SIEM tenia mas sin que el SIEM lo diga: si vuelven tope+1,
        # habia al menos uno mas y el resultado esta cortado. Ese registro de
        # sobra se descarta; solo sirve como testigo.
        endpoint = f"{self.config.url.rstrip('/')}/servicesNS/-/{self.config.app}/search/jobs/export"
        data = {
            "search": spl,
            "output_mode": "json",
            "count": str(tope + 1),
        }
        if time_from:
            data["earliest_time"] = time_from.isoformat()
        if time_to:
            data["latest_time"] = time_to.isoformat()

        client = self._client()
        try:
            response = await client.post(endpoint, data=data)
        except httpx.HTTPError as exc:
            raise ConnectorError(self.name, f"No se pudo conectar: {exc}") from exc

        if response.status_code >= 400:
            raise ConnectorError(
                self.name,
                f"HTTP {response.status_code}: {response.text[:300]}",
                status=response.status_code,
            )

        filas, avisos = _parse_export(response.text, tope + 1)
        truncado = len(filas) > tope
        return FetchResult(records=filas[:tope], truncated=truncado, warnings=avisos)

    async def ping(self) -> Health:
        if not self.configured:
            return Health(ok=False, detail="Sin credenciales configuradas.", probed=False)

        import httpx

        # /services/server/info es lo mas barato que exige autenticacion: si
        # contesta 200, la URL resuelve, el TLS cuadra y el token vale.
        url = f"{self.config.url.rstrip('/')}/services/server/info"
        arranque = time.monotonic()
        client = self._client()
        try:
            response = await client.get(url, params={"output_mode": "json"},
                                        timeout=PING_TIMEOUT)
        except httpx.HTTPError as exc:
            return Health(ok=False, detail=f"No responde: {exc}", probed=True)

        tardanza = int((time.monotonic() - arranque) * 1000)
        if response.status_code in (401, 403):
            return Health(ok=False, detail="Credenciales rechazadas por Splunk.",
                          probed=True, latency_ms=tardanza)
        if response.status_code >= 400:
            return Health(ok=False, detail=f"HTTP {response.status_code}.",
                          probed=True, latency_ms=tardanza)
        return Health(ok=True, detail="Responde.", probed=True, latency_ms=tardanza)


def _parse_export(text: str, tope: int) -> tuple[List[Dict[str, Any]], List[str]]:
    """El endpoint /export devuelve NDJSON: un objeto por linea.

    Cada linea util trae ``{"preview": false, "result": {...}}``. Las lineas de
    tipo ``preview: true`` son resultados parciales y se descartan para no
    duplicar; las de ``lastrow`` no aportan datos.

    Las lineas ilegibles se cuentan en vez de tragarselas en silencio: si el
    SIEM devuelve mil lineas y ciento veinte no se dejan interpretar, el
    analista tiene que enterarse. Puede ser una consulta que devuelve algo que
    no son eventos, o una respuesta cortada a mitad.
    """
    import json

    out: List[Dict[str, Any]] = []
    ilegibles = 0
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            payload = json.loads(line)
        except ValueError:
            ilegibles += 1
            continue
        if not isinstance(payload, dict):
            ilegibles += 1
            continue
        if payload.get("preview") is True:
            continue
        result = payload.get("result")
        if isinstance(result, dict):
            out.append(result)
        elif "results" in payload and isinstance(payload["results"], list):
            out.extend(item for item in payload["results"] if isinstance(item, dict))
        if len(out) >= tope:
            break

    avisos: List[str] = []
    if ilegibles:
        avisos.append(f"{ilegibles} lineas de la respuesta de Splunk no se pudieron interpretar.")
    return out, avisos
