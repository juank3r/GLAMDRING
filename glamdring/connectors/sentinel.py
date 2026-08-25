"""Conector a Microsoft Sentinel / Log Analytics (KQL).

Dos caminos, y se elige el primero que este disponible:

1. ``azure-monitor-query`` + ``azure-identity`` si estan instalados. Es la via
   soportada y gestiona el refresco de token sola.
2. REST directa contra ``api.loganalytics.io`` pidiendo el token a Entra ID por
   client-credentials. Sirve cuando no se pueden instalar los SDK de Azure, que
   en entornos corporativos pasa mas de lo que parece.

En ambos casos se inyecta ``Type`` (el nombre de la tabla) en cada fila: las
filas de Log Analytics no lo llevan y el normalizador lo necesita para saber que
tabla esta leyendo.

EL SDK ES SINCRONO Y SE LLAMA DESDE UN HILO. ``query_workspace`` bloquea, y
antes se llamaba tal cual dentro de una corrutina. En un servidor asincrono eso
no ralentiza esa consulta: para el BUCLE ENTERO. Mientras Log Analytics se toma
sus segundos —hasta 120, que es el tiempo de espera configurado— no se sirve el
frontend, no responde ``/api/health``, no entra la consulta del companero de
turno y el navegador da la aplicacion por caida. Con ``asyncio.to_thread`` el
bloqueo se queda dentro del hilo.

Hoy no se nota porque el SDK esta comentado en requirements.txt y siempre se
acaba cayendo a la via REST, que si es asincrona. Es decir: el fallo esta
esperando a que alguien instale el SDK, que es justo lo que hara el primero que
lo despliegue en serio.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..config import SETTINGS, SentinelConfig
from .base import PING_TIMEOUT, ConnectorError, FetchResult, Health, HttpConnector

_LOGANALYTICS_SCOPE = "https://api.loganalytics.io/.default"
_LOGANALYTICS_API = "https://api.loganalytics.io/v1/workspaces"


class SentinelConnector(HttpConnector):
    name = "sentinel"
    query_language = "KQL"
    example_query = "DeviceProcessEvents | where Timestamp > ago(24h) | take 5000"

    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        super().__init__()
        self.config = config or SETTINGS.sentinel

    @property
    def configured(self) -> bool:
        return self.config.configured

    def _client_kwargs(self) -> Dict[str, Any]:
        return {"timeout": SETTINGS.query_timeout}

    async def fetch(
        self,
        query: str,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 10_000,
        cursor: Optional[str] = None,
    ) -> FetchResult:
        if not self.configured:
            raise ConnectorError(self.name, "Sentinel no esta configurado (SENTINEL_WORKSPACE_ID).")

        if not time_to:
            time_to = datetime.now(timezone.utc)
        if not time_from:
            time_from = time_to - timedelta(hours=24)

        tope = max(1, min(limit, SETTINGS.max_results))

        salida = await self._fetch_sdk(query, time_from, time_to)
        if salida is None:
            salida = await self._fetch_rest(query, time_from, time_to)
        filas, avisos = salida

        # Log Analytics no acepta un tope por parametro: se le pone en la propia
        # KQL con take. Asi que el corte es aqui, y por eso se sabe si sobraban.
        return FetchResult(
            records=filas[:tope],
            truncated=len(filas) > tope,
            warnings=avisos,
        )

    # -- via SDK -----------------------------------------------------------

    async def _fetch_sdk(self, query: str, time_from: datetime,
                         time_to: datetime) -> Optional[Tuple[List[Dict[str, Any]], List[str]]]:
        try:
            from azure.monitor.query import LogsQueryStatus
        except ImportError:
            return None  # sin SDK: que lo intente la via REST

        # El SDK bloquea de principio a fin: credencial, token y consulta. Todo
        # el bloque va al hilo, no solo query_workspace, porque pedir el token
        # tambien es una llamada de red sincrona.
        return await asyncio.to_thread(self._consulta_sdk_bloqueante, query, time_from,
                                       time_to, LogsQueryStatus)

    def _consulta_sdk_bloqueante(self, query: str, time_from: datetime, time_to: datetime,
                                 LogsQueryStatus) -> Tuple[List[Dict[str, Any]], List[str]]:
        """Todo lo sincrono del SDK, junto, para poder mandarlo a un hilo."""
        from azure.identity import ClientSecretCredential, DefaultAzureCredential
        from azure.monitor.query import LogsQueryClient

        if self.config.client_id and self.config.client_secret and self.config.tenant_id:
            credential = ClientSecretCredential(
                tenant_id=self.config.tenant_id,
                client_id=self.config.client_id,
                client_secret=self.config.client_secret,
            )
        else:
            # Cubre az login, managed identity y variables AZURE_*.
            credential = DefaultAzureCredential()

        client = LogsQueryClient(credential)
        try:
            response = client.query_workspace(
                workspace_id=self.config.workspace_id,
                query=query,
                timespan=(time_from, time_to),
                server_timeout=SETTINGS.query_timeout,
            )
        except Exception as exc:  # el SDK lanza tipos muy variados
            raise ConnectorError(self.name, f"Error consultando Log Analytics: {exc}") from exc

        estado = getattr(response, "status", None)
        if estado == LogsQueryStatus.FAILURE:
            raise ConnectorError(self.name, f"Consulta KQL fallida: {getattr(response, 'partial_error', '')}")

        avisos: List[str] = []
        if estado == LogsQueryStatus.PARTIAL:
            # Log Analytics corta por tamano de respuesta y por numero de filas,
            # y lo dice AQUI y en ningun otro sitio. Callarselo es entregar un
            # grafo incompleto con pinta de completo.
            detalle = str(getattr(response, "partial_error", "") or "")[:200]
            avisos.append(f"Log Analytics devolvio un resultado PARCIAL. {detalle}".strip())

        out: List[Dict[str, Any]] = []
        tables = getattr(response, "tables", None) or getattr(response, "partial_data", []) or []
        for table in tables:
            columns = list(table.columns)
            table_name = getattr(table, "name", "") or ""
            for row in table.rows:
                record = dict(zip(columns, row))
                record.setdefault("Type", table_name)
                out.append(record)
        return out, avisos

    # -- via REST ----------------------------------------------------------

    async def _token(self, client) -> str:
        """Token de Entra ID por client-credentials."""
        token_url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
        token_response = await client.post(token_url, data={
            "grant_type": "client_credentials",
            "client_id": self.config.client_id,
            "client_secret": self.config.client_secret,
            "scope": _LOGANALYTICS_SCOPE,
        })
        if token_response.status_code >= 400:
            raise ConnectorError(self.name, f"No se pudo obtener token: {token_response.text[:200]}",
                                 status=token_response.status_code)
        return token_response.json().get("access_token", "")

    def _exige_credenciales_rest(self) -> None:
        if not (self.config.tenant_id and self.config.client_id and self.config.client_secret):
            raise ConnectorError(
                self.name,
                "Sin SDK de Azure instalado hacen falta AZURE_TENANT_ID, AZURE_CLIENT_ID y "
                "AZURE_CLIENT_SECRET para la via REST.",
            )

    async def _fetch_rest(self, query: str, time_from: datetime,
                          time_to: datetime) -> Tuple[List[Dict[str, Any]], List[str]]:
        self._exige_credenciales_rest()
        client = self._client()
        token = await self._token(client)

        timespan = f"{time_from.isoformat()}/{time_to.isoformat()}"
        response = await client.post(
            f"{_LOGANALYTICS_API}/{self.config.workspace_id}/query",
            headers={"Authorization": f"Bearer {token}"},
            json={"query": query, "timespan": timespan},
        )
        if response.status_code >= 400:
            raise ConnectorError(self.name, f"HTTP {response.status_code}: {response.text[:300]}",
                                 status=response.status_code)
        payload = response.json()

        avisos: List[str] = []
        # La REST marca el resultado parcial con un bloque 'error' al lado de
        # las tablas, no con un codigo HTTP: llega un 200 con datos a medias.
        error = payload.get("error")
        if isinstance(error, dict):
            avisos.append(f"Log Analytics devolvio un resultado PARCIAL. "
                          f"{str(error.get('message', ''))[:200]}".strip())

        out: List[Dict[str, Any]] = []
        for table in payload.get("tables", []):
            columns = [column.get("name") for column in table.get("columns", [])]
            table_name = table.get("name", "")
            for row in table.get("rows", []):
                record = dict(zip(columns, row))
                record.setdefault("Type", table_name)
                out.append(record)
        return out, avisos

    # -- comprobacion ------------------------------------------------------

    async def ping(self) -> Health:
        if not self.configured:
            return Health(ok=False, detail="Sin credenciales configuradas.", probed=False)

        arranque = time.monotonic()
        try:
            # 'print' no toca ninguna tabla: no lee datos del cliente, no cuesta
            # cuota de consulta y aun asi valida token, workspace y permisos,
            # que es todo lo que se quiere saber.
            await asyncio.wait_for(self._ping_real(), timeout=PING_TIMEOUT)
        except asyncio.TimeoutError:
            return Health(ok=False, detail=f"No responde en {PING_TIMEOUT}s.", probed=True)
        except ConnectorError as exc:
            return Health(ok=False, detail=exc.message, probed=True)
        except Exception as exc:  # pragma: no cover - el SDK lanza de todo
            return Health(ok=False, detail=f"No responde: {exc}", probed=True)

        return Health(ok=True, detail="Responde.", probed=True,
                      latency_ms=int((time.monotonic() - arranque) * 1000))

    async def _ping_real(self) -> None:
        ahora = datetime.now(timezone.utc)
        salida = await self._fetch_sdk("print comprobacion = 1", ahora - timedelta(minutes=5), ahora)
        if salida is None:
            self._exige_credenciales_rest()
            client = self._client()
            # Basta con conseguir token: si Entra ID lo da, la identidad existe
            # y el secreto vale. Consultar ademas seria pagar una llamada de mas
            # por informacion que ya se tiene.
            token = await self._token(client)
            if not token:
                raise ConnectorError(self.name, "Entra ID no devolvio token.")
