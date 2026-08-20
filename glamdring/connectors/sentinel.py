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
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..config import SETTINGS, SentinelConfig
from .base import Connector, ConnectorError

_LOGANALYTICS_SCOPE = "https://api.loganalytics.io/.default"
_LOGANALYTICS_API = "https://api.loganalytics.io/v1/workspaces"


class SentinelConnector(Connector):
    name = "sentinel"
    query_language = "KQL"
    example_query = "DeviceProcessEvents | where Timestamp > ago(24h) | take 5000"

    def __init__(self, config: Optional[SentinelConfig] = None) -> None:
        self.config = config or SETTINGS.sentinel

    @property
    def configured(self) -> bool:
        return self.config.configured

    async def fetch(
        self,
        query: str,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 10_000,
    ) -> List[Dict[str, Any]]:
        if not self.configured:
            raise ConnectorError(self.name, "Sentinel no esta configurado (SENTINEL_WORKSPACE_ID).")

        if not time_to:
            time_to = datetime.now(timezone.utc)
        if not time_from:
            time_from = time_to - timedelta(hours=24)

        rows = await self._fetch_sdk(query, time_from, time_to)
        if rows is None:
            rows = await self._fetch_rest(query, time_from, time_to)
        return rows[:limit]

    # -- via SDK -----------------------------------------------------------

    async def _fetch_sdk(self, query: str, time_from: datetime,
                         time_to: datetime) -> Optional[List[Dict[str, Any]]]:
        try:
            from azure.identity import ClientSecretCredential, DefaultAzureCredential
            from azure.monitor.query import LogsQueryClient, LogsQueryStatus
        except ImportError:
            return None  # sin SDK: que lo intente la via REST

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

        if getattr(response, "status", None) == LogsQueryStatus.FAILURE:
            raise ConnectorError(self.name, f"Consulta KQL fallida: {getattr(response, 'partial_error', '')}")

        out: List[Dict[str, Any]] = []
        tables = getattr(response, "tables", None) or getattr(response, "partial_data", []) or []
        for table in tables:
            columns = list(table.columns)
            table_name = getattr(table, "name", "") or ""
            for row in table.rows:
                record = dict(zip(columns, row))
                record.setdefault("Type", table_name)
                out.append(record)
        return out

    # -- via REST ----------------------------------------------------------

    async def _fetch_rest(self, query: str, time_from: datetime,
                          time_to: datetime) -> List[Dict[str, Any]]:
        if not (self.config.tenant_id and self.config.client_id and self.config.client_secret):
            raise ConnectorError(
                self.name,
                "Sin SDK de Azure instalado hacen falta AZURE_TENANT_ID, AZURE_CLIENT_ID y "
                "AZURE_CLIENT_SECRET para la via REST.",
            )
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise ConnectorError(self.name, "Falta la dependencia 'httpx'.") from exc

        token_url = f"https://login.microsoftonline.com/{self.config.tenant_id}/oauth2/v2.0/token"
        async with httpx.AsyncClient(timeout=SETTINGS.query_timeout) as client:
            token_response = await client.post(token_url, data={
                "grant_type": "client_credentials",
                "client_id": self.config.client_id,
                "client_secret": self.config.client_secret,
                "scope": _LOGANALYTICS_SCOPE,
            })
            if token_response.status_code >= 400:
                raise ConnectorError(self.name, f"No se pudo obtener token: {token_response.text[:200]}",
                                     status=token_response.status_code)
            token = token_response.json().get("access_token", "")

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

        out: List[Dict[str, Any]] = []
        for table in payload.get("tables", []):
            columns = [column.get("name") for column in table.get("columns", [])]
            table_name = table.get("name", "")
            for row in table.get("rows", []):
                record = dict(zip(columns, row))
                record.setdefault("Type", table_name)
                out.append(record)
        return out
