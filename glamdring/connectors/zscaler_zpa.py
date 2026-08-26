"""Conector a Zscaler ZPA: logs de acceso a aplicaciones privadas.

POR QUE SOLO ZPA Y NO ZIA. Es la division que manda en todo este fichero:

* **ZIA** (el proxy de salida a Internet) NO entrega sus logs web por API. Los
  empuja NSS a una URL que se le configura, asi que entra por
  ``POST /api/receive/zscaler``. No hay conector para eso y no lo va a haber:
  no es una limitacion nuestra, es como funciona el producto.
* **ZPA** (el acceso a aplicaciones privadas, el sustituto de la VPN) SI tiene
  API REST para sus logs de usuario. Eso si encaja en el contrato.

Autenticacion OAuth2 client-credentials contra ``/signin``, que devuelve un
token de vida corta.

PENDIENTE DE COMPROBAR CONTRA UN ZPA REAL: los nombres exactos de los campos de
la respuesta y el comportamiento de la paginacion cuando hay mas paginas de las
que caben. Lo que hay aqui sale de la documentacion publica y esta escrito para
fallar de forma legible si no cuadra, no para aparentar que funciona.
"""

from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from ..config import SETTINGS, ZscalerZpaConfig
from .base import PING_TIMEOUT, ConnectorError, FetchResult, Health, HttpConnector


class ZscalerZpaConnector(HttpConnector):
    name = "zscaler_zpa"
    query_language = "user_activity | user_status | app_connector_status"
    example_query = "user_activity"

    def __init__(self, config: Optional[ZscalerZpaConfig] = None) -> None:
        super().__init__()
        self.config = config or SETTINGS.zscaler_zpa
        self._token: Optional[str] = None
        self._token_expira: float = 0.0

    @property
    def configured(self) -> bool:
        return self.config.configured

    def _client_kwargs(self) -> Dict[str, Any]:
        return {"timeout": SETTINGS.query_timeout,
                "headers": {"Accept": "application/json"}}

    def _base(self) -> str:
        return self.config.url.rstrip("/")

    async def _autenticar(self) -> str:
        """Token OAuth2, cacheado hasta poco antes de caducar.

        El margen de sesenta segundos no es paranoia: el token caduca en el
        reloj de Zscaler, no en el nuestro, y una consulta larga que empieza con
        un token a punto de morir falla a mitad con un 401 que parece un
        problema de credenciales y no lo es.
        """
        ahora = time.monotonic()
        if self._token and ahora < self._token_expira:
            return self._token

        import httpx

        cliente = self._client()
        try:
            respuesta = await cliente.post(
                f"{self._base()}/signin",
                data={"client_id": self.config.client_id,
                      "client_secret": self.config.client_secret},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(self.name, f"No se pudo conectar: {exc}") from exc

        if respuesta.status_code >= 400:
            raise ConnectorError(self.name,
                                 f"Autenticacion rechazada: HTTP {respuesta.status_code}.",
                                 status=respuesta.status_code)
        cuerpo = respuesta.json()
        token = cuerpo.get("access_token")
        if not token:
            raise ConnectorError(self.name, "ZPA no devolvio access_token.")
        # expires_in viene en MILISEGUNDOS en la API de ZPA, no en segundos.
        # Tratarlo como segundos daria un token "valido" durante un mes y una
        # racha de 401 inexplicables cuando de verdad caducara.
        milis = cuerpo.get("expires_in")
        try:
            duracion = int(milis) / 1000.0 if milis else 3600.0
        except (TypeError, ValueError):
            duracion = 3600.0
        self._token = str(token)
        self._token_expira = ahora + max(60.0, duracion - 60.0)
        return self._token

    async def fetch(
        self,
        query: str,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 10_000,
        cursor: Optional[str] = None,
    ) -> FetchResult:
        if not self.configured:
            raise ConnectorError(self.name, "ZPA no esta configurado "
                                            "(ZPA_URL / ZPA_CLIENT_ID / ZPA_CLIENT_SECRET).")

        import httpx

        tipo = (query or "user_activity").strip().lower()
        rutas = {
            "user_activity": "/mgmtconfig/v1/admin/customers/{cid}/userActivity",
            "user_status": "/mgmtconfig/v1/admin/customers/{cid}/userStatus",
            "app_connector_status": "/mgmtconfig/v1/admin/customers/{cid}/connectorStatus",
        }
        if tipo not in rutas:
            raise ConnectorError(self.name,
                                 f"Tipo '{tipo}' desconocido. Hay: {', '.join(rutas)}.")

        if not time_to:
            time_to = datetime.now(timezone.utc)
        if not time_from:
            time_from = time_to - timedelta(hours=24)

        tope = max(1, min(limit, SETTINGS.max_results))
        token = await self._autenticar()
        pagina = int(cursor) if cursor and str(cursor).isdigit() else 1

        url = self._base() + rutas[tipo].format(cid=self.config.customer_id)
        cliente = self._client()
        try:
            respuesta = await cliente.get(
                url,
                headers={"Authorization": f"Bearer {token}"},
                params={"startTime": int(time_from.timestamp() * 1000),
                        "endTime": int(time_to.timestamp() * 1000),
                        "page": pagina,
                        "pagesize": min(tope, 1000)},
            )
        except httpx.HTTPError as exc:
            raise ConnectorError(self.name, f"No se pudo conectar: {exc}") from exc

        if respuesta.status_code in (401, 403):
            self._token = None  # que se renueve en el siguiente intento
            raise ConnectorError(self.name, "Credenciales rechazadas por ZPA.",
                                 status=respuesta.status_code)
        if respuesta.status_code >= 400:
            raise ConnectorError(self.name,
                                 f"HTTP {respuesta.status_code}: {respuesta.text[:300]}",
                                 status=respuesta.status_code)

        cuerpo = respuesta.json()
        filas = cuerpo.get("list") if isinstance(cuerpo, dict) else cuerpo
        if not isinstance(filas, list):
            return FetchResult(
                records=[],
                warnings=["La respuesta de ZPA no traia una lista. Los nombres de campo "
                          "estan pendientes de comprobar contra un ZPA real."])

        registros = [f for f in filas if isinstance(f, dict)]
        total = cuerpo.get("totalCount") if isinstance(cuerpo, dict) else None
        try:
            total = int(total) if total is not None else None
        except (TypeError, ValueError):
            total = None

        hay_mas = bool(total and total > pagina * min(tope, 1000))
        return FetchResult(
            records=registros[:tope],
            truncated=hay_mas or len(registros) > tope,
            total=total,
            cursor=str(pagina + 1) if hay_mas else None,
        )

    async def ping(self) -> Health:
        if not self.configured:
            return Health(ok=False, detail="Sin credenciales configuradas.", probed=False)

        arranque = time.monotonic()
        try:
            # Basta con conseguir el token: si ZPA lo da, la URL resuelve, el
            # TLS cuadra y las credenciales valen. Pedir ademas datos seria
            # pagar una llamada de mas por informacion que ya se tiene.
            token = await self._autenticar()
        except ConnectorError as exc:
            return Health(ok=False, detail=exc.message, probed=True)
        except Exception as exc:  # pragma: no cover
            return Health(ok=False, detail=f"No responde: {exc}", probed=True)

        tardanza = int((time.monotonic() - arranque) * 1000)
        if not token:
            return Health(ok=False, detail="ZPA no devolvio token.", probed=True,
                          latency_ms=tardanza)
        return Health(ok=True, detail="Responde.", probed=True, latency_ms=tardanza)

    async def close(self) -> None:
        self._token = None
        self._token_expira = 0.0
        await super().close()
