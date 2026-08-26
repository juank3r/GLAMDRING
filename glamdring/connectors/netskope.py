"""Conector a Netskope (API REST v2, endpoint de exportacion de eventos).

ES UN ITERADOR CON ESTADO, y por eso el contrato v1 no valia. A Netskope no se
le pide "damelo entre estas dos fechas": se le pide "damelo desde donde me
quede", y el servidor lleva la cuenta por un nombre de iterador que se elige al
configurarlo.

Eso tiene una consecuencia que conviene entender antes de tocarlo: **cada
llamada avanza el puntero**. Si se pide dos veces con el mismo iterador no
salen los mismos eventos, salen los SIGUIENTES. No se puede reintentar una
consulta como si fuera de solo lectura, y por eso ``fetch`` devuelve el cursor
en ``FetchResult`` en vez de esconderlo: quien lo llama tiene que saber por
donde va.

Para investigar hacia atras -que es lo normal en un SOC- esta el modo por
ventana temporal, que si es repetible.

Autenticacion por cabecera ``Netskope-Api-Token``. El token se limita por
ambito al crearlo, del estilo ``/api/v2/events/dataexport/events/application``.
"""

from __future__ import annotations

import re
import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..config import SETTINGS, NetskopeConfig
from .base import PING_TIMEOUT, ConnectorError, FetchResult, Health, HttpConnector

# Los tipos de evento que sirven para un grafo de incidente. 'application' es el
# que da la actividad dentro de la aplicacion cloud, que es lo mas valioso.
TIPOS = ("application", "alert", "page", "network", "audit", "infrastructure")

# El nombre del iterador es parte de la URL: solo lo previsible.
_ITERADOR_VALIDO = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


class NetskopeConnector(HttpConnector):
    name = "netskope"
    query_language = "tipo de evento (application, alert, page, network, audit)"
    example_query = "application"
    supports_cursor = True

    def __init__(self, config: Optional[NetskopeConfig] = None) -> None:
        super().__init__()
        self.config = config or SETTINGS.netskope

    @property
    def configured(self) -> bool:
        return self.config.configured

    def _client_kwargs(self) -> Dict[str, Any]:
        return {
            "timeout": SETTINGS.query_timeout,
            "headers": {"Netskope-Api-Token": self.config.token,
                        "Accept": "application/json"},
        }

    def _base(self) -> str:
        return self.config.url.rstrip("/")

    async def fetch(
        self,
        query: str,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 10_000,
        cursor: Optional[str] = None,
    ) -> FetchResult:
        if not self.configured:
            raise ConnectorError(self.name, "Netskope no esta configurado "
                                            "(NETSKOPE_URL / NETSKOPE_TOKEN).")

        import httpx

        tipo = (query or "application").strip().lower()
        if tipo not in TIPOS:
            raise ConnectorError(
                self.name,
                f"Tipo de evento '{tipo}' desconocido. Hay: {', '.join(TIPOS)}.")

        # El tope de Netskope por peticion es 10.000; pedir mas no da mas.
        por_pagina = max(1, min(limit, SETTINGS.max_results, 10_000))
        iterador = (cursor or self.config.iterator or "glamdring").strip()
        if not _ITERADOR_VALIDO.match(iterador):
            raise ConnectorError(self.name, "Nombre de iterador no permitido.")

        parametros: Dict[str, Any] = {"index": iterador, "operation": "next"}
        avisos: List[str] = []

        # Con ventana temporal se usa una operacion repetible en vez del
        # iterador. Es lo que hace falta para investigar hacia atras: pedir dos
        # veces lo mismo tiene que dar lo mismo.
        if time_from:
            parametros["operation"] = str(int(time_from.timestamp()))
            avisos.append("Consulta por ventana temporal: no avanza el iterador.")

        url = f"{self._base()}/api/v2/events/dataexport/events/{tipo}"
        cliente = self._client()
        try:
            respuesta = await cliente.get(url, params=parametros)
        except httpx.HTTPError as exc:
            raise ConnectorError(self.name, f"No se pudo conectar: {exc}") from exc

        if respuesta.status_code == 429:
            # Netskope limita a una peticion cada 5 segundos por iterador, y lo
            # dice en Retry-After. Se traslada tal cual: reintentar antes solo
            # consigue que el siguiente 429 tarde mas.
            espera = respuesta.headers.get("Retry-After", "5")
            raise ConnectorError(self.name,
                                 f"Netskope pide esperar {espera}s antes de volver a pedir.",
                                 status=429)
        if respuesta.status_code in (401, 403):
            raise ConnectorError(self.name,
                                 "Token rechazado, o sin permiso sobre ese tipo de evento. "
                                 "El ambito se fija al crear el token.",
                                 status=respuesta.status_code)
        if respuesta.status_code >= 400:
            raise ConnectorError(self.name,
                                 f"HTTP {respuesta.status_code}: {respuesta.text[:300]}",
                                 status=respuesta.status_code)

        cuerpo = respuesta.json()
        filas = cuerpo.get("result")
        if not isinstance(filas, list):
            return FetchResult(records=[], cursor=iterador,
                               warnings=["Netskope no devolvio una lista en 'result'."])

        registros = [f for f in filas if isinstance(f, dict)]
        # Netskope dice cuantos quedan sin entregar. Es de las pocas fuentes que
        # lo dice, y permite contar en vez de solo avisar de que falta algo.
        restantes = cuerpo.get("wait_time")
        pendientes = cuerpo.get("remaining_events") or cuerpo.get("total")
        if isinstance(restantes, (int, float)) and restantes:
            avisos.append(f"Netskope pide {int(restantes)}s de espera antes de la siguiente.")

        return FetchResult(
            records=registros[:por_pagina],
            truncated=len(registros) >= por_pagina or bool(pendientes),
            total=int(pendientes) if isinstance(pendientes, (int, float)) else None,
            cursor=iterador,
            warnings=avisos,
        )

    async def ping(self) -> Health:
        if not self.configured:
            return Health(ok=False, detail="Sin credenciales configuradas.", probed=False)

        import httpx

        arranque = time.monotonic()
        cliente = self._client()
        try:
            # El endpoint de estado del iterador no consume eventos: preguntar
            # por 'next' avanzaria el puntero, y un semaforo no puede tener
            # efectos secundarios sobre los datos.
            respuesta = await cliente.get(
                f"{self._base()}/api/v2/events/dataexport/events/application",
                params={"index": (self.config.iterator or "glamdring"), "operation": "head"},
                timeout=PING_TIMEOUT,
            )
        except httpx.HTTPError as exc:
            return Health(ok=False, detail=f"No responde: {exc}", probed=True)

        tardanza = int((time.monotonic() - arranque) * 1000)
        if respuesta.status_code in (401, 403):
            return Health(ok=False, detail="Token rechazado por Netskope.",
                          probed=True, latency_ms=tardanza)
        if respuesta.status_code == 429:
            # Que limite el ritmo significa que ha entendido la peticion: la
            # credencial vale y el servicio esta vivo.
            return Health(ok=True, detail="Responde (limitando el ritmo).",
                          probed=True, latency_ms=tardanza)
        if respuesta.status_code >= 400:
            return Health(ok=False, detail=f"HTTP {respuesta.status_code}.",
                          probed=True, latency_ms=tardanza)
        return Health(ok=True, detail="Responde.", probed=True, latency_ms=tardanza)
