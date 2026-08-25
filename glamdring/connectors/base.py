"""Contrato comun de los conectores a SIEM.

Un conector solo tiene una responsabilidad: devolver registros crudos. No
normaliza, no construye grafo, no filtra por severidad. Asi cada SIEM nuevo se
anade escribiendo unas 60 lineas y nada mas del sistema cambia.

CONTRATO v2. Antes ``fetch`` devolvia una lista pelada, y con eso se perdian
tres cosas que si importan:

- **Si faltaban datos.** "El SIEM tenia justo 10.000" y "el SIEM tenia dos
  millones y te doy los primeros 10.000" llegaban identicos. El analista se
  queda con un grafo incompleto sin saberlo, que en forense es peor que no
  tener grafo: lo que no esta se lee como que no paso.
- **Por donde seguir.** Las fuentes que paginan con estado (a Netskope no se le
  piden fechas: se le pide "lo siguiente") no tenian donde devolver su marca.
- **Lo raro que no llega a error.** Un resultado parcial de Log Analytics, una
  tabla vacia, un campo que se ignora: o se lanzaba excepcion o se callaba.

De ahi ``FetchResult``. Y de paso los dos metodos que faltaban: ``ping``, para
que el semaforo de la interfaz diga la verdad, y ``close``, para dejar de tirar
el pool TLS en cada consulta.
"""

from __future__ import annotations

import abc
import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# Comprobar que el SIEM responde es una pregunta rapida. Si no contesta en diez
# segundos, para el semaforo ya es un no: esperar los 120 de una consulta de
# verdad dejaria la pantalla colgada nada mas abrirla.
PING_TIMEOUT = 10


class ConnectorError(RuntimeError):
    """Fallo al hablar con el SIEM.

    Se traduce a un 502 con mensaje legible: el analista tiene que poder
    distinguir "mi consulta esta mal" de "el SIEM no responde".
    """

    def __init__(self, connector: str, message: str, status: Optional[int] = None) -> None:
        super().__init__(f"[{connector}] {message}")
        self.connector = connector
        self.message = message
        self.status = status


@dataclass
class FetchResult:
    """Lo que devuelve una consulta, con el contexto de si esta completa."""

    records: List[Dict[str, Any]] = field(default_factory=list)

    # True = habia mas y se corto. Es el dato que separa un grafo completo de
    # uno que solo lo parece.
    truncated: bool = False

    # Cuantos habia en total, cuando el SIEM se digna a decirlo (QRadar lo pone
    # en Content-Range). None = no lo ha dicho, que no es lo mismo que cero.
    total: Optional[int] = None

    # Por donde seguir, en las fuentes que paginan con estado. None = no aplica.
    cursor: Optional[str] = None

    # Lo que conviene contar sin que llegue a error: resultado parcial, tabla
    # vacia, campo ignorado.
    warnings: List[str] = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.records)

    def as_dict(self) -> Dict[str, Any]:
        salida: Dict[str, Any] = {"fetched": len(self.records), "truncated": self.truncated}
        if self.total is not None:
            salida["total"] = self.total
        if self.cursor:
            salida["cursor"] = self.cursor
        if self.warnings:
            salida["warnings"] = self.warnings
        return salida


@dataclass
class Health:
    """Resultado de ``ping``.

    ``probed`` es el campo importante, y por eso existe: separa "he hablado con
    el SIEM y responde" de "tiene credenciales puestas, pero no lo he probado".
    El semaforo de hoy ensena verde por lo segundo, que es lo que hace que un
    token caducado no se descubra hasta la primera consulta de verdad,
    normalmente en mitad de una investigacion.
    """

    ok: bool
    detail: str = ""
    probed: bool = False
    latency_ms: Optional[int] = None

    def as_dict(self) -> Dict[str, Any]:
        salida: Dict[str, Any] = {"ok": self.ok, "detail": self.detail, "probed": self.probed}
        if self.latency_ms is not None:
            salida["latencyMs"] = self.latency_ms
        return salida


class Connector(abc.ABC):
    """Fuente de registros crudos."""

    name: str = "base"
    query_language: str = ""
    example_query: str = ""

    # True si sabe continuar desde un cursor. Lo mira la interfaz para ofrecer
    # "traer mas" en vez de repetir la consulta entera.
    supports_cursor: bool = False

    @property
    @abc.abstractmethod
    def configured(self) -> bool:
        """True si hay credenciales suficientes para intentar la consulta."""

    @abc.abstractmethod
    async def fetch(
        self,
        query: str,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 10_000,
        cursor: Optional[str] = None,
    ) -> FetchResult:
        """Ejecuta la consulta y devuelve los registros tal cual llegan."""

    async def ping(self) -> Health:
        """Comprueba que la fuente responde.

        Por defecto NO prueba nada, y lo dice (``probed=False``). Un conector
        que no sepa comprobarse debe quedarse asi antes que devolver un verde
        que no ha verificado.
        """
        if not self.configured:
            return Health(ok=False, detail="Sin credenciales configuradas.", probed=False)
        return Health(ok=True, detail="Configurado, sin comprobar.", probed=False)

    async def close(self) -> None:
        """Suelta lo que haya abierto. Por defecto no hay nada."""

    def describe(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "configured": self.configured,
            "queryLanguage": self.query_language,
            "exampleQuery": self.example_query,
            "supportsCursor": self.supports_cursor,
        }


class HttpConnector(Connector):
    """Conector que habla HTTP, con el cliente reutilizado entre consultas.

    Antes cada ``fetch`` abria su ``httpx.AsyncClient`` con ``async with`` y lo
    cerraba al salir. O sea: resolucion DNS, negociacion TLS entera y conexion
    nueva en CADA consulta, tirando a la basura un pool que existe justo para no
    tener que hacer eso. Contra un SIEM detras de un proxy corporativo el
    apreton de manos se lleva mas tiempo que la consulta.

    El cliente queda atado AL BUCLE en el que se creo, y por eso se guarda cual
    era. Uno creado en un bucle y usado en otro falla de forma especialmente
    desagradable —se queda esperando a un selector que ya no corre—, y eso pasa
    de verdad en los tests, donde cada peticion puede montar su propio bucle. Si
    el bucle ha cambiado, se descarta y se abre otro.
    """

    def __init__(self) -> None:
        self._cliente: Any = None
        self._bucle: Any = None

    def _client_kwargs(self) -> Dict[str, Any]:
        """Lo que necesita el cliente de este SIEM: verify, timeout, cabeceras."""
        return {}

    def _client(self):
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise ConnectorError(self.name, "Falta la dependencia 'httpx'.") from exc

        try:
            bucle = asyncio.get_running_loop()
        except RuntimeError:
            bucle = None

        if self._cliente is not None and (self._cliente.is_closed or self._bucle is not bucle):
            # El anterior se queda sin cerrar a proposito: si su bucle ya no
            # existe, cerrarlo desde aqui volveria a fallar por lo mismo.
            self._cliente = None

        if self._cliente is None:
            self._cliente = httpx.AsyncClient(**self._client_kwargs())
            self._bucle = bucle
        return self._cliente

    async def close(self) -> None:
        cliente, self._cliente = self._cliente, None
        self._bucle = None
        if cliente is not None and not cliente.is_closed:
            try:
                await cliente.aclose()
            except Exception:  # pragma: no cover - cerrar nunca debe romper el apagado
                pass
