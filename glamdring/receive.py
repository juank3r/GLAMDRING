"""Control de acceso y de caudal del receptor de logs.

Esto vive aparte de la ruta HTTP a proposito: son las decisiones de seguridad
del unico endpoint que va a estar escuchando a lo que le manden, y conviene
poder probarlas sin montar un servidor.

POR QUE HAY UN RECEPTOR. El contrato de conector solo sabe TIRAR de datos:
``fetch(consulta, desde, hasta, limite)``. Y hay medio mercado que no funciona
asi. Zscaler ZIA es el ejemplo que obliga -sus logs web no salen por la API de
ZIA, los empuja NSS-, pero es lo mismo con syslog, con los webhooks y con el HEC
de Splunk. Sin receptor, esas fuentes simplemente no entran.

Y un receptor es un sitio donde cualquiera que alcance el puerto puede volcar lo
que quiera. De ahi que lo primero que se escriba sea esto y no el parseo.
"""

from __future__ import annotations

import hmac
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, Optional, Tuple

log = logging.getLogger("glamdring.receive")

# Por debajo de esto una clave no protege nada: se adivina a fuerza bruta en un
# rato. Se rechaza al cargar la configuracion, con aviso, en vez de aceptarla y
# aparentar que el endpoint esta protegido, que es lo peligroso de verdad.
LONGITUD_MINIMA_CLAVE = 24

# Un envio son eventos, no un volcado del indice. 50 MB ya es generoso para un
# lote de NSS.
MAX_BYTES_ENVIO = 50 * 1024 * 1024

# Envios por minuto y por fuente.
ENVIOS_POR_MINUTO = 120


class ReceiveError(RuntimeError):
    """Rechazo del receptor, con el codigo HTTP que le corresponde."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


@dataclass
class ReceiveConfig:
    """Fuentes que pueden empujar, con su clave."""

    # fuente -> clave. Nunca se devuelve al exterior.
    keys: Dict[str, str] = field(default_factory=dict)
    max_bytes: int = MAX_BYTES_ENVIO
    per_minute: int = ENVIOS_POR_MINUTO

    @property
    def enabled(self) -> bool:
        """Sin ninguna clave configurada el receptor NO existe.

        Apagado por defecto y sin forma de encenderlo a medias: no hay modo
        "sin clave" ni para pruebas. Un receptor abierto en un portatil acaba
        copiado tal cual a un servidor.
        """
        return bool(self.keys)

    def sources(self) -> Tuple[str, ...]:
        return tuple(sorted(self.keys))


def parse_keys(raw: str) -> Dict[str, str]:
    """Lee ``fuente:clave,fuente:clave`` del entorno.

    Una clave POR FUENTE y no una global: asi se rota la de un cliente sin
    tocar las demas, y si se filtra la de un reenviador no queda abierto el
    resto. Es la diferencia entre revocar una cosa y revocarlo todo.

    Las claves cortas se descartan con aviso. Aceptar 'test' dejaria un endpoint
    que parece protegido y no lo esta, que es peor que no tenerlo.
    """
    salida: Dict[str, str] = {}
    for trozo in (raw or "").split(","):
        trozo = trozo.strip()
        if not trozo:
            continue
        if ":" not in trozo:
            log.warning("Entrada de GLAMDRING_RECEIVE_KEYS sin ':' ignorada.")
            continue
        fuente, clave = trozo.split(":", 1)
        fuente = fuente.strip().lower()
        clave = clave.strip()
        if not fuente or not clave:
            continue
        if len(clave) < LONGITUD_MINIMA_CLAVE:
            # El nombre de la fuente si se registra; la clave no, ni truncada.
            log.warning("La clave de la fuente '%s' tiene menos de %d caracteres y se "
                        "descarta. Genera una con: python -c \"import secrets; "
                        "print(secrets.token_urlsafe(32))\"",
                        fuente, LONGITUD_MINIMA_CLAVE)
            continue
        salida[fuente] = clave
    return salida


class RateLimiter:
    """Ventana deslizante de envios por fuente.

    En memoria del proceso, y hay que decirlo: con varios trabajadores de
    uvicorn cada uno lleva su propia cuenta, asi que el limite efectivo se
    multiplica por el numero de trabajadores. Para un despliegue de un solo
    proceso -que es lo que hay hoy- sirve; para varios hace falta algo
    compartido. Escrito aqui para que no se descubra el dia que se escale.
    """

    def __init__(self, per_minute: int) -> None:
        self.per_minute = per_minute
        self._marcas: Dict[str, Deque[float]] = {}

    def check(self, fuente: str, ahora: Optional[float] = None) -> None:
        if self.per_minute <= 0:
            return
        ahora = time.monotonic() if ahora is None else ahora
        marcas = self._marcas.setdefault(fuente, deque())
        limite = ahora - 60.0
        while marcas and marcas[0] < limite:
            marcas.popleft()
        if len(marcas) >= self.per_minute:
            espera = int(60 - (ahora - marcas[0])) + 1
            raise ReceiveError(429, f"Demasiados envios de '{fuente}'. "
                                    f"Reintenta en {espera}s.")
        marcas.append(ahora)

    def reset(self) -> None:
        self._marcas.clear()


def authorize(config: ReceiveConfig, fuente: str, presentada: Optional[str]) -> str:
    """Comprueba fuente y clave. Devuelve el nombre de fuente normalizado.

    DOS DECISIONES QUE PARECEN RARAS Y NO LO SON:

    1. ``hmac.compare_digest`` y no ``==``. La comparacion normal de cadenas
       para en el primer byte distinto, asi que tarda un poquito mas cuanto mas
       acierta el que prueba. Sobre un endpoint alcanzable por red eso permite
       ir sacando la clave caracter a caracter. compare_digest tarda lo mismo
       acierte lo que acierte.

    2. Una fuente que no existe devuelve 401, no 404. Distinguirlos convertiria
       el receptor en un listado de que integraciones tiene montadas la empresa:
       se prueba 'netskope', 'zscaler', 'crowdstrike' y el codigo de respuesta
       va contestando. El detalle se registra en el log, que es donde hace
       falta para depurar.
    """
    nombre = (fuente or "").strip().lower()

    if not config.enabled:
        raise ReceiveError(503, "El receptor no esta configurado (GLAMDRING_RECEIVE_KEYS).")

    esperada = config.keys.get(nombre)
    if esperada is None:
        log.warning("Envio rechazado: la fuente '%s' no esta configurada.", nombre[:40])
        raise ReceiveError(401, "Fuente o clave incorrecta.")

    if not presentada:
        raise ReceiveError(401, "Falta la cabecera X-Glamdring-Key.")

    if not hmac.compare_digest(presentada, esperada):
        log.warning("Envio rechazado: clave incorrecta para la fuente '%s'.", nombre)
        raise ReceiveError(401, "Fuente o clave incorrecta.")

    return nombre
