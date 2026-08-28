"""Almacen en memoria de los eventos de la sesion de investigacion.

Deliberadamente simple: un proceso, una investigacion. Es lo correcto para el
caso de uso real (un analista triando un incidente en su portatil) y evita
arrastrar una base de datos para algo que cabe de sobra en RAM: 100.000 eventos
normalizados rondan los 200 MB.

Cuando haga falta multiusuario, esta clase es la unica pieza que cambia: se
sustituye por un backend con clave de sesion (Redis, DuckDB o Postgres) y el
resto del sistema no se entera, porque nadie mas toca los eventos directamente.
"""

from __future__ import annotations

import re
import threading
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence

from .models import NormalizedEvent

# Campos cuyo valor jamas debe salir del backend, ni siquiera dentro de `raw`.
_SECRET_KEYS = re.compile(
    r"(password|passwd|pwd|secret|token|api[_-]?key|authorization|credential|"
    r"client[_-]?secret|private[_-]?key|session[_-]?key|cookie)",
    re.I,
)

REDACTED = "***redactado***"

# Secretos reconocibles POR SU FORMA, esten donde esten.
#
# Tachar solo por nombre de clave deja pasar el caso mas comun de todos: el
# secreto dentro de una cadena. Un `curl -H "Authorization: Bearer eyJ..."` en
# una linea de comandos, una cadena de conexion con la contrasena dentro, o un
# token en el cuerpo de un mensaje syslog. El campo se llama `cmdline` o
# `message`, no `password`, asi que la lista de nombres no lo veia.
#
# Cada patron tacha SOLO el secreto y deja el resto de la linea legible: la
# linea de comandos es evidencia y borrarla entera seria perder el hallazgo por
# proteger la credencial.
_SECRET_VALUES = [
    # Cabecera de autorizacion entera, incluido el esquema. Capturar solo hasta
    # el primer espacio tachaba la palabra "Bearer" y dejaba el token detras,
    # que es exactamente lo contrario de lo que hace falta.
    re.compile(r"((?:proxy-)?authorization\s*[:=]\s*)([^\"'\r\n]{8,})", re.I),
    # JWT suelto, sin cabecera delante.
    re.compile(r"()(eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})"),
    # Esquema + credencial larga en cualquier sitio.
    re.compile(r"\b((?:bearer|basic|splunk)\s+)([A-Za-z0-9._\-+/=]{16,})", re.I),
    # clave=valor con nombre sospechoso, en texto libre o en linea de comandos.
    re.compile(r"((?:password|passwd|pwd|secret|token|apikey|api[_-]key|client[_-]secret)"
               r"\s*[:=]\s*)([^\s,;&\"']{4,})", re.I),
    # -p contrasena / --password contrasena, tipico de clientes de linea.
    re.compile(r"(--?(?:p|pass|password|token)[ =])([^\s]{4,})", re.I),
    # Credenciales dentro de una URL.
    re.compile(r"(://[^\s:/@]{1,64}:)([^\s@]{1,128})(@)"),
]

MAX_EVENTS = 500_000


def _redact_text(text: str) -> str:
    """Tacha los secretos que se reconocen por su forma dentro de una cadena."""
    if len(text) < 8:
        return text
    # CONVENCION, y hay que respetarla al anadir patrones:
    #   grupo 1 = prefijo, se conserva (dice QUE era: util para investigar)
    #   grupo 2 = el secreto, se tacha
    #   grupo 3 = cierre opcional, se conserva
    # Un patron sin grupo 1 dejaria el secreto intacto y tacharia lo de al lado,
    # que es como se me colo un JWT entero en la primera version.
    for patron in _SECRET_VALUES:
        text = patron.sub(
            lambda m: (m.group(1) or "") + REDACTED
                      + (m.group(3) if (m.lastindex or 0) >= 3 else ""),
            text,
        )
    return text


def redact(value: Any, depth: int = 0) -> Any:
    """Tacha secretos recursivamente dentro de un registro crudo.

    El log crudo se ensena tal cual en el inspector, y los logs de autenticacion
    a veces arrastran credenciales. Es mas barato tacharlas siempre que confiar
    en que nunca aparezcan.

    Se tacha por DOS vias, porque una sola no basta:
      - por nombre de clave, para los campos que se llaman lo que se llaman;
      - por forma del valor, para el secreto que viaja dentro de una cadena, que
        es el caso mas frecuente y el que la lista de nombres no veia.
    """
    if depth > 6:
        # Pasado el fondo se PODA, no se devuelve el original: devolverlo tal
        # cual era una puerta trasera: bastaba con anidar siete niveles para que
        # el secreto saliera entero.
        return REDACTED if isinstance(value, (dict, list)) else _redact_text(str(value))
    if isinstance(value, dict):
        return {
            key: (REDACTED if _SECRET_KEYS.search(str(key)) else redact(item, depth + 1))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, depth + 1) for item in value]
    if isinstance(value, str):
        return _redact_text(value)
    return value


class EventStore:
    """Coleccion de eventos con deduplicacion por uid y acceso concurrente."""

    def __init__(self) -> None:
        self._events: List[NormalizedEvent] = []
        self._by_uid: Dict[str, NormalizedEvent] = {}
        self._lock = threading.RLock()
        self.last_ingest: Optional[datetime] = None
        self.ingest_log: List[Dict[str, Any]] = []
        # Sube cada vez que el contenido cambia. Es lo que permite cachear el
        # grafo construido sin miedo: mientras no suba, lo cacheado sigue
        # valiendo, y cuando sube todo lo anterior caduca de golpe.
        self._version = 0
        # QUIEN es este almacen, no solo cuantas veces ha cambiado.
        #
        # `version` empieza en 0 en CADA instancia, asi que dos almacenes recien
        # cargados estan los dos en la version 1. La cache de grafos usa la
        # version como parte de su clave, y con dos incidentes cargados a la vez
        # eso colisiona: se devuelve el grafo del otro. No falla y no avisa, y
        # ademas es verosimil, que es lo peor que puede pasarle a una
        # herramienta forense.
        self._id = uuid.uuid4().hex[:12]
        # Si la lista esta ordenada por tiempo ahora mismo. Una lista vacia lo
        # esta. Se pone en False al anadir y se resuelve al leer.
        self._ordenado = True

    @property
    def store_id(self) -> str:
        """Identidad estable de este almacen, para no confundirlo con otro."""
        return self._id

    @property
    def version(self) -> int:
        """Cuantas veces ha cambiado el contenido desde el arranque."""
        with self._lock:
            return self._version

    # -- lectura -----------------------------------------------------------

    @property
    def events(self) -> List[NormalizedEvent]:
        """Los eventos, ordenados por tiempo.

        SE ORDENA AL LEER, NO AL ESCRIBIR, y la diferencia es grande cuando
        entra mucho de golpe.

        Antes `add()` reordenaba la lista ENTERA en cada llamada. Medido, lo que
        costaba anadir UN evento segun lo que ya hubiera dentro:

            50.000 eventos ->  30 ms
           200.000 eventos ->  99 ms
           400.000 eventos -> 325 ms

        El receptor admite 120 envios por minuto y por fuente, y cada uno de
        esos envios se llevaba el `RLock` cientos de milisegundos con el almacen
        medio lleno: no solo se ralentiza quien empuja, se para el analista que
        estaba mirando su grafo.

        Ahora N ingestas seguidas cuestan lo que ocupan, y el orden se paga una
        sola vez cuando alguien mira. Ordenar una lista que ya esta ordenada
        salvo por la cola es casi gratis: Timsort reconoce los tramos.
        """
        with self._lock:
            if not self._ordenado:
                self._events.sort(key=lambda e: e.time)
                self._ordenado = True
            return list(self._events)

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    def get(self, uid: str) -> Optional[NormalizedEvent]:
        with self._lock:
            return self._by_uid.get(uid)

    def get_many(self, uids: Sequence[str], limit: int = 500) -> List[NormalizedEvent]:
        """Eventos por uid, en el orden pedido y sin repetir."""
        with self._lock:
            out: List[NormalizedEvent] = []
            seen = set()
            for uid in uids:
                if uid in seen or len(out) >= limit:
                    continue
                event = self._by_uid.get(uid)
                if event is not None:
                    seen.add(uid)
                    out.append(event)
            return out

    def sources(self) -> List[str]:
        with self._lock:
            return sorted({event.source for event in self._events})

    def span(self) -> Dict[str, Optional[datetime]]:
        with self._lock:
            if not self._events:
                return {"from": None, "to": None}
            times = [event.time for event in self._events]
            return {"from": min(times), "to": max(times)}

    # -- escritura ---------------------------------------------------------

    def add(self, events: Iterable[NormalizedEvent], origin: str = "") -> Dict[str, int]:
        """Anade eventos nuevos. Devuelve el recuento de nuevos y duplicados."""
        added = 0
        duplicates = 0
        dropped = 0
        with self._lock:
            for event in events:
                if event.uid in self._by_uid:
                    duplicates += 1
                    continue
                if len(self._events) >= MAX_EVENTS:
                    dropped += 1
                    continue
                event.raw = redact(event.raw)
                self._by_uid[event.uid] = event
                self._events.append(event)
                added += 1
            if added:
                # NO se ordena aqui. Se marca y ya: quien lea pagara el orden
                # una vez, en vez de pagarlo cada uno de los que escriben.
                self._ordenado = False
            self.last_ingest = datetime.now(timezone.utc)
            entry = {
                "origin": origin,
                "added": added,
                "duplicates": duplicates,
                "dropped": dropped,
                "total": len(self._events),
            }
            self.ingest_log.append(entry)
            if len(self.ingest_log) > 50:
                self.ingest_log = self.ingest_log[-50:]
            # Solo si de verdad entro algo: una ingesta de puros duplicados no
            # cambia el grafo y tirar la cache por eso seria gratuito.
            if added:
                self._version += 1
        return {"added": added, "duplicates": duplicates, "dropped": dropped, "total": len(self._events)}

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._ordenado = True
            self._by_uid.clear()
            self.ingest_log.clear()
            self.last_ingest = None
            self._version += 1


# Instancia unica del proceso.
STORE = EventStore()
