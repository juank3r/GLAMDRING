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

MAX_EVENTS = 500_000


def redact(value: Any, depth: int = 0) -> Any:
    """Tacha secretos recursivamente dentro de un registro crudo.

    El log crudo se ensena tal cual en el inspector, y los logs de autenticacion
    a veces arrastran credenciales en la linea de comandos o en cabeceras. Es mas
    barato tacharlas siempre que confiar en que nunca aparezcan.
    """
    if depth > 6:
        return value
    if isinstance(value, dict):
        return {
            key: (REDACTED if _SECRET_KEYS.search(str(key)) else redact(item, depth + 1))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [redact(item, depth + 1) for item in value]
    return value


class EventStore:
    """Coleccion de eventos con deduplicacion por uid y acceso concurrente."""

    def __init__(self) -> None:
        self._events: List[NormalizedEvent] = []
        self._by_uid: Dict[str, NormalizedEvent] = {}
        self._lock = threading.RLock()
        self.last_ingest: Optional[datetime] = None
        self.ingest_log: List[Dict[str, Any]] = []

    # -- lectura -----------------------------------------------------------

    @property
    def events(self) -> List[NormalizedEvent]:
        with self._lock:
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
            self._events.sort(key=lambda e: e.time)
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
        return {"added": added, "duplicates": duplicates, "dropped": dropped, "total": len(self._events)}

    def clear(self) -> None:
        with self._lock:
            self._events.clear()
            self._by_uid.clear()
            self.ingest_log.clear()
            self.last_ingest = None


# Instancia unica del proceso.
STORE = EventStore()
