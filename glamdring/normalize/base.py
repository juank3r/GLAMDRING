"""Base de los normalizadores: registro, despacho y utilidades compartidas.

Un normalizador implementa dos cosas:

    matches(record)   -> True si sabe interpretar ese registro
    normalize(record) -> NormalizedEvent | None

El registro esta ordenado por prioridad: gana el primero que dice "esto es mio".
Los especificos (Splunk Windows, Defender, QRadar) van antes que el generico,
que nunca falla y sirve de red de seguridad.
"""

from __future__ import annotations

import math
import re
from datetime import datetime, timezone
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from ..models import NormalizedEvent

# ---------------------------------------------------------------------------
# Registro
# ---------------------------------------------------------------------------

Matcher = Callable[[Dict[str, Any]], bool]
Normalizer = Callable[[Dict[str, Any]], Optional[NormalizedEvent]]

_REGISTRY: List[Tuple[int, str, Matcher, Normalizer]] = []


def register(name: str, matcher: Matcher, normalizer: Normalizer, priority: int = 50) -> None:
    """Da de alta un normalizador. Menor ``priority`` = se evalua antes."""
    _REGISTRY.append((priority, name, matcher, normalizer))
    _REGISTRY.sort(key=lambda item: item[0])


def registry() -> List[Tuple[int, str, Matcher, Normalizer]]:
    return list(_REGISTRY)


def normalize_record(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    """Traduce un registro crudo al primer normalizador que lo reconozca."""
    for _priority, _name, matcher, normalizer in _REGISTRY:
        try:
            if not matcher(record):
                continue
            event = normalizer(record)
        except Exception:
            # Un normalizador roto no puede tumbar la ingesta entera: se pasa al
            # siguiente candidato y, en ultimo termino, al generico.
            continue
        if event is not None:
            return event
        # Reclamo el registro pero no supo convertirlo: no puede quedarselo y
        # hacerlo desaparecer. Se sigue probando; el generico lo recogera.
    return None


def normalize_all(records: Iterable[Dict[str, Any]]) -> List[NormalizedEvent]:
    out: List[NormalizedEvent] = []
    for record in records:
        if not isinstance(record, dict):
            continue
        event = normalize_record(record)
        if event is not None:
            out.append(event)
    return out


# ---------------------------------------------------------------------------
# Tiempo
# ---------------------------------------------------------------------------

# El orden importa: se prueban de mas especifico a menos, para que un formato
# CON ano no lo capture antes uno sin ano.
_TIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%fZ",
    "%Y-%m-%dT%H:%M:%SZ",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%m/%d/%Y %I:%M:%S %p",
    "%m/%d/%Y %H:%M:%S",
    "%d/%m/%Y %H:%M:%S",
    # CEF escribe 'rt' asi: "Aug 19 2026 09:16:02". Sin esta entrada, TODOS los
    # eventos CEF caian a la hora actual y el incidente parecia estar pasando
    # ahora mismo, con la cronologia y el informe estirados hasta hoy.
    "%b %d %Y %H:%M:%S",
    "%b %d %Y %H:%M:%S.%f",
    "%d %b %Y %H:%M:%S",
    # Syslog RFC3164: sin ano. Va el ultimo a proposito.
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",
)


def parse_time(value: Any, default: Optional[datetime] = None) -> datetime:
    """Convierte a datetime UTC lo que sea que traiga el SIEM.

    Acepta epoch en segundos o milisegundos (QRadar usa ms), ISO-8601 con y sin
    zona, y los formatos de fecha tipicos de Windows y syslog.
    """
    if value is None or value == "":
        return default or datetime.now(timezone.utc)

    if isinstance(value, datetime):
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)

    if isinstance(value, (int, float)):
        seconds = float(value)
        # Por encima de 1e11 son milisegundos (QRadar 'starttime').
        if seconds > 1e11:
            seconds /= 1000.0
        return datetime.fromtimestamp(seconds, tz=timezone.utc)

    text = str(value).strip()

    # Cadena numerica -> epoch
    if re.fullmatch(r"\d{10,16}(\.\d+)?", text):
        return parse_time(float(text), default)

    # ISO con 'Z' -> python <3.11 no acepta la Z en fromisoformat
    iso_text = text.replace("Z", "+00:00") if text.endswith("Z") else text
    try:
        parsed = datetime.fromisoformat(iso_text)
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass

    for fmt in _TIME_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            if parsed.year == 1900:  # syslog RFC3164 no lleva ano
                parsed = parsed.replace(year=datetime.now(timezone.utc).year)
            return parsed.astimezone(timezone.utc) if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue

    return default or datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Severidad
# ---------------------------------------------------------------------------

_SEVERITY_WORDS = {
    "informational": 1, "information": 1, "info": 1, "low": 2, "baja": 2,
    "medium": 3, "moderate": 3, "media": 3, "warning": 3, "warn": 3,
    "high": 4, "alta": 4, "error": 4,
    "critical": 5, "critica": 5, "severe": 5, "fatal": 5, "emergency": 5,
}


def parse_severity(value: Any, scale_max: int = 10) -> int:
    """Lleva cualquier escala de severidad al 0-5 de la ontologia.

    Sentinel usa palabras, QRadar magnitud 1-10, CEF 0-10. ``scale_max`` dice
    de que escala numerica venimos.
    """
    if value is None or value == "":
        return 1
    if isinstance(value, str):
        word = value.strip().lower()
        if word in _SEVERITY_WORDS:
            return _SEVERITY_WORDS[word]
        try:
            value = float(word)
        except ValueError:
            return 1
    try:
        number = float(value)
    except (TypeError, ValueError):
        return 1
    # Se redondea hacia arriba en los empates (2.5 -> 3) en lugar de usar el
    # redondeo bancario de round(), que en una escala de riesgo siempre debe
    # errar por exceso: magnitud 9 de QRadar es critica, no alta.
    if scale_max <= 5:
        return max(0, min(5, _round_half_up(number)))
    return max(0, min(5, _round_half_up(number / float(scale_max) * 5)))


def _round_half_up(value: float) -> int:
    return int(math.floor(value + 0.5))


# ---------------------------------------------------------------------------
# Normalizacion canonica de identificadores
#
# Sin esto, 'CORP\\jlopez', 'JLOPEZ' y 'jlopez@corp.com' serian tres nodos
# distintos y el grafo mentiria. Es la pieza mas importante de todo el modulo.
# ---------------------------------------------------------------------------

_MACHINE_ACCOUNT = re.compile(r"^[A-Za-z0-9_-]+\$$")


def canon_user(value: Optional[str]) -> Optional[str]:
    """'CORP\\JLopez' | 'jlopez@corp.com' | 'JLOPEZ' -> 'jlopez'."""
    if not value:
        return None
    text = str(value).strip()
    if not text or text in ("-", "N/A", "null", "NULL"):
        return None
    if "\\" in text:  # DOMINIO\usuario
        text = text.rsplit("\\", 1)[-1]
    if "@" in text:  # UPN
        text = text.split("@", 1)[0]
    text = text.strip().lower()
    if text in ("system", "local service", "network service", "anonymous logon", "-"):
        return None  # cuentas de servicio de Windows: ruido puro en el grafo
    if _MACHINE_ACCOUNT.match(text):
        return None  # cuentas de maquina (WKS-0421$)
    return text or None


def canon_host(value: Optional[str]) -> Optional[str]:
    """'WKS-0421.corp.local' -> 'wks-0421'. Deja pasar las IP tal cual."""
    if not value:
        return None
    text = str(value).strip().strip(".")
    if not text or text in ("-", "N/A", "null", "NULL"):
        return None
    if is_ip(text):
        return text
    return text.split(".", 1)[0].lower() or None


def canon_path(value: Optional[str]) -> Optional[str]:
    """Rutas en minusculas con separador unificado; NTFS no distingue mayusculas."""
    if not value:
        return None
    text = str(value).strip().strip('"')
    if not text or text == "-":
        return None
    return text.replace("/", "\\").lower()


# Un nombre de host valido: etiquetas alfanumericas separadas por puntos. No se
# valida el TLD a proposito, porque en redes internas abundan los dominios que
# no existen en Internet (corp.local, ad.interno).
_HOSTNAME = re.compile(r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
                       r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")


def canon_domain(value: Optional[str]) -> Optional[str]:
    """Extrae el dominio de lo que le echen, o None si no hay dominio dentro.

    Los SIEM meten en el mismo campo dominios pelados, URLs completas, host con
    puerto y hasta correos. Antes esto aceptaba cualquier cosa, y una URL entera
    acababa siendo un nodo de tipo 'dominio' y, peor, un indicador de compromiso
    con la ruta pegada. Ahora se recorta y se valida la forma.
    """
    if not value:
        return None
    text = str(value).strip().lower()
    if not text or text in ("-", "n/a", "null", "none"):
        return None

    if "//" in text:            # https://host/ruta -> host/ruta
        text = text.split("//", 1)[1]
    text = text.split("/", 1)[0]   # host/ruta        -> host
    text = text.split("?", 1)[0]
    if "@" in text:             # usuario@host       -> host
        text = text.rsplit("@", 1)[1]
    text = text.split(":", 1)[0]   # host:8443        -> host
    text = text.strip().strip(".")

    # Se exige al menos un punto: sin el, 'host' o la letra de una unidad ('c:'
    # de C:\Windows\Temp) colarian como dominios. Un nombre de una sola etiqueta
    # es un host, y como host se modela.
    if not text or "." not in text or is_ip(text) or not _HOSTNAME.match(text):
        return None
    return text


_IPV4 = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def is_ip(value: Optional[str]) -> bool:
    if not value:
        return False
    text = str(value).strip()
    if _IPV4.match(text):
        return all(0 <= int(part) <= 255 for part in text.split("."))
    return ":" in text and all(c in "0123456789abcdefABCDEF:" for c in text)


def is_private_ip(value: Optional[str]) -> bool:
    """RFC1918 / loopback / link-local. Se usa para decidir que es 'interno'."""
    if not value or not _IPV4.match(str(value).strip()):
        return False
    octets = [int(p) for p in str(value).strip().split(".")]
    if octets[0] == 10 or octets[0] == 127:
        return True
    if octets[0] == 192 and octets[1] == 168:
        return True
    if octets[0] == 172 and 16 <= octets[1] <= 31:
        return True
    if octets[0] == 169 and octets[1] == 254:
        return True
    return False


def basename(path: Optional[str]) -> Optional[str]:
    if not path:
        return None
    text = str(path).replace("/", "\\").rstrip("\\")
    return text.rsplit("\\", 1)[-1] or None


def first(record: Dict[str, Any], *keys: str) -> Optional[Any]:
    """Primer valor no vacio entre varias claves candidatas.

    Los SIEM llaman al mismo campo de diez maneras; esto evita diez ifs.
    """
    for key in keys:
        if key in record:
            value = record[key]
            if value not in (None, "", "-", "N/A"):
                return value
    return None


def to_int(value: Any) -> Optional[int]:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return None
