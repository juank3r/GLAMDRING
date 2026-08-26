"""Capa de normalizacion.

Importar este paquete registra todos los normalizadores. El orden de import no
importa: cada modulo se auto-registra con su prioridad y la lista se reordena.
"""

from .base import (  # noqa: F401
    normalize_all,
    normalize_record,
    parse_severity,
    parse_time,
    register,
    registry,
)

# Los imports que siguen tienen efecto secundario (register). No quitar.
from . import splunk_windows  # noqa: F401,E402
from . import sentinel_defender  # noqa: F401,E402
from . import qradar_events  # noqa: F401,E402
# Los proxies SASE van antes que el generico y antes que los cuatro SIEM: sus
# marcadores son inconfundibles, asi que no hay riesgo de que les roben
# registros a nadie.
from . import netskope  # noqa: F401,E402
from . import zscaler  # noqa: F401,E402
from . import cef  # noqa: F401,E402

from .detect import detect_format, parse_payload  # noqa: F401,E402

__all__ = [
    "normalize_all",
    "normalize_record",
    "parse_time",
    "parse_severity",
    "register",
    "registry",
    "detect_format",
    "parse_payload",
]
