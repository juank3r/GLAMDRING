"""Conector de ficheros: exports descargados del SIEM y ficheros de ejemplo.

Es el conector que mas se usa en la practica: el analista casi nunca tiene
credenciales de API del SIEM, pero siempre puede exportar el resultado de su
busqueda. Acepta lo que le echen (JSON, NDJSON, CSV, CEF, LEEF, syslog) y deja
que ``normalize.detect`` averigue de que se trata.

La lectura de rutas del servidor esta desactivada por defecto
(``GLAMDRING_ALLOW_FILE_PATHS``): un endpoint que lee rutas arbitrarias del
disco es una lectura de fichero local servida en bandeja.
"""

from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..config import SAMPLES_DIR, SETTINGS
from ..normalize.detect import parse_payload
from .base import Connector, ConnectorError

MAX_BYTES = 200 * 1024 * 1024  # 200 MB: por encima, esto no es una investigacion puntual


class FileConnector(Connector):
    name = "files"
    query_language = "ruta o fichero subido"
    example_query = "samples/splunk_windows.json"

    @property
    def configured(self) -> bool:
        return True

    async def fetch(
        self,
        query: str,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 10_000,
    ) -> List[Dict[str, Any]]:
        records, _fmt = self.read_path(query)
        return records[:limit]

    # -- lectura -----------------------------------------------------------

    def read_path(self, path: str) -> Tuple[List[Dict[str, Any]], str]:
        """Lee un fichero del disco del servidor. Solo si esta permitido."""
        target = Path(path)
        is_sample = _within(target, SAMPLES_DIR) or not target.is_absolute()

        if not is_sample and not SETTINGS.allow_file_paths:
            raise ConnectorError(
                self.name,
                "La lectura de rutas del servidor esta desactivada. "
                "Sube el fichero o activa GLAMDRING_ALLOW_FILE_PATHS=1.",
            )

        if not target.is_absolute():
            candidate = (SAMPLES_DIR / Path(path).name)
            target = candidate if candidate.exists() else Path(path).resolve()

        if not target.exists() or not target.is_file():
            raise ConnectorError(self.name, f"No existe el fichero: {path}")
        if target.stat().st_size > MAX_BYTES:
            raise ConnectorError(self.name, f"Fichero demasiado grande (>{MAX_BYTES // 1048576} MB).")

        text = target.read_text(encoding="utf-8", errors="replace")
        return parse_payload(text)

    def read_text(self, text: str, hint: str = "") -> Tuple[List[Dict[str, Any]], str]:
        """Contenido ya en memoria (una subida HTTP)."""
        if len(text.encode("utf-8", errors="ignore")) > MAX_BYTES:
            raise ConnectorError(self.name, f"Contenido demasiado grande (>{MAX_BYTES // 1048576} MB).")
        return parse_payload(text, hint=hint)

    def list_samples(self) -> List[Dict[str, Any]]:
        """Ficheros de ejemplo disponibles, para el boton 'Cargar demo'."""
        if not SAMPLES_DIR.exists():
            return []
        out = []
        for item in sorted(SAMPLES_DIR.iterdir()):
            if item.is_file() and item.suffix.lower() in (".json", ".ndjson", ".csv", ".cef", ".log", ".txt"):
                out.append({"name": item.name, "size": item.stat().st_size})
        return out


def _within(path: Path, parent: Path) -> bool:
    """True si ``path`` cuelga de ``parent`` (evita el ../../ clasico)."""
    try:
        path.resolve().relative_to(parent.resolve())
        return True
    except (ValueError, OSError):
        return False
