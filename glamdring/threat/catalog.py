"""Catalogo de inteligencia de amenazas: carga e indexado.

Los datos son ficheros JSON vendorizados en `data/`, generados por
`tools/fetch_threat_intel.py`. No se descarga nada en tiempo de ejecucion: la
herramienta tiene que arrancar en un portatil aislado.

El indice mas importante es `pattern_index`: nombre de ejecutable -> herramienta.
Convierte la deteccion en una busqueda en diccionario en lugar de comparar cada
linea de comandos contra ochocientos patrones, que con cien mil eventos es la
diferencia entre un segundo y un minuto.
"""

from __future__ import annotations

import json
import re
import threading
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

DATA_DIR = Path(__file__).resolve().parent / "data"

_lock = threading.RLock()


def _load(name: str) -> Any:
    path = DATA_DIR / name
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        # Un fichero de datos corrupto degrada la deteccion, no tumba la
        # herramienta: sin catalogo el grafo se sigue construyendo igual.
        return {}


class Catalog:
    """Catalogo cargado y con sus indices ya montados."""

    def __init__(self) -> None:
        self.tools: Dict[str, Dict[str, Any]] = _load("tools.json")
        self.groups: Dict[str, Dict[str, Any]] = _load("groups.json")
        self.notes: Dict[str, Dict[str, Any]] = _load("ransomnotes.json")
        self.meta: Dict[str, Any] = _load("meta.json")

        # nombre de ejecutable (minusculas) -> nombre de herramienta
        self.pattern_index: Dict[str, str] = {}
        # subcadenas que solo se buscan en lineas de comandos (p. ej. 'sekurlsa')
        self.fragment_index: Dict[str, str] = {}

        for name, tool in self.tools.items():
            for pattern in tool.get("patterns", []):
                key = pattern.lower().strip()
                if not key:
                    continue
                if key.endswith((".exe", ".dll", ".sys", ".ps1", ".py", ".com", ".bat")):
                    self.pattern_index.setdefault(key, name)
                else:
                    # Sin extension: es un fragmento (nombre de proyecto, verbo
                    # de mimikatz...). Se busca solo dentro de la linea de
                    # comandos y con un minimo de longitud, para no disparar
                    # con cualquier cosa.
                    if len(key) >= 5:
                        self.fragment_index.setdefault(key, name)

        # nombre de nota (minusculas) -> entrada
        self.note_index: Dict[str, Dict[str, Any]] = {
            key.lower(): value for key, value in self.notes.items()
        }

        # Cuantos grupos usan cada herramienta: base del peso discriminante.
        self.group_count = max(len(self.groups), 1)
        self.tool_group_count: Dict[str, int] = {
            name: len(tool.get("groups", [])) for name, tool in self.tools.items()
        }

    # -- consultas ---------------------------------------------------------

    def tool(self, name: str) -> Optional[Dict[str, Any]]:
        return self.tools.get(name)

    def group(self, name: str) -> Optional[Dict[str, Any]]:
        return self.groups.get(name)

    def tool_for_binary(self, binary: str) -> Optional[str]:
        """Nombre de ejecutable -> herramienta conocida, o None."""
        if not binary:
            return None
        return self.pattern_index.get(binary.lower().strip())

    def note_for_filename(self, filename: str) -> Optional[Dict[str, Any]]:
        if not filename:
            return None
        return self.note_index.get(filename.lower().strip())

    def discriminating_weight(self, tool_name: str) -> float:
        """Cuanto distingue esta herramienta a un grupo de los demas.

        PsExec lo usa todo el mundo y no dice nada; 'Zemana Anti-Rootkit' lo usan
        dos grupos y es una pista de verdad. Es la idea del IDF de recuperacion
        de informacion aplicada a la atribucion.

        Una herramienta que no aparece en ningun perfil pesa 1.0: no resta, pero
        tampoco inventa una relacion que no tenemos documentada.
        """
        usada_por = self.tool_group_count.get(tool_name, 0)
        if usada_por <= 0:
            return 1.0
        import math

        return 1.0 + math.log(self.group_count / usada_por)

    @property
    def available(self) -> bool:
        return bool(self.tools)

    def stats(self) -> Dict[str, Any]:
        return {
            "tools": len(self.tools),
            "groups": len(self.groups),
            "ransomNotes": len(self.notes),
            "binaryPatterns": len(self.pattern_index),
            "generated": self.meta.get("generated"),
            "sources": self.meta.get("sources", []),
            "caveat": self.meta.get("caveat", ""),
        }


_catalog: Optional[Catalog] = None


def catalog() -> Catalog:
    """Catalogo compartido del proceso, cargado la primera vez que se pide."""
    global _catalog
    with _lock:
        if _catalog is None:
            _catalog = Catalog()
        return _catalog


def reload_catalog() -> Catalog:
    """Fuerza la relectura de los ficheros (util en tests y tras actualizar)."""
    global _catalog
    with _lock:
        _catalog = Catalog()
        return _catalog


# ---------------------------------------------------------------------------
# Tokenizacion de lineas de comandos
# ---------------------------------------------------------------------------

# Separadores tipicos de una linea de comandos de Windows. Se parte por todos a
# la vez para quedarse con los nombres de fichero sueltos.
_SPLIT = re.compile(r"[\s\"'`|&;,()<>]+")


@lru_cache(maxsize=4096)
def binaries_in(cmdline: str) -> tuple:
    """Nombres de ejecutable que aparecen en una linea de comandos.

    Se tokeniza y se extrae el ultimo segmento de cada ruta, en lugar de buscar
    ochocientos patrones dentro del texto. Ademas de ser mucho mas rapido, evita
    el falso positivo clasico: 'C:\\Users\\rclone-backup\\informe.docx' no es
    rclone.
    """
    if not cmdline:
        return ()
    salida: Set[str] = set()
    for token in _SPLIT.split(cmdline.lower()):
        if not token:
            continue
        base = token.replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1]
        if base:
            salida.add(base)
        # 'rclone.exe:algo' o 'mimikatz.exe,arg'
        if ":" in base:
            salida.add(base.split(":", 1)[0])
    return tuple(salida)


def basename_of(path: str) -> str:
    if not path:
        return ""
    return str(path).replace("/", "\\").rstrip("\\").rsplit("\\", 1)[-1].lower()
