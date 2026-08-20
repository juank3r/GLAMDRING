"""Fixtures compartidas. Los tests no necesitan red ni credenciales de SIEM."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from glamdring.config import SAMPLES_DIR  # noqa: E402
from glamdring.normalize import normalize_all, parse_payload  # noqa: E402
from glamdring.store import STORE  # noqa: E402


def load_sample(name: str) -> List[Dict[str, Any]]:
    """Registros crudos de un fichero de samples/, ya troceados."""
    text = (SAMPLES_DIR / name).read_text(encoding="utf-8")
    records, _fmt = parse_payload(text)
    return records


@pytest.fixture
def splunk_records() -> List[Dict[str, Any]]:
    return load_sample("splunk_windows.json")


@pytest.fixture
def sentinel_records() -> List[Dict[str, Any]]:
    return load_sample("sentinel_defender.json")


@pytest.fixture
def qradar_records() -> List[Dict[str, Any]]:
    return load_sample("qradar_ariel.json")


@pytest.fixture
def cef_records() -> List[Dict[str, Any]]:
    return load_sample("perimeter.cef")


@pytest.fixture
def all_events():
    """Todos los ficheros de ejemplo normalizados en una sola lista."""
    records: List[Dict[str, Any]] = []
    for name in ("splunk_windows.json", "sentinel_defender.json",
                 "qradar_ariel.json", "perimeter.cef"):
        records.extend(load_sample(name))
    return normalize_all(records)


@pytest.fixture(autouse=True)
def clean_store():
    """El almacen es un singleton: sin esto los tests se contaminarian."""
    STORE.clear()
    yield
    STORE.clear()
