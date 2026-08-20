"""Deteccion de formato de un fichero subido y troceado en registros.

El analista arrastra "lo que le ha dado el SIEM" sin saber ni como se llama el
formato. Aqui se decide si es JSON, NDJSON, CSV, CEF/LEEF o syslog y se
convierte en una lista de diccionarios; quien los interpreta despues es la capa
de normalizadores.
"""

from __future__ import annotations

import csv
import io
import json
from typing import Any, Dict, List, Tuple

from .cef import parse_line

# Claves donde los SIEM esconden la lista de resultados dentro de un JSON envolvente.
_RESULT_KEYS = ("results", "events", "value", "records", "data", "hits", "rows")


def detect_format(text: str) -> str:
    """Devuelve 'json' | 'ndjson' | 'csv' | 'cef' | 'syslog' | 'empty'."""
    sample = text.lstrip()
    if not sample:
        return "empty"

    if sample[0] in "[{":
        # Varios objetos JSON pegados uno por linea es NDJSON, no JSON.
        try:
            json.loads(text)
            return "json"
        except ValueError:
            return "ndjson"

    head = [line for line in sample.splitlines()[:20] if line.strip()]
    if any("CEF:" in line or "LEEF:" in line for line in head):
        return "cef"
    if head and head[0].startswith("<") and ">" in head[0][:5]:
        return "syslog"

    if head:
        first_line = head[0]
        # CSV: separadores consistentes y sin pinta de mensaje de log.
        commas = first_line.count(",")
        if commas >= 2 and "=" not in first_line[:40]:
            return "csv"

    return "syslog"


def _unwrap(payload: Any) -> List[Dict[str, Any]]:
    """Saca la lista de eventos de dentro del sobre JSON del fabricante."""
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict):
        for key in _RESULT_KEYS:
            value = payload.get(key)
            if isinstance(value, list):
                return [item for item in value if isinstance(item, dict)]
            # Elasticsearch: hits.hits[]._source
            if key == "hits" and isinstance(value, dict) and isinstance(value.get("hits"), list):
                return [item.get("_source", item) for item in value["hits"] if isinstance(item, dict)]
        # Tabla de Log Analytics: {tables:[{name, columns, rows}]}
        tables = payload.get("tables")
        if isinstance(tables, list):
            out: List[Dict[str, Any]] = []
            for table in tables:
                columns = [c.get("name") if isinstance(c, dict) else str(c) for c in table.get("columns", [])]
                for row in table.get("rows", []):
                    record = dict(zip(columns, row))
                    record.setdefault("Type", table.get("name", ""))
                    out.append(record)
            return out
        return [payload]
    return []


def parse_payload(text: str, hint: str = "") -> Tuple[List[Dict[str, Any]], str]:
    """Texto -> (registros, formato detectado).

    ``hint`` permite forzar el formato cuando la deteccion se equivoca (p.ej. un
    CSV cuya primera fila lleva comas dentro de un mensaje).
    """
    fmt = hint or detect_format(text)

    if fmt == "empty":
        return [], fmt

    if fmt == "json":
        try:
            return _unwrap(json.loads(text)), fmt
        except ValueError:
            fmt = "ndjson"

    if fmt == "ndjson":
        records: List[Dict[str, Any]] = []
        for line in text.splitlines():
            line = line.strip().rstrip(",")
            if not line or line in ("[", "]"):
                continue
            try:
                parsed = json.loads(line)
            except ValueError:
                continue
            records.extend(_unwrap(parsed))
        return records, fmt

    if fmt == "csv":
        try:
            dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        records = []
        for row in reader:
            # DictReader mete None en la clave sobrante de filas mal formadas.
            records.append({k: v for k, v in row.items() if k is not None})
        return records, fmt

    # cef | leef | syslog: linea a linea
    records = []
    for line in text.splitlines():
        parsed = parse_line(line)
        if parsed:
            records.append(parsed)
    return records, fmt
