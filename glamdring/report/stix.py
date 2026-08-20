"""Exportacion estructurada: JSON completo, STIX-lite y lista plana de IOCs.

**STIX-lite, no STIX 2.1.** Se generan objetos con la forma de STIX (tipo,
identificador, patron, marcas de tiempo) para que sean utiles y reconocibles,
pero sin bundle firmado, sin relaciones completas y sin el vocabulario entero.
Sirve para alimentar un TIP o una regla de bloqueo; no para presumir de
cumplimiento del estandar. Decirlo aqui evita que alguien lo asuma.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, List

# Como se escribe cada tipo de indicador en un patron STIX.
PATTERNS = {
    "ip": "[ipv4-addr:value = '{value}']",
    "domain": "[domain-name:value = '{value}']",
    "url": "[url:value = '{value}']",
    "hash": "[file:hashes.'SHA-256' = '{value}']",
    "file": "[file:name = '{value}']",
    "mailbox": "[email-addr:value = '{value}']",
}

LABELS = {
    "ip": "malicious-activity", "domain": "malicious-activity",
    "url": "malicious-activity", "hash": "malicious-activity",
    "file": "anomalous-activity", "mailbox": "malicious-activity",
}


def _deterministic_id(prefix: str, value: str) -> str:
    """Identificador estable derivado del valor.

    Se usa un hash del indicador en lugar de un UUID aleatorio para que
    reexportar el mismo incidente no genere objetos nuevos cada vez y el TIP de
    destino acabe con duplicados.
    """
    digest = hashlib.sha256(f"{prefix}:{value}".encode("utf-8")).hexdigest()
    return (f"{prefix}--{digest[0:8]}-{digest[8:12]}-{digest[12:16]}-"
            f"{digest[16:20]}-{digest[20:32]}")


def render_stix(report: Dict[str, Any]) -> str:
    objects: List[Dict[str, Any]] = []
    created = report["generated"]

    objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": _deterministic_id("report", report["title"] + created),
        "created": created,
        "modified": created,
        "name": report["title"],
        "description": (
            f"{report['summary']['events']} eventos correlados desde "
            f"{', '.join(report['summary']['sources'])}. "
            f"Severidad maxima: {report['summary']['maxSeverityLabel']}."
        ),
        "published": created,
        "labels": ["threat-report"],
        "x_glamdring_tactics": report["summary"]["tactics"],
        "x_glamdring_note": "STIX-lite generado por GLAMDRING; no es un bundle STIX 2.1 completo.",
    })

    for kind, items in report["iocs"].items():
        pattern = PATTERNS.get(kind)
        if not pattern:
            continue
        for item in items:
            value = str(item["value"]).replace("'", "\\'")
            objects.append({
                "type": "indicator",
                "spec_version": "2.1",
                "id": _deterministic_id("indicator", f"{kind}:{item['value']}"),
                "created": created,
                "modified": created,
                "name": f"{kind}: {item['value']}",
                "pattern": pattern.format(value=value),
                "pattern_type": "stix",
                "valid_from": item.get("firstSeen") or created,
                "labels": [LABELS.get(kind, "anomalous-activity")],
                "confidence": min(100, int(item.get("risk", 0))),
                "x_glamdring_role": item.get("role"),
                "x_glamdring_sources": item.get("sources", []),
            })

    return json.dumps(
        {"type": "bundle", "id": _deterministic_id("bundle", created), "objects": objects},
        indent=2, ensure_ascii=False,
    )


def render_json(report: Dict[str, Any], include_image: bool = False) -> str:
    """El informe entero. La imagen se excluye salvo que se pida.

    Un data-URL de PNG son cientos de kilobytes de base64 que hacen ilegible el
    JSON y rompen cualquier diff.
    """
    payload = dict(report)
    if not include_image:
        payload.pop("image", None)
    return json.dumps(payload, indent=2, ensure_ascii=False)


ORDER = ["ip", "domain", "url", "hash", "file", "mailbox"]

SECTION_TITLES = {
    "ip": "IPs externas", "domain": "Dominios", "url": "URLs",
    "hash": "Hashes SHA-256", "file": "Rutas de fichero", "mailbox": "Buzones",
}


def render_flat(report: Dict[str, Any], with_headers: bool = True) -> str:
    """Lista plana lista para pegar en un firewall, un EDR o una regla.

    Con ``with_headers=False`` sale un valor por linea y nada mas, que es lo que
    esperan casi todos los importadores masivos.
    """
    lines: List[str] = []
    for kind in ORDER:
        items = report["iocs"].get(kind) or []
        if not items:
            continue
        if with_headers:
            if lines:
                lines.append("")
            lines.append(f"# {SECTION_TITLES[kind]} ({len(items)})")
        lines.extend(str(item["value"]) for item in items)
    return "\n".join(lines) + ("\n" if lines else "")
