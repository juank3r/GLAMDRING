"""Informe en Markdown, para pegar en Jira, TheHive, Confluence o un ticket.

No se incrusta la imagen: en base64 dentro de un Markdown queda un churro de
cientos de kilobytes que ninguna de esas herramientas renderiza bien. Se indica
que la captura acompaña al informe HTML.
"""

from __future__ import annotations

from typing import Any, Dict, List

from ..graph import ontology


def _fmt_time(iso: str) -> str:
    return (iso or "").replace("T", " ")[:19] or "—"


def _table(headers: List[str], rows: List[List[str]]) -> str:
    if not rows:
        return "_Sin datos._\n"
    out = ["| " + " | ".join(headers) + " |",
           "|" + "|".join("---" for _ in headers) + "|"]
    for row in rows:
        out.append("| " + " | ".join(str(cell).replace("|", "\\|") for cell in row) + " |")
    return "\n".join(out) + "\n"


IOC_LABELS = {
    "ip": "Direcciones IP externas", "domain": "Dominios", "url": "URLs",
    "hash": "Hashes", "file": "Rutas de fichero", "mailbox": "Buzones",
}


def render(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    window = report["window"]
    lines: List[str] = []

    lines.append(f"# {report['title']}\n")
    lines.append(
        f"> Ventana **{_fmt_time(window.get('from') or '')}** → "
        f"**{_fmt_time(window.get('to') or '')}**"
        + (f" ({window['duration']})" if window.get("duration") else "")
        + f" · Generado {_fmt_time(report['generated'])}"
        + (f" · Analista: {report['analyst']}" if report.get("analyst") else "")
        + "\n"
    )

    lines.append("## Resumen ejecutivo\n")
    lines.append(_table(
        ["Eventos", "Entidades", "Relaciones", "Severidad máx.", "Indicadores"],
        [[summary["events"], summary["nodes"], summary["links"],
          summary["maxSeverityLabel"], summary["iocCount"]]],
    ))
    lines.append(
        f"\nSe han correlado **{summary['events']}** eventos de "
        f"**{', '.join(summary['sources']) or 'ninguna fuente'}**, que involucran a "
        f"**{summary['nodes']}** entidades unidas por **{summary['links']}** acciones. "
        f"La severidad máxima observada es **{summary['maxSeverityLabel']}**.\n"
    )

    lines.append("\n## Cronología\n")
    for entry in report["narrative"]:
        repeat = f" **×{entry['count']}**" if entry["count"] > 1 else ""
        techniques = ""
        if entry.get("techniques"):
            techniques = "  \n  `" + "` `".join(entry["techniques"]) + "`"
        lines.append(f"- **{_fmt_time(entry['time'])}** — {entry['text']}{repeat}{techniques}")
    if not report["narrative"]:
        lines.append("_Sin eventos destacables._")

    lines.append("\n\n## Cadena de ataque (MITRE ATT&CK)\n")
    if report["killchain"]:
        for stage in report["killchain"]:
            entities = ", ".join(f"`{item['label']}`" for item in stage["entities"][:6])
            lines.append(f"### {stage['label']}\n")
            lines.append(f"{entities}\n")
            for item in stage["evidence"][:3]:
                lines.append(f"- {item['text']}")
            lines.append("")
    else:
        lines.append("_No se detectaron tácticas MITRE etiquetadas._\n")

    lines.append("\n## Entidades implicadas\n")
    lines.append(_table(
        ["Riesgo", "Tipo", "Entidad", "Papel", "Severidad", "Eventos", "Origen"],
        [[item["risk"], item["typeLabel"], f"`{item['label']}`", item["roleLabel"],
          ontology.severity(item["severity"])["label"], item["events"],
          ", ".join(item["sources"])]
         for item in report["entities"][:40]],
    ))

    lines.append("\n## Indicadores de compromiso\n")
    any_ioc = False
    for key, label in IOC_LABELS.items():
        items = report["iocs"].get(key) or []
        if not items:
            continue
        any_ioc = True
        lines.append(f"### {label} ({len(items)})\n")
        lines.append("```")
        lines.extend(str(item["value"]) for item in items)
        lines.append("```\n")
    if not any_ioc:
        lines.append("_No se extrajeron indicadores._\n")

    lines.append("\n## Acciones recomendadas\n")
    if report["recommendations"]:
        for item in report["recommendations"]:
            lines.append(f"- **{item['label']}** — {item['text']}")
    else:
        lines.append("_Sin recomendaciones automáticas._")

    lines.append(
        "\n\n---\n_Generado automáticamente por GLAMDRING a partir de los logs originales "
        "del SIEM. Cada línea de la cronología procede de un evento concreto y puede "
        "contrastarse con su registro original en la herramienta._\n"
    )
    return "\n".join(lines)
