"""Informe en HTML autocontenido.

Un solo fichero, sin recursos externos: se abre en cualquier maquina, se adjunta
a un correo y se imprime a PDF con Ctrl+P. La captura del grafo viaja incrustada
en base64 dentro del propio HTML.

El tema es claro y no oscuro a proposito: la herramienta se mira en pantalla,
pero el informe se imprime y se lee en papel o en un PDF.
"""

from __future__ import annotations

from html import escape
from typing import Any, Dict, List

from ..graph import ontology
from .threat_section import render_html as _threat_html

# Colores adaptados a fondo blanco. Los de la interfaz estan pensados para
# brillar sobre negro y sobre papel quedan lavados.
SEVERITY_PRINT = {
    0: "#64748b", 1: "#0284c7", 2: "#16a34a",
    3: "#ca8a04", 4: "#ea580c", 5: "#dc2626",
}

ROLE_PRINT = {
    "hostile": "#dc2626", "victim": "#ea580c", "suspicious": "#ca8a04",
    "asset": "#16a34a", "neutral": "#64748b",
}

STYLE = """
:root { --ink:#1a2233; --muted:#5b6880; --line:#dfe5ee; --bg:#ffffff; --soft:#f6f8fb; }
* { box-sizing:border-box; }
body { margin:0; background:var(--bg); color:var(--ink);
       font:14px/1.65 "Segoe UI", Inter, system-ui, sans-serif; }
.wrap { max-width:960px; margin:0 auto; padding:40px 32px 72px; }
header.rep { border-bottom:3px solid var(--ink); padding-bottom:18px; margin-bottom:28px; }
.brand { font-size:11px; letter-spacing:.22em; text-transform:uppercase; color:var(--muted); }
h1 { margin:6px 0 10px; font-size:28px; line-height:1.25; }
.meta { color:var(--muted); font-size:12px; }
h2 { margin:34px 0 12px; font-size:16px; letter-spacing:.02em;
     border-bottom:1px solid var(--line); padding-bottom:6px; }
h3 { margin:20px 0 8px; font-size:13px; letter-spacing:.06em; text-transform:uppercase; color:var(--muted); }
.cards { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin:18px 0; }
.card { border:1px solid var(--line); border-radius:8px; padding:12px 14px; background:var(--soft); }
.card .k { font-size:10px; text-transform:uppercase; letter-spacing:.1em; color:var(--muted); }
.card .v { font-size:22px; font-weight:600; margin-top:2px; }
table { width:100%; border-collapse:collapse; margin:10px 0 4px; font-size:12.5px; }
th { text-align:left; font-size:10px; text-transform:uppercase; letter-spacing:.09em;
     color:var(--muted); border-bottom:1px solid var(--line); padding:6px 8px; }
td { padding:6px 8px; border-bottom:1px solid var(--line); vertical-align:top; }
tr:nth-child(even) td { background:var(--soft); }
.badge { display:inline-block; padding:1px 8px; border-radius:10px; font-size:10.5px;
         font-weight:600; border:1px solid currentColor; }
.mono { font-family:"Cascadia Mono", Consolas, monospace; font-size:12px; word-break:break-all; }
ol.timeline { list-style:none; margin:0; padding:0; }
ol.timeline li { border-left:2px solid var(--line); padding:0 0 14px 16px; margin-left:6px; position:relative; }
ol.timeline li::before { content:""; position:absolute; left:-6px; top:6px; width:10px; height:10px;
                         border-radius:50%; background:var(--muted); border:2px solid #fff; }
ol.timeline .t { font-family:"Cascadia Mono", Consolas, monospace; font-size:11px; color:var(--muted); }
ol.timeline .txt { margin-top:1px; }
ol.timeline .tags { margin-top:3px; font-size:10.5px; color:var(--muted); }
.stage { border:1px solid var(--line); border-left-width:4px; border-radius:6px;
         padding:10px 14px; margin-bottom:10px; background:var(--soft); }
.stage .name { font-weight:600; }
.stage .ev { color:var(--muted); font-size:12px; margin-top:4px; }
.rec { border:1px solid var(--line); border-radius:6px; padding:10px 14px; margin-bottom:8px; }
.rec .h { font-weight:600; margin-bottom:2px; }
.snapshot { width:100%; border:1px solid var(--line); border-radius:8px; margin:10px 0; }
.ioc-block { margin-bottom:14px; }
.ioc-block pre { background:#0f1522; color:#dbe4f2; border-radius:6px; padding:12px 14px;
                 font-family:"Cascadia Mono", Consolas, monospace; font-size:12px;
                 overflow-x:auto; margin:6px 0 0; }
footer.rep { margin-top:44px; padding-top:14px; border-top:1px solid var(--line);
             color:var(--muted); font-size:11px; }
@media print {
  .wrap { padding:0; max-width:none; }
  .stage, .card, .rec { break-inside:avoid; }
  ol.timeline li { break-inside:avoid; }
}
"""


def _sev_badge(level: int) -> str:
    color = SEVERITY_PRINT.get(level, "#64748b")
    label = ontology.severity(level)["label"]
    return f'<span class="badge" style="color:{color}">{escape(label)}</span>'


def _role_badge(role: str, label: str) -> str:
    color = ROLE_PRINT.get(role, "#64748b")
    return f'<span class="badge" style="color:{color}">{escape(label)}</span>'


def _fmt_time(iso: str) -> str:
    if not iso:
        return "—"
    return escape(iso.replace("T", " ")[:19])


def _summary_cards(report: Dict[str, Any]) -> str:
    summary = report["summary"]
    window = report["window"]
    cards = [
        ("Eventos", str(summary["events"])),
        ("Entidades", str(summary["nodes"])),
        ("Relaciones", str(summary["links"])),
        ("Severidad max.", escape(summary["maxSeverityLabel"])),
        ("Indicadores", str(summary["iocCount"])),
        ("Duracion", escape(window.get("duration") or "—")),
    ]
    return '<div class="cards">' + "".join(
        f'<div class="card"><div class="k">{escape(k)}</div><div class="v">{v}</div></div>'
        for k, v in cards
    ) + "</div>"


def _timeline(report: Dict[str, Any]) -> str:
    items: List[str] = []
    for entry in report["narrative"]:
        color = SEVERITY_PRINT.get(entry["severity"], "#64748b")
        repeat = f' <b>×{entry["count"]}</b>' if entry["count"] > 1 else ""
        tags = []
        if entry.get("techniques"):
            tags.append("MITRE " + ", ".join(escape(t) for t in entry["techniques"]))
        tags.append(escape(ontology.source(entry["source"])["label"]))
        items.append(
            f'<li style="border-left-color:{color}">'
            f'<div class="t">{_fmt_time(entry["time"])}</div>'
            f'<div class="txt">{escape(entry["text"])}{repeat}</div>'
            f'<div class="tags">{" · ".join(tags)}</div></li>'
        )
    return '<ol class="timeline">' + "".join(items) + "</ol>"


def _killchain(report: Dict[str, Any]) -> str:
    blocks = []
    for stage in report["killchain"]:
        entities = ", ".join(escape(item["label"]) for item in stage["entities"][:6])
        evidence = "".join(
            f'<div class="ev">• {escape(item["text"])}</div>' for item in stage["evidence"][:3]
        )
        blocks.append(
            f'<div class="stage" style="border-left-color:#ea580c">'
            f'<div class="name">{escape(stage["label"])}</div>'
            f'<div class="ev">{entities}</div>{evidence}</div>'
        )
    return "".join(blocks) or '<p class="meta">No se detectaron tacticas MITRE etiquetadas.</p>'


def _entities(report: Dict[str, Any], limit: int = 40) -> str:
    rows = []
    for item in report["entities"][:limit]:
        rows.append(
            "<tr>"
            f'<td><b>{item["risk"]}</b></td>'
            f"<td>{escape(item['typeLabel'])}</td>"
            f'<td class="mono">{escape(item["label"])}</td>'
            f"<td>{_role_badge(item['role'], item['roleLabel'])}</td>"
            f"<td>{_sev_badge(item['severity'])}</td>"
            f"<td>{item['events']}</td>"
            f"<td>{_fmt_time(item['firstSeen'] or '')}</td>"
            f"<td>{', '.join(escape(s) for s in item['sources'])}</td>"
            "</tr>"
        )
    more = ""
    if len(report["entities"]) > limit:
        more = f'<p class="meta">… y {len(report["entities"]) - limit} entidades mas.</p>'
    return (
        "<table><thead><tr><th>Riesgo</th><th>Tipo</th><th>Entidad</th><th>Papel</th>"
        "<th>Severidad</th><th>Eventos</th><th>Primera vez</th><th>Origen</th></tr></thead>"
        f"<tbody>{''.join(rows)}</tbody></table>{more}"
    )


IOC_LABELS = {
    "ip": "Direcciones IP externas", "domain": "Dominios", "url": "URLs",
    "hash": "Hashes", "file": "Rutas de fichero", "mailbox": "Buzones",
}


def _iocs(report: Dict[str, Any]) -> str:
    blocks = []
    for key, label in IOC_LABELS.items():
        items = report["iocs"].get(key) or []
        if not items:
            continue
        values = "\n".join(escape(str(item["value"])) for item in items)
        blocks.append(
            f'<div class="ioc-block"><h3>{escape(label)} ({len(items)})</h3>'
            f"<pre>{values}</pre></div>"
        )
    return "".join(blocks) or '<p class="meta">No se extrajeron indicadores.</p>'


def _recommendations(report: Dict[str, Any]) -> str:
    blocks = []
    for item in report["recommendations"]:
        blocks.append(
            f'<div class="rec"><div class="h">{escape(item["label"])}</div>'
            f"<div>{escape(item['text'])}</div></div>"
        )
    return "".join(blocks) or '<p class="meta">Sin recomendaciones automaticas.</p>'


def render(report: Dict[str, Any]) -> str:
    image = ""
    if report.get("image"):
        image = (f'<h2>Grafo del incidente</h2>'
                 f'<img class="snapshot" src="{escape(report["image"])}" '
                 f'alt="Grafo del incidente">')

    analyst = ""
    if report.get("analyst"):
        analyst = f" · Analista: {escape(report['analyst'])}"

    window = report["window"]
    return f"""<!DOCTYPE html>
<html lang="es"><head><meta charset="utf-8">
<title>{escape(report['title'])}</title>
<style>{STYLE}</style></head><body><div class="wrap">

<header class="rep">
  <div class="brand">GLAMDRING · Informe de incidente</div>
  <h1>{escape(report['title'])}</h1>
  <div class="meta">
    Ventana: {_fmt_time(window.get('from') or '')} → {_fmt_time(window.get('to') or '')}
    · Generado: {_fmt_time(report['generated'])}{analyst}
  </div>
</header>

<h2>Resumen ejecutivo</h2>
{_summary_cards(report)}
<p>Se han correlado <b>{report['summary']['events']}</b> eventos procedentes de
{escape(', '.join(report['summary']['sources']) or 'ninguna fuente')}, que involucran a
<b>{report['summary']['nodes']}</b> entidades relacionadas entre si por
<b>{report['summary']['links']}</b> acciones. La severidad maxima observada es
<b>{escape(report['summary']['maxSeverityLabel'])}</b>.</p>

{image}

<h2>Cronologia</h2>
{_timeline(report)}

<h2>Cadena de ataque (MITRE ATT&amp;CK)</h2>
{_killchain(report)}

<h2>Entidades implicadas</h2>
{_entities(report)}

{_threat_html(report)}

<h2>Indicadores de compromiso</h2>
{_iocs(report)}

<h2>Acciones recomendadas</h2>
{_recommendations(report)}

<footer class="rep">
  Generado automaticamente por GLAMDRING a partir de los logs originales del SIEM.
  Cada linea de la cronologia procede de un evento concreto y puede contrastarse con
  su registro original en la herramienta.
</footer>
</div></body></html>"""
