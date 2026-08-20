"""La seccion de amenaza del informe, en HTML y en Markdown.

Vive aparte de `html.py` y `markdown.py` porque es la unica seccion que los dos
formatos comparten casi palabra por palabra, y porque el matiz de "esto es una
hipotesis" tiene que decirse igual en los dos sitios. Duplicarla era la forma
segura de que un dia el HTML afirmara mas de lo que afirma el Markdown.
"""

from __future__ import annotations

from html import escape
from typing import Any, Dict, List

# Colores para fondo blanco: el informe se imprime.
SEVERITY_PRINT = {
    0: "#64748b", 1: "#0284c7", 2: "#16a34a",
    3: "#ca8a04", 4: "#ea580c", 5: "#dc2626",
}

CONFIDENCE_PRINT = {
    "alta": "#dc2626",
    "media": "#ea580c",
    "baja": "#ca8a04",
    "no concluyente": "#64748b",
}


def _unique_notes(detection: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Una entrada por nombre de nota: la misma nota en cuarenta equipos es una."""
    vistas: Dict[str, Dict[str, Any]] = {}
    for nota in detection.get("ransomNotes", []):
        clave = nota["filename"]
        if clave in vistas:
            vistas[clave]["hosts"].append(nota["where"])
            continue
        vistas[clave] = {**nota, "hosts": [nota["where"]]}
    return list(vistas.values())


def _credits(block: Dict[str, Any], separator: str) -> str:
    return separator.join(
        f"{src.get('name', '')} ({src.get('author', '')})"
        for src in block.get("sources", [])
    )


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

def render_html(report: Dict[str, Any]) -> str:
    block = report.get("threat") or {}
    if not block.get("detected"):
        return ""

    detection = block.get("detection", {})
    attribution = block.get("attribution", {})
    partes: List[str] = ["<h2>Herramientas de intrusion y ransomware</h2>"]

    # -- escalera de etapas ------------------------------------------------
    partes.append("<h3>Etapa del despliegue</h3>")
    for etapa in detection.get("stages", []):
        alcanzada = bool(etapa.get("reached"))
        color = "#dc2626" if alcanzada else "#cbd5e1"
        marca = "&#9679;" if alcanzada else "&#9675;"
        evidencia = ", ".join(
            escape(str(item.get("label", ""))) for item in etapa.get("evidence", [])[:4]
        )
        partes.append(
            f'<div class="stage" style="border-left-color:{color}">'
            f'<div class="name">{marca} {escape(etapa.get("label", ""))}</div>'
            f'<div class="ev">{evidencia or escape(etapa.get("hint", ""))}</div></div>'
        )

    siguiente = detection.get("nextStage")
    if siguiente:
        partes.append(
            f'<p><b>Etapa siguiente esperable:</b> {escape(siguiente.get("label", ""))}. '
            f'{escape(siguiente.get("hint", ""))}</p>'
        )

    # -- arsenal -----------------------------------------------------------
    filas = [
        f"<tr><td><b>{escape(categoria)}</b></td>"
        f'<td class="mono">{escape(", ".join(herramientas))}</td></tr>'
        for categoria, herramientas in (detection.get("toolsByCategory") or {}).items()
    ]
    if filas:
        partes.append("<h3>Arsenal observado</h3>")
        partes.append(
            "<table><thead><tr><th>Categoria</th><th>Herramientas</th></tr></thead>"
            f"<tbody>{''.join(filas)}</tbody></table>"
        )

    # -- comportamiento ----------------------------------------------------
    comportamientos = detection.get("behaviours") or []
    if comportamientos:
        partes.append("<h3>Comportamiento detectado</h3>")
        for item in comportamientos:
            color = SEVERITY_PRINT.get(item.get("severity", 0), "#64748b")
            mitre = f" &middot; {escape(item['mitre'])}" if item.get("mitre") else ""
            partes.append(
                f'<div class="stage" style="border-left-color:{color}">'
                f'<div class="name">{escape(item.get("label", ""))}{mitre}</div>'
                f'<div class="ev">{escape(item.get("why", ""))}</div>'
                f'<div class="ev"><b>{escape(item.get("where", ""))}</b> &mdash; '
                f'<span class="mono">{escape(item.get("evidence", "")[:140])}</span>'
                f"</div></div>"
            )

    # -- notas de rescate --------------------------------------------------
    notas = _unique_notes(detection)
    if notas:
        partes.append("<h3>Notas de rescate encontradas</h3><ul>")
        for nota in notas:
            grupos = ", ".join(nota.get("groups", [])) or "familia no identificada"
            equipos = ", ".join(sorted(set(nota["hosts"]))[:4])
            aviso = "" if nota.get("known") else " (coincidencia por patron generico)"
            partes.append(
                f'<li><b class="mono">{escape(nota["filename"])}</b> en '
                f"{escape(equipos)} &mdash; {escape(grupos)}{aviso}</li>"
            )
        partes.append("</ul>")

    # -- atribucion --------------------------------------------------------
    candidatos = (attribution.get("candidates") or [])[:5]
    if candidatos:
        partes.append("<h3>Compatibilidad con grupos conocidos</h3>")
        if block.get("explanation"):
            partes.append(f"<p>{escape(block['explanation'])}</p>")

        filas_attr = []
        for candidato in candidatos:
            color = CONFIDENCE_PRINT.get(candidato.get("confidence", ""), "#64748b")
            distinguen = ", ".join(
                escape(t) for t in candidato.get("discriminating", [])[:6]
            ) or "&mdash;"
            nota = escape(", ".join(candidato.get("noteMatch", [])[:2])) or "&mdash;"
            filas_attr.append(
                "<tr>"
                f'<td><b>{escape(candidato.get("group", ""))}</b></td>'
                f'<td><span class="badge" style="color:{color}">'
                f'{escape(candidato.get("confidence", ""))}</span></td>'
                f'<td>{len(candidato.get("matched", []))}</td>'
                f'<td class="mono">{distinguen}</td>'
                f'<td class="mono">{nota}</td>'
                "</tr>"
            )
        partes.append(
            "<table><thead><tr><th>Grupo</th><th>Confianza</th><th>Coincidencias</th>"
            "<th>Herramientas que distinguen</th><th>Nota</th></tr></thead>"
            f"<tbody>{''.join(filas_attr)}</tbody></table>"
        )
        # El aviso no es opcional: sin el, una tabla ordenada se lee como una
        # acusacion.
        partes.append(
            f'<p class="meta"><b>Aviso:</b> {escape(attribution.get("caveat", ""))}</p>'
        )

        ubicuas = attribution.get("ubiquitousTools") or []
        if ubicuas:
            partes.append(
                f'<p class="meta">No sirven para atribuir porque las usan casi todas '
                f'las familias: {escape(", ".join(ubicuas[:10]))}.</p>'
            )
        sin_perfil = attribution.get("undocumentedTools") or []
        if sin_perfil:
            partes.append(
                f'<p class="meta">Sin perfil publico conocido, y por eso quiza lo mas '
                f'interesante de este incidente: {escape(", ".join(sin_perfil[:10]))}.</p>'
            )

    creditos = _credits(block, " &middot; ")
    if creditos:
        partes.append(f'<p class="meta">Inteligencia: {escape(creditos)}</p>')

    return "\n".join(partes)


# ---------------------------------------------------------------------------
# Markdown
# ---------------------------------------------------------------------------

def render_markdown(report: Dict[str, Any]) -> str:
    block = report.get("threat") or {}
    if not block.get("detected"):
        return ""

    detection = block.get("detection", {})
    attribution = block.get("attribution", {})
    lineas: List[str] = ["\n## Herramientas de intrusión y ransomware\n"]

    lineas.append("### Etapa del despliegue\n")
    for etapa in detection.get("stages", []):
        marca = "x" if etapa.get("reached") else " "
        evidencia = ", ".join(
            str(item.get("label", "")) for item in etapa.get("evidence", [])[:4]
        )
        sufijo = f" — {evidencia}" if evidencia else ""
        lineas.append(f"- [{marca}] **{etapa.get('label', '')}**{sufijo}")

    siguiente = detection.get("nextStage")
    if siguiente:
        lineas.append(
            f"\n> **Etapa siguiente esperable:** {siguiente.get('label', '')}. "
            f"{siguiente.get('hint', '')}\n"
        )

    por_categoria = detection.get("toolsByCategory") or {}
    if por_categoria:
        lineas.append("\n### Arsenal observado\n")
        lineas.append("| Categoría | Herramientas |")
        lineas.append("|---|---|")
        for categoria, herramientas in por_categoria.items():
            valores = ", ".join(f"`{t}`" for t in herramientas)
            lineas.append(f"| {categoria} | {valores} |")
        lineas.append("")

    comportamientos = detection.get("behaviours") or []
    if comportamientos:
        lineas.append("\n### Comportamiento detectado\n")
        for item in comportamientos:
            mitre = f" (`{item['mitre']}`)" if item.get("mitre") else ""
            lineas.append(
                f"- **{item.get('label', '')}**{mitre} en `{item.get('where', '')}`  \n"
                f"  {item.get('why', '')}"
            )

    notas = _unique_notes(detection)
    if notas:
        lineas.append("\n### Notas de rescate\n")
        lineas.append("```")
        for nota in notas:
            grupos = ", ".join(nota.get("groups", [])) or "familia no identificada"
            lineas.append(f"{nota['filename']}  —  {grupos}")
        lineas.append("```\n")

    candidatos = (attribution.get("candidates") or [])[:5]
    if candidatos:
        lineas.append("\n### Compatibilidad con grupos conocidos\n")
        if block.get("explanation"):
            lineas.append(block["explanation"] + "\n")
        lineas.append("| Grupo | Confianza | Coincidencias | Herramientas que distinguen |")
        lineas.append("|---|---|---|---|")
        for candidato in candidatos:
            distinguen = ", ".join(
                f"`{t}`" for t in candidato.get("discriminating", [])[:6]
            ) or "—"
            lineas.append(
                f"| {candidato.get('group', '')} | {candidato.get('confidence', '')} "
                f"| {len(candidato.get('matched', []))} | {distinguen} |"
            )
        lineas.append(f"\n> **Aviso:** {attribution.get('caveat', '')}\n")

        ubicuas = attribution.get("ubiquitousTools") or []
        if ubicuas:
            lineas.append(
                "_No sirven para atribuir porque las usan casi todas las familias: "
                + ", ".join(f"`{t}`" for t in ubicuas[:10]) + "._\n"
            )
        sin_perfil = attribution.get("undocumentedTools") or []
        if sin_perfil:
            lineas.append(
                "_Sin perfil público conocido, y por eso quizá lo más interesante: "
                + ", ".join(f"`{t}`" for t in sin_perfil[:10]) + "._\n"
            )

    creditos = _credits(block, " · ")
    if creditos:
        lineas.append(f"\n_Inteligencia: {creditos}_\n")

    return "\n".join(lineas)
