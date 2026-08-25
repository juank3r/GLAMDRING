"""Genera el cuadro de grupos de ransomware para el README.

Lee ``glamdring/threat/data/groups.json`` y escribe
``docs/diagrams/08-grupos-ransomware.svg``.

SE GENERA, NO SE ESCRIBE A MANO, y eso es lo importante: cada numero del cuadro
sale del catalogo vendorizado. Si manana se actualiza con
``tools/fetch_threat_intel.py``, se vuelve a ejecutar esto y el cuadro sigue
diciendo la verdad. Un cuadro escrito a mano envejece en silencio.

SOBRE LOS EMBLEMAS: no son logotipos. Estos grupos no tienen una marca que se
pueda usar, y ponerles uno inventado seria afirmar algo falso sobre ellos. Lo
que hay es un monograma con sus iniciales y un color estable, que cumple lo que
tiene que cumplir —distinguirlos de un vistazo— sin fingir lo que no es.

Uso:
    .venv/Scripts/python.exe tools/make_group_table.py
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Dict, List

RAIZ = Path(__file__).resolve().parent.parent
DATOS = RAIZ / "glamdring" / "threat" / "data" / "groups.json"
SALIDA = RAIZ / "docs" / "diagrams" / "08-grupos-ransomware.svg"

# Las ocho categorias del Ransomware Tool Matrix, en el orden en que aparecen a
# lo largo de una intrusion: primero se entra y se mira, luego se roba y se
# salta, y al final se saca y se tapa.
CATEGORIAS: List[tuple] = [
    ("RMM Tools",        "RMM",  "#4ea8ff", "Control remoto"),
    ("Discovery",        "Desc", "#22d3ee", "Reconocimiento"),
    ("Credential Theft", "Cred", "#a78bfa", "Robo de credenciales"),
    ("OffSec",           "OffS", "#f472b6", "Utillaje ofensivo"),
    ("Networking",       "Red",  "#4ade80", "Tuneles y red"),
    ("Exfiltration",     "Exfi", "#fb923c", "Exfiltracion"),
    ("Defense Evasion",  "Evas", "#eab308", "Evasion de defensas"),
    ("LOLBAS",           "LOL",  "#94a3b8", "Binarios del sistema"),
]

# Paleta estable por posicion, no aleatoria: el mismo grupo sale siempre del
# mismo color y el cuadro no cambia de aspecto entre regeneraciones.
PALETA = [
    "#ff2d55", "#fb923c", "#eab308", "#4ade80", "#2dd4bf", "#22d3ee",
    "#4ea8ff", "#818cf8", "#a78bfa", "#d4a5ff", "#f472b6", "#fb7185",
    "#f97316", "#a3e635", "#34d399", "#38bdf8", "#c084fc",
]

ANCHO = 1400
TARJETA_W = 434
TARJETA_H = 148
COLUMNAS = 3
MARGEN = 40
HUECO = 14
CABECERA = 196


def escapar(texto: str) -> str:
    return (str(texto).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;"))


def monograma(nombre: str) -> str:
    """Dos letras que identifiquen al grupo.

    'BlackBasta' -> BB, 'INC Ransom' -> IR, 'Akira' -> AK. Se parte por espacios
    y por mayuscula intermedia, que es como estan escritos casi todos.
    """
    partes = [p for p in re.split(r"[\s_-]+|(?<=[a-z])(?=[A-Z])", nombre) if p]
    if len(partes) >= 2:
        return (partes[0][0] + partes[1][0]).upper()
    return nombre[:2].upper()


def nota_caracteristica(nombre: str, grupos: Dict[str, dict]) -> str:
    """La nota de rescate que menos grupos comparten.

    Una que use un solo grupo casi identifica sola; 'README.txt' no dice nada.
    Se elige la mas discriminante para que el cuadro enseñe la util.
    """
    notas = grupos[nombre].get("notes") or []
    if not notas:
        return ""
    cuantos: Dict[str, int] = {}
    for datos in grupos.values():
        for n in (datos.get("notes") or []):
            cuantos[n.lower()] = cuantos.get(n.lower(), 0) + 1
    mejor = min(notas, key=lambda n: cuantos[n.lower()])
    return mejor if cuantos[mejor.lower()] == 1 else ""


def tarjeta(nombre: str, datos: dict, color: str, nota: str, x: int, y: int) -> str:
    cats = datos.get("toolsByCategory") or {}
    total = len(datos.get("tools") or [])
    fuentes = len(datos.get("sources") or [])
    presentes = sum(1 for c, _, _, _ in CATEGORIAS if cats.get(c))

    partes = [f'<g transform="translate({x},{y})">',
              f'<rect width="{TARJETA_W}" height="{TARJETA_H}" rx="10" '
              f'fill="#0d121c" stroke="#1d2635"/>',
              f'<rect width="4" height="{TARJETA_H}" rx="2" fill="{color}"/>']

    # Emblema: monograma sobre un disco del color del grupo.
    partes.append(f'<circle cx="46" cy="42" r="21" fill="{color}" opacity="0.16"/>')
    partes.append(f'<circle cx="46" cy="42" r="21" fill="none" stroke="{color}" stroke-width="1.5"/>')
    partes.append(f'<text x="46" y="49" fill="{color}" font-size="16" font-weight="700" '
                  f'text-anchor="middle" letter-spacing="0.5">{escapar(monograma(nombre))}</text>')

    partes.append(f'<text x="78" y="34" fill="#dce4f0" font-size="15.5" font-weight="700">'
                  f'{escapar(nombre)}</text>')
    informes = f'{fuentes} informe' + ('' if fuentes == 1 else 's')
    partes.append(f'<text x="78" y="52" fill="#8b98ad" font-size="11">'
                  f'{total} herramientas · {presentes} de 8 categorias · {informes}</text>')

    # Barra apilada: cuanto pesa cada categoria en su repertorio.
    ancho_util = TARJETA_W - 96
    partes.append(f'<g transform="translate(78,64)">')
    desplazado = 0
    for clave, _, tono, etiqueta in CATEGORIAS:
        n = len(cats.get(clave) or [])
        if not n:
            continue
        w = max(3, round(ancho_util * n / total))
        partes.append(f'<rect x="{desplazado}" y="0" width="{w}" height="9" fill="{tono}" '
                      f'rx="1.5"><title>{escapar(etiqueta)}: {n}</title></rect>')
        desplazado += w + 1
    partes.append("</g>")

    # Cifras por categoria, solo las que tiene.
    partes.append('<g transform="translate(78,92)" font-size="10">')
    columna = 0
    for clave, abrev, tono, _ in CATEGORIAS:
        n = len(cats.get(clave) or [])
        if not n:
            continue
        cx = columna * 62
        partes.append(f'<text x="{cx}" y="0" fill="{tono}">{abrev}</text>'
                      f'<text x="{cx + 30}" y="0" fill="#94a3b8">{n}</text>')
        columna += 1
        if columna >= 5:
            break
    partes.append("</g>")

    if nota:
        partes.append(f'<text x="78" y="126" fill="#5b6880" font-size="10">nota propia</text>')
        partes.append(f'<text x="140" y="126" fill="#94a3b8" font-size="10" '
                      f'font-family="Consolas, monospace">{escapar(nota[:34])}</text>')
    else:
        partes.append('<text x="78" y="126" fill="#5b6880" font-size="10">'
                      'sin nota que lo distinga en el catalogo</text>')

    partes.append("</g>")
    return "\n  ".join(partes)


def construir() -> str:
    grupos: Dict[str, dict] = json.loads(DATOS.read_text(encoding="utf-8"))
    orden = sorted(grupos.items(), key=lambda kv: -len(kv[1].get("tools") or []))

    filas = (len(orden) + COLUMNAS - 1) // COLUMNAS
    alto = CABECERA + filas * (TARJETA_H + HUECO) + 118

    total_herramientas = len({t for d in grupos.values() for t in (d.get("tools") or [])})

    out = [
        f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {ANCHO} {alto}" '
        f'width="{ANCHO}" height="{alto}" font-family="Segoe UI, Inter, system-ui, sans-serif">',
        '<defs><linearGradient id="bg8" x1="0" y1="0" x2="0" y2="1">'
        '<stop offset="0" stop-color="#0b1220"/><stop offset="1" stop-color="#070a10"/>'
        '</linearGradient></defs>',
        f'<rect width="{ANCHO}" height="{alto}" fill="url(#bg8)"/>',
        f'<text x="{MARGEN}" y="52" fill="#dce4f0" font-size="26" font-weight="700" '
        f'letter-spacing="1">Los {len(orden)} grupos que GLAMDRING reconoce</text>',
        f'<text x="{MARGEN}" y="78" fill="#8b98ad" font-size="14">'
        f'{total_herramientas} herramientas distintas, clasificadas en ocho categorias. '
        f'Lo que se busca no es el cifrador: es el rastro de las horas anteriores.</text>',
    ]

    # Leyenda de categorias.
    out.append(f'<rect x="{MARGEN}" y="98" width="{ANCHO - 2 * MARGEN}" height="76" rx="10" '
               f'fill="#0d121c" stroke="#1d2635"/>')
    out.append(f'<text x="{MARGEN + 22}" y="122" fill="#5b6880" font-size="11" '
               f'letter-spacing="2">LAS OCHO CATEGORIAS, EN ORDEN DE INTRUSION</text>')
    x = MARGEN + 22
    for clave, abrev, tono, etiqueta in CATEGORIAS:
        out.append(f'<rect x="{x}" y="138" width="10" height="10" rx="2" fill="{tono}"/>')
        out.append(f'<text x="{x + 16}" y="147" fill="#94a3b8" font-size="11.5">'
                   f'{escapar(etiqueta)}</text>')
        x += 26 + len(etiqueta) * 6.6

    for indice, (nombre, datos) in enumerate(orden):
        fila, columna = divmod(indice, COLUMNAS)
        x = MARGEN + columna * (TARJETA_W + HUECO)
        y = CABECERA + fila * (TARJETA_H + HUECO)
        out.append(tarjeta(nombre, datos, PALETA[indice % len(PALETA)],
                           nota_caracteristica(nombre, grupos), x, y))

    pie = CABECERA + filas * (TARJETA_H + HUECO) + 12
    out.append(f'<rect x="{MARGEN}" y="{pie}" width="{ANCHO - 2 * MARGEN}" height="88" rx="10" '
               f'fill="#160d12" stroke="#7f1d1d" stroke-opacity="0.5"/>')
    out.append(f'<text x="{MARGEN + 22}" y="{pie + 26}" fill="#ff2d55" font-size="11.5" '
               f'font-weight="700" letter-spacing="1.5">ESTO NO SIRVE PARA SEÑALAR A NADIE</text>')
    out.append(f'<text x="{MARGEN + 22}" y="{pie + 48}" fill="#dce4f0" font-size="12.5">'
               f'Estos grupos comparten afiliados y casi todos usan las mismas utilidades, que ademas '
               f'usan los administradores legitimos.</text>')
    out.append(f'<text x="{MARGEN + 22}" y="{pie + 66}" fill="#dce4f0" font-size="12.5">'
               f'El solape orienta la busqueda: dice que mirar a continuacion, no quien fue.</text>')
    out.append(f'<text x="{MARGEN + 22}" y="{pie + 82}" fill="#5b6880" font-size="10.5">'
               f'Datos: Ransomware Tool Matrix (BushidoUK, CC BY 4.0) y ransomware.live '
               f'(Julien Mousqueton). Los emblemas son monogramas, no logotipos.</text>')

    out.append("</svg>")
    return "\n".join(out)


def main() -> None:
    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    svg = construir()
    SALIDA.write_text(svg, encoding="utf-8", newline="\n")
    grupos = json.loads(DATOS.read_text(encoding="utf-8"))
    print(f"{SALIDA.relative_to(RAIZ)}: {len(grupos)} grupos, {len(svg) // 1024} KB")


if __name__ == "__main__":
    main()
