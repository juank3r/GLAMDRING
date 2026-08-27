"""Comprueba que los diagramas SVG son validos y que nada se sale del lienzo.

Un SVG mal cerrado no se ve en GitHub y no avisa: sale el icono de imagen rota y
ya esta. Y uno con un texto que se sale del viewBox se ve a medias, que es peor,
porque parece correcto hasta que alguien intenta leer la ultima linea.

    python tools/check_diagrams.py
"""

from __future__ import annotations

import re
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DIAGRAMAS = RAIZ / "docs" / "diagrams"

SVG = "{http://www.w3.org/2000/svg}"
_TRANSLATE = re.compile(r"translate\(\s*(-?[\d.]+)\s*[, ]\s*(-?[\d.]+)\s*\)")

# Ancho medio de un caracter en proporcion al tamano de fuente.
#
# ES UNA ESTIMACION Y HAY QUE SABERLO. Aqui no hay metricas de fuente, asi que
# esto no puede decir "cabe justo": puede decir "esto se sale por goleada", que
# es el fallo que de verdad rompe un diagrama. Calibrado sobre Segoe UI en texto
# de frase, que es lo que llevan estos SVG.
#
# Se ha bajado de 0.58 a 0.52 despues de comprobar dos avisos a mano: los dos
# eran del estimador, no del diagrama. Un comprobador que avisa de lo que esta
# bien acaba ignorandose entero, y entonces no sirve para lo que si esta mal.
ANCHO_POR_CARACTER = 0.52

# Margen de tolerancia. Un par de pixeles de mas no son un fallo.
HOLGURA = 6


def _acumular(elemento, dx: float, dy: float, salidas: list, lienzo,
              fuente: float = 12.0) -> None:
    ancho, alto = lienzo
    for hijo in elemento:
        cdx, cdy = dx, dy
        # El font-size se HEREDA. Sin esto, un texto dentro de un grupo que
        # declara el tamano se medía con el de por defecto y el aviso salia mal.
        heredado = hijo.get("font-size")
        cfuente = float(heredado) if heredado else fuente
        transform = hijo.get("transform") or ""
        encontrado = _TRANSLATE.search(transform)
        if encontrado:
            cdx += float(encontrado.group(1))
            cdy += float(encontrado.group(2))

        etiqueta = hijo.tag.replace(SVG, "")

        if etiqueta == "text":
            x = float(hijo.get("x") or 0) + cdx
            y = float(hijo.get("y") or 0) + cdy
            tamano = cfuente
            texto = "".join(hijo.itertext())
            estimado = len(texto) * tamano * ANCHO_POR_CARACTER
            anclaje = hijo.get("text-anchor") or "start"
            if anclaje == "middle":
                izquierda, derecha = x - estimado / 2, x + estimado / 2
            elif anclaje == "end":
                izquierda, derecha = x - estimado, x
            else:
                izquierda, derecha = x, x + estimado
            if derecha > ancho + HOLGURA or izquierda < -HOLGURA:
                salidas.append(f"texto se sale por los lados (x={izquierda:.0f}..{derecha:.0f} "
                               f"de {ancho}): {texto[:56]!r}")
            if y > alto + HOLGURA or y < -HOLGURA:
                salidas.append(f"texto fuera del alto (y={y:.0f} de {alto}): {texto[:56]!r}")

        elif etiqueta == "rect" and hijo.get("width") and hijo.get("height"):
            x = float(hijo.get("x") or 0) + cdx
            y = float(hijo.get("y") or 0) + cdy
            w = float(hijo.get("width"))
            h = float(hijo.get("height"))
            # El rectangulo de fondo cubre el lienzo entero: no es un desbordamiento.
            if w >= ancho and h >= alto:
                continue
            if x + w > ancho + HOLGURA or y + h > alto + HOLGURA:
                salidas.append(f"caja fuera del lienzo: {x:.0f},{y:.0f} {w:.0f}x{h:.0f} "
                               f"de {ancho}x{alto}")

        _acumular(hijo, cdx, cdy, salidas, lienzo, cfuente)


def revisar(ruta: Path) -> list:
    try:
        arbol = ET.parse(ruta)
    except ET.ParseError as exc:
        return [f"XML invalido: {exc}"]

    raiz = arbol.getroot()
    caja = (raiz.get("viewBox") or "").split()
    if len(caja) != 4:
        return ["sin viewBox utilizable"]
    lienzo = (float(caja[2]), float(caja[3]))

    salidas: list = []
    raiz_fuente = raiz.get("font-size")
    _acumular(raiz, 0.0, 0.0, salidas, lienzo,
              float(raiz_fuente) if raiz_fuente else 12.0)
    return salidas


def main() -> int:
    if not DIAGRAMAS.exists():
        print(f"No existe {DIAGRAMAS}")
        return 1

    problemas = 0
    for ruta in sorted(DIAGRAMAS.glob("*.svg")):
        fallos = revisar(ruta)
        if fallos:
            problemas += 1
            print(f"\n{ruta.name}")
            for fallo in fallos[:12]:
                print(f"   {fallo}")
            if len(fallos) > 12:
                print(f"   ... y {len(fallos) - 12} mas")
        else:
            print(f"ok   {ruta.name}")

    print()
    print("Todos correctos." if not problemas else f"{problemas} diagramas con problemas.")
    return 1 if problemas else 0


if __name__ == "__main__":
    sys.exit(main())
