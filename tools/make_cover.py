"""Genera la portada del README: el ASCII en blanco sobre negro.

El original es ASCII oscuro sobre fondo blanco, y en un README que se lee casi
siempre en tema oscuro eso es un cuadro blanco enorme en mitad de la pagina: la
vista se va ahi antes que al titulo.

Invertido queda al reves -trazo claro sobre negro-, se funde con el fondo de
GitHub en tema oscuro y sigue leyendose en el claro.

    python tools/make_cover.py

Toma docs/glamdring-original.png (el que subio el usuario, que se conserva) y
escribe docs/glamdring.png.
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image, ImageOps

RAIZ = Path(__file__).resolve().parent.parent
ORIGEN = RAIZ / "docs" / "glamdring-original.png"
DESTINO = RAIZ / "docs" / "glamdring.png"

# 520 px de lado. El ASCII sigue reconociendose y ocupa la mitad de alto que
# antes, que es lo que se pedia: la portada tiene que dejar ver el titulo.
LADO = 520


def main() -> int:
    if not ORIGEN.exists():
        print(f"No existe {ORIGEN}.")
        print("Guarda ahi el PNG original antes de ejecutar esto.")
        return 1

    imagen = Image.open(ORIGEN)

    # El original viene con canal alfa. Se aplasta sobre BLANCO y no sobre
    # negro: las zonas transparentes eran fondo de papel, y componerlas sobre
    # negro las dejaria oscuras y se perderian al invertir.
    if imagen.mode in ("RGBA", "LA", "P"):
        imagen = imagen.convert("RGBA")
        fondo = Image.new("RGBA", imagen.size, (255, 255, 255, 255))
        imagen = Image.alpha_composite(fondo, imagen)

    gris = imagen.convert("L")
    invertida = ImageOps.invert(gris)

    # LANCZOS y no el remuestreo por defecto: el ASCII son trazos finos de un
    # pixel, y un filtro pobre se los come y deja una mancha gris.
    pequena = invertida.resize((LADO, LADO), Image.LANCZOS)

    # Se guarda en escala de grises: es una imagen de un solo canal y no hay
    # motivo para arrastrar tres. Baja de 191 KB a una fraccion.
    pequena.save(DESTINO, optimize=True)

    antes = ORIGEN.stat().st_size / 1024
    despues = DESTINO.stat().st_size / 1024
    print(f"{ORIGEN.name}  {imagen.size[0]}x{imagen.size[1]}  {antes:.0f} KB")
    print(f"{DESTINO.name}  {LADO}x{LADO}  {despues:.0f} KB  (blanco sobre negro)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
