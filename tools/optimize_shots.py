"""Comprime las capturas de docs/capturas/ sin que se note.

Una captura de interfaz usa muy pocos colores distintos -fondo plano, texto, unas
cuantas tintas de severidad-, asi que cuantizar a una paleta de 256 la lleva de
24 bits por pixel a 8. Medido sobre las cuatro del README: 1.266 KB -> 410 KB,
sin degradacion visible.

LO QUE NO HAY QUE HACER, y esta escrito porque se probo y salio al reves:
redimensionar. El remuestreo con antialias mete degradados donde antes habia
bordes nitidos, y esos degradados comprimen PEOR: bajando de 1.900 a 1.600 px de
ancho el conjunto pasaba de 1.266 KB a 1.458 KB. Mas pequeno y mas pesado.

    python tools/optimize_shots.py
"""

from __future__ import annotations

import sys
from pathlib import Path

from PIL import Image

RAIZ = Path(__file__).resolve().parent.parent
CAPTURAS = RAIZ / "docs" / "capturas"

COLORES = 256


def main() -> int:
    if not CAPTURAS.exists():
        print(f"No existe {CAPTURAS}.")
        return 1

    antes = despues = 0
    for ruta in sorted(CAPTURAS.glob("*.png")):
        tamano = ruta.stat().st_size
        imagen = Image.open(ruta)
        # Si ya esta en paleta, no se vuelve a cuantizar: hacerlo dos veces
        # acumula error de difuminado y la imagen se va ensuciando.
        if imagen.mode == "P":
            print(f"{ruta.name:30} ya en paleta, se deja")
            antes += tamano
            despues += tamano
            continue
        cuantizada = imagen.convert("RGB").quantize(
            colors=COLORES, method=Image.MEDIANCUT, dither=Image.FLOYDSTEINBERG)
        cuantizada.save(ruta, optimize=True)
        nuevo = ruta.stat().st_size
        antes += tamano
        despues += nuevo
        print(f"{ruta.name:30} {tamano / 1024:6.0f} -> {nuevo / 1024:6.0f} KB")

    if antes:
        print(f"{'TOTAL':30} {antes / 1024:6.0f} -> {despues / 1024:6.0f} KB "
              f"({100 - despues * 100 // antes}% menos)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
