"""Leer un fichero subido sin fiarse de lo que diga que mide.

Estaba escrito en `routes_ingest` y solo lo usaba la ingesta. La subida de
modelos `.glb`, que tiene el mismo problema y peor limite, hacia
`payload = await file.read()` y miraba el tamano DESPUES: medido, un fichero de
200 MB contra un limite de 25 daba **600 MB de pico** y el 413 llegaba cuando ya
no servia de nada. Aqui esta una sola vez y lo usan las dos.
"""

from __future__ import annotations

from typing import List

from fastapi import HTTPException, UploadFile

TROZO_BYTES = 1024 * 1024        # cuanto se lee de golpe al comprobar el limite


async def leer_acotado(file: UploadFile, tope: int) -> bytes:
    """Lee cortando EN CUANTO se pasa del limite.

    La version ingenua -leer entero, medir despues- comprueba el limite justo
    cuando ya da igual: la memoria ya esta gastada. Cualquiera con acceso a la
    ruta tumba el proceso sin necesidad de que el fichero sea valido siquiera.

    Leyendo a trozos el pico queda en el limite mas un trozo.
    """
    trozos: List[bytes] = []
    leidos = 0
    while True:
        trozo = await file.read(TROZO_BYTES)
        if not trozo:
            break
        leidos += len(trozo)
        if leidos > tope:
            raise HTTPException(
                status_code=413,
                detail=f"Fichero demasiado grande: el limite son "
                       f"{tope // (1024 * 1024)} MB.")
        trozos.append(trozo)
    return b"".join(trozos)
