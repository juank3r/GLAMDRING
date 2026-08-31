"""Rutas del panel de administrador: el perfil visual del equipo."""

from __future__ import annotations

import re
from typing import Any, Dict

from fastapi import APIRouter, File, HTTPException, UploadFile

from .lectura import leer_acotado
from .. import appearance
from ..graph import ontology

router = APIRouter(prefix="/api", tags=["appearance"])

MAX_MODEL_BYTES = 25 * 1024 * 1024
SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
GLB_MAGIC = b"glTF"


@router.get("/appearance")
def get_appearance() -> Dict[str, Any]:
    """Perfil efectivo mas los limites de cada control.

    El ``spec`` viaja con el perfil para que el panel construya sus sliders con
    los rangos reales del servidor, en vez de duplicarlos en el JavaScript y que
    se desincronicen a la primera.
    """
    return {
        "appearance": appearance.load(),
        "defaults": appearance.defaults(),
        "spec": {
            "sections": {name: {key: list(rule) for key, rule in rules.items()}
                         for name, rules in appearance.SPEC.items()},
            "entity": {key: list(rule) for key, rule in appearance.ENTITY_SPEC.items()},
            "relation": {key: list(rule) for key, rule in appearance.RELATION_SPEC.items()},
        },
        "colorModes": ontology.COLOR_MODES,
    }


@router.put("/appearance")
def put_appearance(patch: Dict[str, Any]) -> Dict[str, Any]:
    """Guarda un parche. Lo que no pase el saneado se devuelve en ``rejected``.

    Se informa de lo descartado en lugar de fallar entero: si el panel manda diez
    ajustes y uno esta mal, es mejor aplicar nueve y decir cual no que perder los
    diez.
    """
    if not isinstance(patch, dict):
        raise HTTPException(status_code=400, detail="Se esperaba un objeto JSON.")
    profile, rejected = appearance.update(patch)
    return {"appearance": profile, "rejected": rejected}


@router.post("/appearance/reset")
def reset_appearance() -> Dict[str, Any]:
    return {"appearance": appearance.reset(), "rejected": []}


@router.post("/appearance/model/{name}")
async def upload_model(name: str, file: UploadFile = File(...)) -> Dict[str, Any]:
    """Sube un ``.glb`` que sustituye a una figura procedural.

    Se comprueba la cabecera del fichero y no solo la extension: aqui llega algo
    que despues se sirve como estatico y lo carga el navegador de todo el equipo.
    """
    if not SAFE_NAME.match(name):
        raise HTTPException(status_code=400, detail="Nombre de figura no valido.")

    # Acotado AL LEER, no despues: leer entero y medir luego comprueba el limite
    # cuando la memoria ya esta gastada. Medido antes de esto: 200 MB contra un
    # limite de 25 daban 600 MB de pico y un 413 que ya no evitaba nada.
    payload = await leer_acotado(file, MAX_MODEL_BYTES)
    if not payload.startswith(GLB_MAGIC):
        raise HTTPException(
            status_code=400,
            detail="El fichero no es un .glb binario (falta la cabecera glTF).",
        )

    appearance.MODELS_DIR.mkdir(parents=True, exist_ok=True)
    filename = f"{name}.glb"
    appearance.model_path(filename).write_bytes(payload)
    profile = appearance.register_model(name, filename)
    return {"appearance": profile, "model": name, "bytes": len(payload)}


@router.delete("/appearance/model/{name}")
def delete_model(name: str) -> Dict[str, Any]:
    """Quita el ``.glb`` y devuelve la figura procedural a su sitio."""
    if not SAFE_NAME.match(name):
        raise HTTPException(status_code=400, detail="Nombre de figura no valido.")
    profile = appearance.unregister_model(name)
    return {"appearance": profile, "model": name, "removed": True}
