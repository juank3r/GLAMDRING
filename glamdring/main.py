"""Aplicacion FastAPI de GLAMDRING.

Sirve la API en ``/api`` y el frontend estatico en ``/``. Van juntos a proposito:
mismo origen, sin CORS, sin build de JavaScript y un unico proceso que arrancar.
Para un analista que solo quiere ver su incidente, cada paso de instalacion que
se elimina cuenta.

    uvicorn glamdring.main:app --reload --port 8000
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

from .api import (
    appearance_router,
    graph_router,
    ingest_router,
    meta_router,
    receive_router,
    report_router,
    threat_router,
)
from .appearance import MODELS_DIR, load as load_appearance
from .config import SETTINGS, WEB_DIR
from .connectors import ConnectorError, close_all
from .security import montar_seguridad

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s :: %(message)s",
)
log = logging.getLogger("glamdring")

@asynccontextmanager
async def lifespan(_app: FastAPI):
    """Arranque: se carga el perfil visual y se avisa de lo que hay configurado.

    Cargar el perfil aqui y no bajo demanda tiene un motivo concreto: aplica los
    pesos de riesgo guardados ANTES de que llegue la primera peticion de grafo.
    Si no, el primer grafo se puntuaria con los pesos de fabrica y cambiaria
    solo al segundo refresco.
    """
    profile = load_appearance()
    configured = [name for name, state in SETTINGS.public_status().items()
                  if state.get("configured")]
    log.info("GLAMDRING listo. Conectores configurados: %s",
             ", ".join(configured) or "solo ficheros")
    log.info("Perfil visual: tema '%s', modo de color '%s'",
             profile["theme"]["preset"], profile["colorMode"])
    if SETTINGS.api_key:
        log.info("API protegida por clave (cabecera X-Glamdring-Key).")
    else:
        # No es un detalle de configuracion: es lo que decide si esto puede ver
        # una red o no. Se dice en cada arranque, y con la frase completa.
        log.warning("SIN AUTENTICACION: cualquiera que alcance el puerto puede "
                    "leer y borrar la investigacion. Correcto en local; antes "
                    "de exponerlo, pon GLAMDRING_API_KEY en el .env.")
    if not WEB_DIR.exists():
        log.warning("No existe %s: el frontend no se servira.", WEB_DIR)
    yield
    # Desde el contrato v2 los conectores mantienen su cliente HTTP abierto
    # entre consultas. Sin esto, al apagar quedan conexiones a medio cerrar y
    # httpx se queja por consola justo cuando ya no se puede hacer nada.
    await close_all()


app = FastAPI(
    lifespan=lifespan,
    title="GLAMDRING",
    description=(
        "Visualizador de grafos de incidente sobre logs de SIEM. "
        "Normaliza Splunk, Sentinel, QRadar y CEF a un modelo OCSF-lite y los "
        "convierte en un grafo navegable de entidades y relaciones."
    ),
    version="0.1.0",
)

montar_seguridad(app, SETTINGS.api_key)

app.include_router(meta_router)
app.include_router(ingest_router)
app.include_router(graph_router)
app.include_router(appearance_router)
app.include_router(report_router)
app.include_router(threat_router)
app.include_router(receive_router)


@app.exception_handler(ConnectorError)
async def connector_error_handler(_request, exc: ConnectorError) -> JSONResponse:
    """Cualquier fallo de conector que se escape acaba como 502 legible."""
    log.warning("Error de conector %s: %s", exc.connector, exc.message)
    return JSONResponse(status_code=502, content={"detail": exc.message, "connector": exc.connector})


# Los modelos .glb que sube el sysadmin se sirven como estaticos, para que el
# GLTFLoader del navegador pueda pedirlos por la misma ruta que se guarda en el
# perfil visual.
MODELS_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/config/models", StaticFiles(directory=str(MODELS_DIR)), name="models")

if WEB_DIR.exists():
    # html=True hace que '/' sirva index.html.
    app.mount("/", StaticFiles(directory=str(WEB_DIR), html=True), name="web")
else:  # pragma: no cover
    @app.get("/")
    def missing_frontend() -> RedirectResponse:
        return RedirectResponse(url="/docs")
