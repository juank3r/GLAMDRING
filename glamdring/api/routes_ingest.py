"""Rutas de entrada de datos: subida de ficheros, demo y consulta al SIEM."""

from __future__ import annotations

import re

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, UploadFile
from pydantic import BaseModel, Field

from ..config import SAMPLES_DIR, SETTINGS
from ..connectors import ConnectorError, FileConnector, get_connector
from ..graph.query import parse_moment
from ..normalize import normalize_all
from ..store import STORE

router = APIRouter(prefix="/api", tags=["ingest"])

MAX_UPLOAD_BYTES = 200 * 1024 * 1024
TROZO_BYTES = 1024 * 1024        # cuanto se lee de golpe al comprobar el limite


class QueryRequest(BaseModel):
    """Consulta en vivo contra un SIEM."""

    connector: str = Field(description="splunk | sentinel | qradar")
    query: str
    time_from: Optional[str] = Field(default=None, alias="from",
                                     description="ISO-8601 o relativo ('-24h')")
    time_to: Optional[str] = Field(default=None, alias="to")
    # ge=1 NO es una formalidad. Sin el, limit=0 llega a Splunk como count=0,
    # que en su API REST significa SIN LIMITE: se pide "nada" y se descarga el
    # indice entero. Y un negativo se convierte en Range: items=0--1 en QRadar
    # y en rows[:-n] en Sentinel, que tira las ultimas filas sin decir nada.
    limit: int = Field(default=10_000, ge=1, le=SETTINGS.max_results)
    reset: bool = Field(default=False, description="vaciar la investigacion antes de ingestar")
    # Para las fuentes que paginan con estado: se devuelve en la respuesta y se
    # vuelve a mandar aqui para seguir donde se quedo, en vez de repetir la
    # consulta entera y volver a deduplicar lo mismo.
    cursor: Optional[str] = Field(default=None, max_length=2048,
                                  description="continuar desde una consulta anterior")

    model_config = {"populate_by_name": True}


def _ingest_records(records: List[Dict[str, Any]], origin: str) -> Dict[str, Any]:
    """Normaliza y guarda, informando de lo que se ha quedado por el camino."""
    events = normalize_all(records)
    stats = STORE.add(events, origin=origin)
    unmatched = len(records) - len(events)
    return {
        "read": len(records),
        "normalized": len(events),
        # Registros que ningun normalizador supo interpretar. Deberia ser 0:
        # si sube, es que hace falta un normalizador nuevo.
        "unmatched": unmatched,
        **stats,
    }


async def _leer_acotado(file: UploadFile) -> bytes:
    """Lee un fichero subido cortando EN CUANTO se pasa del limite.

    Antes esto era ``payload = await file.read()`` y despues se miraba el
    tamano. O sea: el limite se comprobaba cuando el fichero ya estaba entero en
    memoria, que es justo cuando ya da igual. Subir diez gigas devolvia un 413
    despues de habersela comido, y cualquiera con acceso a la ruta podia tumbar
    el proceso sin necesidad de que el fichero fuera valido siquiera.

    Leyendo a trozos se corta en el primero que se pasa: el pico de memoria
    queda en el limite mas un trozo, y el 413 llega antes de que duela.
    """
    trozos: List[bytes] = []
    leidos = 0
    while True:
        trozo = await file.read(TROZO_BYTES)
        if not trozo:
            break
        leidos += len(trozo)
        if leidos > MAX_UPLOAD_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"Fichero demasiado grande: el limite son "
                       f"{MAX_UPLOAD_BYTES // (1024 * 1024)} MB.")
        trozos.append(trozo)
    return b"".join(trozos)


@router.post("/ingest")
async def ingest(
    file: Optional[UploadFile] = File(default=None),
    text: Optional[str] = Form(default=None),
    path: Optional[str] = Form(default=None),
    format_hint: Optional[str] = Form(default=None),
    reset: bool = Form(default=False),
) -> Dict[str, Any]:
    """Ingesta desde fichero subido, texto pegado o ruta del servidor."""
    if reset:
        STORE.clear()

    connector = FileConnector()
    try:
        if file is not None:
            payload = await _leer_acotado(file)
            content = payload.decode("utf-8", errors="replace")
            records, fmt = connector.read_text(content, hint=format_hint or "")
            origin = f"upload:{file.filename}"
        elif text:
            records, fmt = connector.read_text(text, hint=format_hint or "")
            origin = "paste"
        elif path:
            records, fmt = connector.read_path(path)
            origin = f"path:{path}"
        else:
            raise HTTPException(status_code=400, detail="Falta 'file', 'text' o 'path'.")
    except ConnectorError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc

    result = _ingest_records(records, origin)
    result["format"] = fmt
    result["origin"] = origin
    return result


# Conjuntos de ejemplo. La clave es lo que se pide por la URL; el valor, el
# subdirectorio de samples/ (vacio = la raiz).
DEMO_SETS = {
    "completo": "",
    "minimo": "minimo",
}


@router.get("/incidents")
def list_incidents() -> Dict[str, Any]:
    """Los incidentes que se pueden cargar, para poder saltar de uno a otro.

    HOY salen de ``samples/``: los dos conjuntos de demostracion y las muestras
    sinteticas de ``samples/apt/``, una por grupo de ransomware.

    MANANA saldran de la base de datos de incidentes reales. Por eso esta ruta
    devuelve una LISTA DE FICHAS y no un listado de ficheros: id, titulo,
    subtitulo y de donde se carga. El dia que haya base de datos se cambia lo
    que hay dentro de esta funcion y la interfaz no se entera, porque lo que
    consume es la ficha.
    """
    fichas: List[Dict[str, Any]] = []

    for clave, etiqueta, detalle in (
        ("completo", "Incidente completo", "52 eventos de los cuatro formatos"),
        ("minimo", "Incidente minimo", "6 eventos: la forma del grafo sin nada encima"),
    ):
        directorio = SAMPLES_DIR / DEMO_SETS[clave] if DEMO_SETS[clave] else SAMPLES_DIR
        if directorio.exists():
            fichas.append({
                "id": f"demo:{clave}",
                "title": etiqueta,
                "subtitle": detalle,
                "kind": "demo",
                "set": clave,
            })

    apt_dir = SAMPLES_DIR / "apt"
    if apt_dir.exists():
        for fichero in sorted(apt_dir.glob("*.json")):
            grupo = fichero.stem.replace("_", " ")
            fichas.append({
                "id": f"apt:{fichero.stem}",
                "title": grupo,
                "subtitle": "muestra sintetica con el repertorio real del grupo",
                "kind": "apt",
                "path": f"apt/{fichero.name}",
            })

    return {"count": len(fichas), "incidents": fichas}


@router.post("/incidents/load")
def load_incident(id: str) -> Dict[str, Any]:
    """Carga uno de los incidentes de ``/api/incidents``, sustituyendo lo que haya.

    Sustituye y no acumula: saltar de un incidente a otro y quedarse con los dos
    mezclados daria un grafo que no corresponde a ninguno de los dos.
    """
    if id.startswith("demo:"):
        return load_demo(reset=True, set=id.split(":", 1)[1])

    if not id.startswith("apt:"):
        raise HTTPException(status_code=400, detail=f"Identificador '{id}' no reconocido.")

    nombre = id.split(":", 1)[1]
    # El identificador acaba siendo una ruta en disco: solo se acepta lo previsible.
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,64}", nombre):
        raise HTTPException(status_code=400, detail="Identificador con caracteres no permitidos.")

    fichero = (SAMPLES_DIR / "apt" / f"{nombre}.json").resolve()
    if not fichero.is_file() or SAMPLES_DIR.resolve() not in fichero.parents:
        raise HTTPException(status_code=404, detail=f"No existe la muestra '{nombre}'.")

    STORE.clear()
    connector = FileConnector()
    try:
        records, fmt = connector.read_path(str(fichero))
    except ConnectorError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc

    stats = _ingest_records(records, f"incident:{nombre}")
    return {"id": id, "title": nombre.replace("_", " "), "format": fmt,
            "events": len(STORE), **stats}


@router.post("/demo")
def load_demo(reset: bool = True, set: str = "completo") -> Dict[str, Any]:
    """Carga los ficheros de ejemplo.

    Es la puerta de entrada de la herramienta: sin esto habria que tener un SIEM
    delante para ver si funciona.

    ``set=minimo`` carga un incidente de seis eventos en vez de los cincuenta y
    dos del completo. Sirve para ver la forma del grafo sin nada encima, para
    entender la herramienta por primera vez, y para saber si algo va lento por
    el volumen o por otra cosa.
    """
    if set not in DEMO_SETS:
        raise HTTPException(
            status_code=400,
            detail=f"Conjunto '{set}' desconocido. Hay: {', '.join(sorted(DEMO_SETS))}.")

    directory = SAMPLES_DIR / DEMO_SETS[set] if DEMO_SETS[set] else SAMPLES_DIR
    if reset:
        STORE.clear()
    if not directory.exists():
        raise HTTPException(status_code=404, detail=f"No hay directorio {directory.name}/.")

    connector = FileConnector()
    totals = {"read": 0, "normalized": 0, "unmatched": 0, "added": 0, "duplicates": 0}
    files: List[Dict[str, Any]] = []

    for item in sorted(directory.iterdir()):
        if not item.is_file() or item.suffix.lower() not in (".json", ".ndjson", ".csv", ".cef", ".log", ".txt"):
            continue
        try:
            records, fmt = connector.read_path(str(item))
        except ConnectorError as exc:
            files.append({"file": item.name, "error": exc.message})
            continue
        stats = _ingest_records(records, f"sample:{item.name}")
        files.append({"file": item.name, "format": fmt, **stats})
        for key in totals:
            totals[key] += stats.get(key, 0)

    return {"files": files, "totals": totals, "events": len(STORE), "set": set}


@router.post("/query")
async def query_siem(request: QueryRequest) -> Dict[str, Any]:
    """Lanza una consulta al SIEM y fusiona el resultado en la investigacion."""
    # 'files' no se acepta aqui. Esta ruta existe para consultar un SIEM en
    # vivo; el conector de ficheros lee del disco del SERVIDOR, y exponerlo por
    # una ruta que acepta una cadena arbitraria como "consulta" es justo por
    # donde se colaba la lectura de ficheros. Para subir un fichero esta
    # /api/ingest, que recibe su contenido y no una ruta.
    if request.connector.strip().lower() == "files":
        raise HTTPException(
            status_code=400,
            detail="El conector 'files' no se consulta por aqui. Sube el fichero a /api/ingest.",
        )

    if request.reset:
        STORE.clear()

    try:
        connector = get_connector(request.connector)
    except ConnectorError as exc:
        raise HTTPException(status_code=400, detail=exc.message) from exc

    if not connector.configured:
        raise HTTPException(
            status_code=409,
            detail=f"El conector '{request.connector}' no tiene credenciales configuradas.",
        )

    try:
        salida = await connector.fetch(
            query=request.query,
            time_from=parse_moment(request.time_from),
            time_to=parse_moment(request.time_to),
            limit=min(request.limit, SETTINGS.max_results),
            cursor=request.cursor,
        )
    except ConnectorError as exc:
        # 502: el fallo es del SIEM o de la consulta, no del servidor.
        raise HTTPException(status_code=502, detail=exc.message) from exc

    result = _ingest_records(salida.records, f"{request.connector}:{request.query[:80]}")
    result["connector"] = request.connector
    # Lo que dice el contrato v2 sobre si el resultado esta completo. Va en la
    # respuesta y no solo en el log porque es informacion del ANALISTA: un grafo
    # cortado y uno entero se ven igual en pantalla.
    result.update(salida.as_dict())
    if salida.truncated:
        result.setdefault("warnings", []).insert(
            0,
            "El SIEM tenia mas eventos de los pedidos: el grafo esta incompleto. "
            "Acota la ventana temporal o sube 'limit'.",
        )
    return result


@router.post("/reset")
def reset_store() -> Dict[str, Any]:
    """Vacia la investigacion en curso."""
    STORE.clear()
    return {"status": "ok", "events": 0}
