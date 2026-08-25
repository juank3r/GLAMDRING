"""Que la lectura de rutas del servidor este cerrada cuando dice estarlo.

EL FALLO QUE CUBRE ESTO era de orden, y de los que se leen sin verlos:

    is_sample = _within(target, SAMPLES_DIR) or not target.is_absolute()

Ese `not is_absolute()` declaraba "muestra" a toda ruta relativa, saltandose la
comprobacion de GLAMDRING_ALLOW_FILE_PATHS. Unas lineas mas abajo la ruta se
resolvia contra el directorio de trabajo del proceso.

Con la lectura DESACTIVADA se leian .env.example, el codigo fuente y
C:\Windows\win.ini por travesia. Y en Windows sin necesidad de un solo '../',
porque is_absolute() devuelve False para rutas con raiz pero sin unidad.

Arrancado desde la raiz del repositorio, path='.env' entregaba los tokens de
Splunk, QRadar y Azure a cualquiera que alcanzase el puerto, que ademas no pide
autenticacion.
"""

from __future__ import annotations

import pytest

from glamdring.connectors import ConnectorError
from glamdring.connectors.files import FileConnector


@pytest.fixture
def conector():
    return FileConnector()


@pytest.fixture(autouse=True)
def lectura_desactivada(monkeypatch):
    """Como viene de fabrica: GLAMDRING_ALLOW_FILE_PATHS=0."""
    from glamdring.config import SETTINGS
    monkeypatch.setattr(SETTINGS, "allow_file_paths", False)


# --------------------------------------------------------------- lo que fugaba


@pytest.mark.parametrize("ruta", [
    ".env",
    ".env.example",
    "glamdring/config.py",
    "requirements.txt",
])
def test_relative_paths_do_not_pass_as_samples(conector, ruta):
    """Una ruta relativa NO es una muestra por el hecho de ser relativa.

    Era la puerta principal: sin un solo '../', desde el directorio de trabajo
    del proceso se llegaba al .env con los tokens de los SIEM.
    """
    with pytest.raises(ConnectorError, match="desactivada"):
        conector.read_path(ruta)


@pytest.mark.parametrize("ruta", [
    "../../../../../Windows/win.ini",
    "..\..\..\Windows\win.ini",
    "/Windows/win.ini",
    "\Windows\win.ini",
    "C:/Windows/win.ini",
    "samples/../glamdring/config.py",
    "minimo/../../glamdring/config.py",
])
def test_traversal_is_blocked(conector, ruta):
    """Ninguna forma de salirse de samples/ puede colarse.

    Se prueban las variantes de Windows a proposito: con raiz pero sin unidad,
    con barras invertidas, y saliendo desde dentro de la propia carpeta de
    muestras. La comprobacion va sobre la ruta YA RESUELTA justo para esto.
    """
    with pytest.raises(ConnectorError):
        conector.read_path(ruta)


# ------------------------------------------------------ lo que tiene que seguir


@pytest.mark.parametrize("ruta,minimo", [
    ("perimeter.cef", 1),
    ("minimo/incidente.json", 1),
    ("apt/Akira.json", 1),
])
def test_samples_still_load(conector, ruta, minimo):
    """Cerrar la puerta no puede dejar fuera a quien tiene que entrar."""
    registros, _formato = conector.read_path(ruta)
    assert len(registros) >= minimo


def test_with_the_switch_on_absolute_paths_work(conector, monkeypatch, tmp_path):
    """Con GLAMDRING_ALLOW_FILE_PATHS=1 vuelve a poder leerse el disco.

    La opcion existe para un analista que investiga en su portatil con los
    exports en una carpeta. Lo que no puede es estar abierta sin pedirlo.
    """
    from glamdring.config import SETTINGS
    fichero = tmp_path / "export.json"
    fichero.write_text('[{"_time": "2026-08-19T09:00:00Z", "host": "H1"}]', encoding="utf-8")

    with pytest.raises(ConnectorError):
        conector.read_path(str(fichero))

    monkeypatch.setattr(SETTINGS, "allow_file_paths", True)
    registros, _formato = conector.read_path(str(fichero))
    assert len(registros) == 1


def test_the_api_does_not_expose_it_either(monkeypatch):
    """La puerta se cierra en el conector, pero se comprueba desde la API.

    Es por donde entraria de verdad: /api/query con connector=files, o
    /api/ingest con path=.
    """
    from fastapi.testclient import TestClient
    from glamdring.config import SETTINGS
    from glamdring.main import app
    monkeypatch.setattr(SETTINGS, "allow_file_paths", False)
    client = TestClient(app)

    respuesta = client.post("/api/query", json={"connector": "files", "query": ".env"})
    assert respuesta.status_code >= 400

    respuesta = client.post("/api/ingest", data={"path": "../../../../../Windows/win.ini"})
    assert respuesta.status_code >= 400
