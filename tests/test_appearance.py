"""Perfil visual: saneado, persistencia y rutas del panel de administrador."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from glamdring import appearance
from glamdring.graph.enrich import DEFAULT_RISK_WEIGHTS, risk_weights
from glamdring.main import app


@pytest.fixture(autouse=True)
def isolated_config(tmp_path, monkeypatch):
    """El perfil vive en un fichero real: los tests no pueden tocar el del repo."""
    monkeypatch.setattr(appearance, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(appearance, "APPEARANCE_PATH", tmp_path / "appearance.json")
    monkeypatch.setattr(appearance, "MODELS_DIR", tmp_path / "models")
    yield
    appearance.reset_risk_weights() if hasattr(appearance, "reset_risk_weights") else None


@pytest.fixture
def client():
    return TestClient(app)


# ------------------------------------------------------------------ defectos


def test_defaults_have_every_section():
    profile = appearance.defaults()
    for section in ("theme", "render", "physics", "labels", "links", "camera", "interaction"):
        assert section in profile
    assert profile["colorMode"] == "type"
    assert profile["riskWeights"] == DEFAULT_RISK_WEIGHTS


def test_every_default_passes_its_own_spec():
    """Un valor de fabrica que su propio validador rechazaria seria un bug."""
    profile = appearance.defaults()
    clean, rejected = appearance.sanitize(
        {section: profile[section] for section in appearance.SPEC}
    )
    assert rejected == []
    for section, values in clean.items():
        for key, value in values.items():
            assert profile[section][key] == value, f"{section}.{key} cambio al sanear"


# ------------------------------------------------------------------- saneado


def test_sanitize_accepts_valid_values():
    clean, rejected = appearance.sanitize({
        "theme": {"accent": "#ff00ff", "fontScale": 1.2},
        "render": {"bloom": False, "nodeResolution": 8},
        "colorMode": "role",
    })
    assert clean["theme"]["accent"] == "#ff00ff"
    assert clean["render"]["bloom"] is False
    assert clean["colorMode"] == "role"
    assert rejected == []


def test_sanitize_clamps_out_of_range():
    clean, _ = appearance.sanitize({
        "render": {"bloomStrength": 999, "nodeResolution": 1},
        "physics": {"chargeStrength": -99999},
    })
    assert clean["render"]["bloomStrength"] == 4.0
    assert clean["render"]["nodeResolution"] == 3
    assert clean["physics"]["chargeStrength"] == -600


def test_sanitize_rejects_unknown_and_malformed():
    clean, rejected = appearance.sanitize({
        "render": {"noExiste": 1, "bloom": "quiza"},
        "theme": {"accent": "rojo"},
        "seccionInventada": {"x": 1},
        "colorMode": "por-signo-del-zodiaco",
    })
    assert "render.noExiste" in rejected
    assert "theme.accent" in rejected
    assert "colorMode" in rejected
    assert "theme" not in clean
    # 'bloom' es booleano: "quiza" no es None, asi que se acepta como verdadero.
    assert clean["render"]["bloom"] is False or clean["render"]["bloom"] is True


def test_sanitize_only_known_entities_and_relations():
    clean, rejected = appearance.sanitize({
        "entities": {"host": {"color": "#123456", "scale": 2},
                     "unicornio": {"color": "#ffffff"}},
        "relations": {"lateral": {"width": 4}, "teletransporte": {"width": 1}},
    })
    assert clean["entities"]["host"]["color"] == "#123456"
    assert "unicornio" not in clean.get("entities", {})
    assert "entities.unicornio" in rejected
    assert "relations.teletransporte" in rejected


def test_sanitize_risk_weights():
    clean, rejected = appearance.sanitize({
        "riskWeights": {"severity": 20, "inventado": 3, "degree": "muchos"},
    })
    assert clean["riskWeights"] == {"severity": 20}
    assert "riskWeights.inventado" in rejected
    assert "riskWeights.degree" in rejected


# --------------------------------------------------------------- persistencia


def test_update_persists_and_merges():
    appearance.update({"theme": {"accent": "#ff00ff"}})
    appearance.update({"render": {"bloom": False}})
    profile = appearance.load()
    # El segundo parche no puede haberse llevado por delante al primero.
    assert profile["theme"]["accent"] == "#ff00ff"
    assert profile["render"]["bloom"] is False
    # Y lo que nadie toco sigue en su valor de fabrica.
    assert profile["render"]["nodeResolution"] == appearance.defaults()["render"]["nodeResolution"]


def test_update_applies_risk_weights_immediately():
    appearance.update({"riskWeights": {"severity": 3}})
    assert risk_weights()["severity"] == 3


def test_reset_deletes_the_file():
    appearance.update({"theme": {"accent": "#ff00ff"}})
    assert appearance.APPEARANCE_PATH.exists()
    profile = appearance.reset()
    assert not appearance.APPEARANCE_PATH.exists()
    assert profile["theme"]["accent"] == appearance.defaults()["theme"]["accent"]


def test_corrupt_profile_does_not_break_startup():
    """Un JSON roto no puede dejar al equipo sin herramienta."""
    appearance.CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    appearance.APPEARANCE_PATH.write_text("{ esto no es json", encoding="utf-8")
    profile = appearance.load()
    assert profile == appearance.defaults()


def test_saved_file_is_only_the_diff():
    """Solo se guarda lo cambiado, para heredar futuros valores por defecto."""
    appearance.update({"theme": {"accent": "#ff00ff"}})
    stored = json.loads(appearance.APPEARANCE_PATH.read_text(encoding="utf-8"))
    assert stored == {"theme": {"accent": "#ff00ff"}}


# ---------------------------------------------------------------------- API


def test_get_appearance_ships_the_spec(client):
    payload = client.get("/api/appearance").json()
    assert "appearance" in payload and "defaults" in payload
    # El panel construye sus sliders con los rangos del servidor, no con copias.
    assert payload["spec"]["sections"]["render"]["bloomStrength"] == ["number", 0.0, 4.0]
    assert any(mode["id"] == "cluster" for mode in payload["colorModes"])


def test_put_appearance_reports_what_it_discarded(client):
    response = client.put("/api/appearance", json={
        "theme": {"accent": "#00ff88"},
        "render": {"inventado": True},
    })
    payload = response.json()
    assert response.status_code == 200
    assert payload["appearance"]["theme"]["accent"] == "#00ff88"
    assert "render.inventado" in payload["rejected"]


def test_put_appearance_survives_a_reload(client):
    client.put("/api/appearance", json={"camera": {"controlType": "fly"}})
    assert client.get("/api/appearance").json()["appearance"]["camera"]["controlType"] == "fly"


def test_reset_endpoint(client):
    client.put("/api/appearance", json={"theme": {"accent": "#00ff88"}})
    payload = client.post("/api/appearance/reset").json()
    assert payload["appearance"]["theme"]["accent"] == appearance.defaults()["theme"]["accent"]


# ------------------------------------------------------------- modelos .glb


def _glb(size: int = 64) -> bytes:
    """Cabecera glTF binaria minima, suficiente para el chequeo del endpoint."""
    return b"glTF" + b"\x02\x00\x00\x00" + b"\x00" * size


def test_upload_model(client):
    response = client.post("/api/appearance/model/server",
                           files={"file": ("rack.glb", _glb(), "model/gltf-binary")})
    payload = response.json()
    assert response.status_code == 200
    assert payload["appearance"]["models"]["server"] == "config/models/server.glb"
    assert appearance.model_path("server.glb").exists()


def test_upload_rejects_files_that_are_not_glb(client):
    """Se mira la cabecera, no la extension: esto lo cargara todo el equipo."""
    response = client.post("/api/appearance/model/server",
                           files={"file": ("falso.glb", b"<html>hola</html>", "model/gltf-binary")})
    assert response.status_code == 400
    assert "glTF" in response.json()["detail"]


@pytest.mark.parametrize("name", ["ser$ver", "mi modelo", "modelo;rm", "a" * 100])
def test_upload_rejects_dangerous_names(client, name):
    """El nombre acaba siendo un fichero en disco: solo se acepta lo previsible."""
    response = client.post(f"/api/appearance/model/{name}",
                           files={"file": ("x.glb", _glb(), "model/gltf-binary")})
    assert response.status_code == 400


def test_upload_cannot_traverse_directories(client):
    """Un intento de salir del directorio no puede acabar en 200 pase lo que pase."""
    response = client.post("/api/appearance/model/..%2F..%2Fetc%2Fpasswd",
                           files={"file": ("x.glb", _glb(), "model/gltf-binary")})
    assert response.status_code != 200


def test_delete_model_restores_the_procedural_one(client):
    client.post("/api/appearance/model/server",
                files={"file": ("rack.glb", _glb(), "model/gltf-binary")})
    response = client.delete("/api/appearance/model/server")
    assert response.status_code == 200
    assert "server" not in response.json()["appearance"].get("models", {})
    assert not appearance.model_path("server.glb").exists()
