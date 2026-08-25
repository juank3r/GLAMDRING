"""Perfil visual del equipo: qué ve el analista y con qué aspecto.

Vive en el servidor (``config/appearance.json``), no en el navegador. Es una
decisión deliberada: el sysadmin del SOC fija un estándar y todo el mundo ve lo
mismo, de modo que una captura de pantalla en un informe significa lo mismo para
quien la envía y para quien la recibe.

Cada valor de este fichero acaba llamando a un accesor de ``3d-force-graph`` o a
una variable CSS. El mapa completo está en ``docs/APPEARANCE.md``.

Todo lo que entra por ``update()`` viene de un formulario web, así que se valida
contra ``SPEC`` clave a clave: lo desconocido se descarta, lo fuera de rango se
recorta y lo que no es del tipo esperado se ignora. Un panel de administración
que acepte cualquier JSON es una forma elegante de romper la herramienta para
todo el equipo a la vez.
"""

from __future__ import annotations

import copy
import json
import os
import re
import tempfile
import threading
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .config import BASE_DIR
from .graph import ontology
from .graph.enrich import DEFAULT_RISK_WEIGHTS, set_risk_weights

CONFIG_DIR = BASE_DIR / "config"
APPEARANCE_PATH = CONFIG_DIR / "appearance.json"
MODELS_DIR = CONFIG_DIR / "models"

_HEX_COLOR = re.compile(r"^#(?:[0-9a-fA-F]{3}|[0-9a-fA-F]{6}|[0-9a-fA-F]{8})$")

_lock = threading.RLock()


# ---------------------------------------------------------------------------
# Perfil por defecto
# ---------------------------------------------------------------------------

def _default_theme() -> Dict[str, Any]:
    return {
        "preset": "soc-dark",
        "background": "#070a10",
        "panel": "#0d121c",
        "panelAlt": "#121927",
        "border": "#1d2635",
        "text": "#dce4f0",
        "textDim": "#8b98ad",
        "accent": "#2dd4bf",
        "fontScale": 1.0,
    }


def _default_render() -> Dict[str, Any]:
    return {
        "modelQuality": "auto",     # auto | high | medium | low
        "nodeResolution": 12,
        "linkResolution": 6,
        "nodeOpacity": 0.95,
        "linkOpacity": 0.55,
        "bloom": True,
        "bloomStrength": 0.9,
        "bloomRadius": 0.55,
        "bloomThreshold": 0.62,
        "fog": True,
        "fogDensity": 0.0016,
        "grid": True,
        "enablePointerInteraction": True,
        "linkHoverPrecision": 4,
        "showNavInfo": False,
        # Por encima de este numero de nodos se degrada la calidad sola.
        "heavyThreshold": 350,
    }


def _default_physics() -> Dict[str, Any]:
    return {
        "forceEngine": "d3",        # d3 | ngraph
        "numDimensions": 3,
        "chargeStrength": -170,
        "linkDistance": 42,
        "collide": True,
        "collideRadius": 1.15,      # x radio del modelo
        "d3AlphaDecay": 0.0228,
        "d3VelocityDecay": 0.32,
        "warmupTicks": 40,
        "cooldownTicks": 320,
        "dagMode": "",              # "" | td | bu | lr | rl | zout | zin | radialout | radialin
        "dagLevelDistance": 130,
        "layerSpacing": 130,
    }


def _default_labels() -> Dict[str, Any]:
    return {
        "nodeMode": "smart",        # never | hover | selection | smart | always
        "nodeRiskThreshold": 45,    # en modo smart, a partir de que riesgo se rotula
        "nodeSize": 1.0,
        "linkMode": "hover",        # never | hover | selection | always | busy
        "linkBusyThreshold": 5,     # en modo busy, a partir de cuantos eventos
        "linkSize": 1.0,
        "renderer": "sprite",       # sprite | css2d
    }


def _default_links() -> Dict[str, Any]:
    return {
        "particles": True,
        "particleDensity": 1.0,
        "particleSpeed": 1.0,
        "particleWidth": 1.1,
        "arrows": True,
        "arrowLength": 3.4,
        "gradient": True,
        "dashed": True,
        "curvature": 0.22,
        "widthScale": 1.0,
    }


def _default_camera() -> Dict[str, Any]:
    return {
        # 'orbit' y no 'trackball' a proposito. TrackballControls no fija el eje
        # vertical: al arrastrar se puede rodar la camara sin limite, el mundo
        # entero se inclina y las figuras acaban boca abajo. Una persona del
        # reves deja de parecer una persona, que es justo lo que hacia el grafo
        # legible de un vistazo. OrbitControls mantiene camera.up en +Y y no
        # permite alabeo, asi que la vertical se respeta siempre.
        # Quien prefiera el giro libre lo tiene en el panel; esto es solo el
        # punto de partida.
        "controlType": "orbit",     # trackball | orbit | fly
        "autoOrbit": False,
        "orbitSpeed": 1.0,
        "focusDistance": 130,
        "transitionMs": 900,
        # Como se orientan las figuras que tienen frente.
        #   fixed     -> no giran nunca
        #   yaw       -> giran sobre su eje vertical para darte la cara
        #   billboard -> encaran la camara por completo
        "figureFacing": "yaw",
    }


def _default_interaction() -> Dict[str, Any]:
    return {
        "dimOnSelect": True,
        # 0.18 y no 0.07. Atenuar sirve para que destaque lo seleccionado, no
        # para borrar lo demas: al 7% sobre un fondo casi negro un nodo queda en
        # luminancia ~22, que en una sala con luz no se ve. Y entonces al
        # seleccionar algo la pantalla parece apagarse, que es justo lo que se
        # queria evitar: el contexto es lo que dice DONDE esta lo importante.
        "dimOpacity": 0.18,
        "hoverHighlight": True,
        "fixOnDrag": True,
        "expandOnDoubleClick": True,
    }


def defaults() -> Dict[str, Any]:
    """Perfil de fábrica. Las entidades y relaciones salen de la ontología."""
    return {
        "version": 1,
        "theme": _default_theme(),
        "render": _default_render(),
        "physics": _default_physics(),
        "labels": _default_labels(),
        "links": _default_links(),
        "camera": _default_camera(),
        "interaction": _default_interaction(),
        "colorMode": "type",
        "view": "explore",
        "riskWeights": dict(DEFAULT_RISK_WEIGHTS),
        # Sustituciones por tipo. Vacío = usar la ontología tal cual.
        "entities": {},   # {"host": {"color": "#...", "model": "server", "scale": 1.2, "visible": true}}
        "relations": {},  # {"lateral": {"color": "#...", "width": 2, "particles": true}}
        "models": {},     # {"server": "/config/models/server.glb"}
    }


# ---------------------------------------------------------------------------
# Validación
#
# ("color",)                -> cadena #rgb / #rrggbb / #rrggbbaa
# ("number", min, max)      -> float recortado al rango
# ("int", min, max)         -> entero recortado al rango
# ("bool",)                 -> booleano
# ("enum", [...])           -> uno de la lista
# ---------------------------------------------------------------------------

SPEC: Dict[str, Dict[str, Tuple]] = {
    "theme": {
        "preset": ("enum", ["soc-dark", "matrix", "contrast", "paper"]),
        "background": ("color",), "panel": ("color",), "panelAlt": ("color",),
        "border": ("color",), "text": ("color",), "textDim": ("color",),
        "accent": ("color",),
        "fontScale": ("number", 0.7, 1.6),
    },
    "render": {
        "modelQuality": ("enum", ["auto", "high", "medium", "low"]),
        "nodeResolution": ("int", 3, 32),
        "linkResolution": ("int", 2, 16),
        "nodeOpacity": ("number", 0.05, 1.0),
        "linkOpacity": ("number", 0.05, 1.0),
        "bloom": ("bool",),
        "bloomStrength": ("number", 0.0, 4.0),
        "bloomRadius": ("number", 0.0, 2.0),
        "bloomThreshold": ("number", 0.0, 1.0),
        "fog": ("bool",),
        "fogDensity": ("number", 0.0, 0.02),
        "grid": ("bool",),
        "enablePointerInteraction": ("bool",),
        "linkHoverPrecision": ("int", 1, 20),
        "showNavInfo": ("bool",),
        "heavyThreshold": ("int", 50, 20000),
    },
    "physics": {
        "forceEngine": ("enum", ["d3", "ngraph"]),
        "numDimensions": ("int", 1, 3),
        "chargeStrength": ("number", -600, 0),
        "linkDistance": ("number", 5, 400),
        "collide": ("bool",),
        "collideRadius": ("number", 0.0, 4.0),
        "d3AlphaDecay": ("number", 0.0, 0.5),
        "d3VelocityDecay": ("number", 0.0, 0.95),
        "warmupTicks": ("int", 0, 500),
        "cooldownTicks": ("int", 0, 5000),
        "dagMode": ("enum", ["", "td", "bu", "lr", "rl", "zout", "zin", "radialout", "radialin"]),
        "dagLevelDistance": ("number", 20, 600),
        "layerSpacing": ("number", 40, 600),
    },
    "labels": {
        "nodeMode": ("enum", ["never", "hover", "selection", "smart", "always"]),
        "nodeRiskThreshold": ("int", 0, 100),
        "nodeSize": ("number", 0.4, 3.0),
        "linkMode": ("enum", ["never", "hover", "selection", "always", "busy"]),
        "linkBusyThreshold": ("int", 1, 10000),
        "linkSize": ("number", 0.4, 3.0),
        "renderer": ("enum", ["sprite", "css2d"]),
    },
    "links": {
        "particles": ("bool",),
        "particleDensity": ("number", 0.0, 4.0),
        "particleSpeed": ("number", 0.1, 6.0),
        "particleWidth": ("number", 0.2, 6.0),
        "arrows": ("bool",),
        "arrowLength": ("number", 0.0, 14.0),
        "gradient": ("bool",),
        "dashed": ("bool",),
        "curvature": ("number", 0.0, 1.0),
        "widthScale": ("number", 0.2, 5.0),
    },
    "camera": {
        "controlType": ("enum", ["trackball", "orbit", "fly"]),
        "autoOrbit": ("bool",),
        "orbitSpeed": ("number", 0.1, 6.0),
        "focusDistance": ("number", 20, 800),
        "transitionMs": ("int", 0, 6000),
        "figureFacing": ("enum", ["fixed", "yaw", "billboard"]),
    },
    "interaction": {
        "dimOnSelect": ("bool",),
        "dimOpacity": ("number", 0.0, 1.0),
        "hoverHighlight": ("bool",),
        "fixOnDrag": ("bool",),
        "expandOnDoubleClick": ("bool",),
    },
}

# Campos permitidos al sobrescribir una entidad o una relación concreta.
ENTITY_SPEC: Dict[str, Tuple] = {
    "color": ("color",),
    "model": ("str", 40),
    "shape": ("str", 24),
    "glyph": ("str", 8),
    "size": ("number", 0.5, 40),
    "scale": ("number", 0.2, 5.0),
    "visible": ("bool",),
    "label": ("str", 60),
}

RELATION_SPEC: Dict[str, Tuple] = {
    "color": ("color",),
    "label": ("str", 60),
    "width": ("number", 0.1, 12),
    "weight": ("int", 0, 10),
    "dashed": ("bool",),
    "particles": ("bool",),
    "curvature": ("number", 0.0, 1.0),
    "text": ("bool",),
    "visible": ("bool",),
}


def _coerce(rule: Tuple, value: Any) -> Optional[Any]:
    """Devuelve el valor saneado, o None si no hay forma de aceptarlo."""
    kind = rule[0]
    try:
        if kind == "color":
            text = str(value).strip()
            return text if _HEX_COLOR.match(text) else None
        if kind == "bool":
            if isinstance(value, bool):
                return value
            if isinstance(value, str):
                return value.strip().lower() in ("1", "true", "yes", "on", "si")
            return bool(value)
        if kind == "int":
            return max(rule[1], min(rule[2], int(float(value))))
        if kind == "number":
            return max(rule[1], min(rule[2], float(value)))
        if kind == "enum":
            text = str(value)
            return text if text in rule[1] else None
        if kind == "str":
            text = str(value).strip()
            return text[: rule[1]] if text else None
    except (TypeError, ValueError):
        return None
    return None


def sanitize(patch: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Filtra un parche entrante contra SPEC. Devuelve (limpio, descartado)."""
    clean: Dict[str, Any] = {}
    rejected: List[str] = []

    for section, rules in SPEC.items():
        incoming = patch.get(section)
        if not isinstance(incoming, dict):
            continue
        bucket: Dict[str, Any] = {}
        for key, value in incoming.items():
            rule = rules.get(key)
            if rule is None:
                rejected.append(f"{section}.{key}")
                continue
            coerced = _coerce(rule, value)
            if coerced is None:
                rejected.append(f"{section}.{key}")
                continue
            bucket[key] = coerced
        if bucket:
            clean[section] = bucket

    for section, item_spec, known in (
        ("entities", ENTITY_SPEC, set(ontology.ENTITIES)),
        ("relations", RELATION_SPEC, set(ontology.RELATIONS)),
    ):
        incoming = patch.get(section)
        if not isinstance(incoming, dict):
            continue
        bucket = {}
        for name, overrides in incoming.items():
            if name not in known or not isinstance(overrides, dict):
                rejected.append(f"{section}.{name}")
                continue
            item: Dict[str, Any] = {}
            for key, value in overrides.items():
                rule = item_spec.get(key)
                if rule is None:
                    rejected.append(f"{section}.{name}.{key}")
                    continue
                coerced = _coerce(rule, value)
                if coerced is None:
                    rejected.append(f"{section}.{name}.{key}")
                    continue
                item[key] = coerced
            if item:
                bucket[name] = item
        if bucket:
            clean[section] = bucket

    color_mode = patch.get("colorMode")
    if color_mode in {mode["id"] for mode in ontology.COLOR_MODES}:
        clean["colorMode"] = color_mode
    elif color_mode is not None:
        rejected.append("colorMode")

    view = patch.get("view")
    if view in ("explore", "killchain", "timeline3d"):
        clean["view"] = view
    elif view is not None:
        rejected.append("view")

    weights = patch.get("riskWeights")
    if isinstance(weights, dict):
        bucket = {}
        for key, value in weights.items():
            if key not in DEFAULT_RISK_WEIGHTS:
                rejected.append(f"riskWeights.{key}")
                continue
            try:
                bucket[key] = max(0, min(500, int(value)))
            except (TypeError, ValueError):
                rejected.append(f"riskWeights.{key}")
        if bucket:
            clean["riskWeights"] = bucket

    return clean, rejected


# ---------------------------------------------------------------------------
# Persistencia
# ---------------------------------------------------------------------------


def _deep_merge(base: Dict[str, Any], patch: Dict[str, Any]) -> Dict[str, Any]:
    out = copy.deepcopy(base)
    for key, value in patch.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def _read_stored() -> Dict[str, Any]:
    if not APPEARANCE_PATH.exists():
        return {}
    try:
        return json.loads(APPEARANCE_PATH.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        # Un perfil corrupto no puede dejar la herramienta sin arrancar: se
        # ignora y se sigue con los valores de fábrica.
        return {}


def _write_stored(profile: Dict[str, Any]) -> None:
    """Escritura atómica: primero a un temporal, luego un rename.

    Si el proceso muere a mitad de escritura, el fichero anterior sigue intacto
    en vez de quedarse truncado y dejar al equipo sin perfil.
    """
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(profile, indent=2, ensure_ascii=False)
    handle, temp_path = tempfile.mkstemp(dir=str(CONFIG_DIR), suffix=".tmp")
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(payload)
        os.replace(temp_path, APPEARANCE_PATH)
    except BaseException:
        Path(temp_path).unlink(missing_ok=True)
        raise


def load() -> Dict[str, Any]:
    """Perfil efectivo: los valores de fábrica con lo guardado por encima."""
    with _lock:
        profile = _deep_merge(defaults(), _read_stored())
        set_risk_weights(profile.get("riskWeights"))
        return profile


def update(patch: Dict[str, Any]) -> Tuple[Dict[str, Any], List[str]]:
    """Aplica un parche saneado y lo persiste. Devuelve (perfil, descartado)."""
    clean, rejected = sanitize(patch or {})
    with _lock:
        stored = _deep_merge(_read_stored(), clean)
        _write_stored(stored)
        profile = _deep_merge(defaults(), stored)
        set_risk_weights(profile.get("riskWeights"))
    return profile, rejected


def reset() -> Dict[str, Any]:
    """Vuelve a fábrica borrando el fichero, no escribiendo los defectos.

    Asi, si una version futura cambia los valores por defecto, el equipo se
    beneficia sin tener que volver a pulsar 'restablecer'.
    """
    with _lock:
        APPEARANCE_PATH.unlink(missing_ok=True)
        return load()


def register_model(entity_or_model: str, filename: str) -> Dict[str, Any]:
    """Asocia un ``.glb`` subido a un nombre de figura."""
    with _lock:
        stored = _read_stored()
        models = stored.setdefault("models", {})
        models[entity_or_model] = f"config/models/{filename}"
        _write_stored(stored)
        return _deep_merge(defaults(), stored)


def unregister_model(entity_or_model: str) -> Dict[str, Any]:
    """Quita la asociacion y borra el fichero: vuelve la figura procedural."""
    with _lock:
        stored = _read_stored()
        stored.get("models", {}).pop(entity_or_model, None)
        _write_stored(stored)
        model_path(f"{entity_or_model}.glb").unlink(missing_ok=True)
        return _deep_merge(defaults(), stored)


def model_path(filename: str) -> Path:
    return MODELS_DIR / filename
