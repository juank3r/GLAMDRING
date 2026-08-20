"""El frontend: que todo lo que la pagina pide exista y encaje.

No se ejecuta JavaScript aqui (no hay motor), pero si se comprueba la clase de
fallo que mas veces rompe una pagina sin build: una ruta mal escrita. Un import
a un fichero que no esta deja el modulo entero sin cargar y la aplicacion en
blanco, sin mas pista que un 404 en la consola del navegador.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from glamdring.config import WEB_DIR
from glamdring.main import app

VENDOR = WEB_DIR / "js" / "vendor"

IMPORT_RE = re.compile(r"""(?:^|\n)\s*(?:import|export)\s[^;\n]*?from\s*['"]([^'"]+)['"]""")
DYNAMIC_RE = re.compile(r"""import\(\s*['"]([^'"]+)['"]""")
ASSET_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+)["']""")

# El bundle UMD y el build de three no se analizan: son minificados y de terceros.
SKIP = {"3d-force-graph.min.js", "three.module.js"}


@pytest.fixture(scope="module")
def html() -> str:
    return (WEB_DIR / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def importmap(html: str) -> dict:
    match = re.search(r'<script type="importmap">(.*?)</script>', html, re.S)
    assert match, "index.html tiene que declarar un importmap"
    return json.loads(match.group(1))["imports"]


def our_modules():
    """Modulos ES propios, sin lo vendorizado."""
    return [path for path in sorted((WEB_DIR / "js").rglob("*.js"))
            if "vendor" not in path.parts]


def all_modules():
    return [path for path in sorted(list(WEB_DIR.rglob("*.js")) + list(WEB_DIR.rglob("*.mjs")))
            if path.name not in SKIP]


def resolve(spec: str, origin: Path, importmap: dict) -> Path | None:
    if spec in importmap:
        return (WEB_DIR / importmap[spec].lstrip("./")).resolve()
    for prefix, target in importmap.items():
        if prefix.endswith("/") and spec.startswith(prefix):
            return (WEB_DIR / target.lstrip("./") / spec[len(prefix):]).resolve()
    if spec.startswith("."):
        return (origin.parent / spec).resolve()
    return None


# ------------------------------------------------------------------ imports


def test_every_import_resolves(importmap):
    """Un import roto deja la pagina en blanco sin mas aviso que un 404."""
    broken = []
    for module in all_modules():
        text = module.read_text(encoding="utf-8", errors="replace")
        specs = set(IMPORT_RE.findall(text)) | set(DYNAMIC_RE.findall(text))
        for spec in specs:
            target = resolve(spec, module, importmap)
            name = module.relative_to(WEB_DIR)
            if target is None:
                broken.append(f"{name}: '{spec}' no lo cubre el importmap")
            elif not target.exists():
                broken.append(f"{name}: '{spec}' no existe")
    assert not broken, "\n".join(broken)


def test_importmap_covers_bare_specifiers(importmap):
    assert importmap["three"].endswith("three.module.js")
    assert importmap["three/addons/"].endswith("jsm/")


def test_html_assets_exist(html):
    missing = [asset for asset in ASSET_RE.findall(html)
               if not asset.startswith(("data:", "http:", "https:", "#"))
               and not (WEB_DIR / asset).exists()]
    assert not missing, f"assets que no existen: {missing}"


def test_ids_used_by_js_exist_in_html(html):
    """getElementById sobre un id inexistente devuelve null y revienta al usarlo."""
    ids = set(re.findall(r'id="([^"]+)"', html))
    used = set()
    for module in our_modules():
        used |= set(re.findall(r"""getElementById\(['"]([^'"]+)['"]\)""",
                               module.read_text(encoding="utf-8", errors="replace")))
    assert not (used - ids), f"ids que el JS busca y el HTML no tiene: {sorted(used - ids)}"


# ------------------------------------------------------------------ vendor


def test_vendor_files_are_present():
    required = [
        "three.module.js",
        "three-spritetext.mjs",
        "3d-force-graph.min.js",
        "jsm/renderers/CSS2DRenderer.js",
        "jsm/postprocessing/UnrealBloomPass.js",
        "jsm/postprocessing/EffectComposer.js",
        "jsm/loaders/GLTFLoader.js",
    ]
    missing = [name for name in required if not (VENDOR / name).exists()]
    assert not missing, (f"faltan librerias vendorizadas: {missing}. "
                         "Ejecuta 'python tools/fetch_vendor.py'.")


def test_three_revisions_match():
    """LA comprobacion critica del frontend.

    Hay dos copias de three en la pagina: la nuestra y la que 3d-force-graph
    empaqueta dentro de su bundle UMD. Con la MISMA revision conviven sin
    problema (three identifica objetos por flags, no por instanceof), pero con
    revisiones distintas el post-procesado revienta con errores de shader que no
    dicen nada. Antes eran r160 y r168 y funcionaba de milagro.
    """
    ours = re.search(r"REVISION = '(\d+)'",
                     (VENDOR / "three.module.js").read_text(encoding="utf-8", errors="replace"))
    assert ours, "no se pudo leer la revision de three.module.js"

    bundle = (VENDOR / "3d-force-graph.min.js").read_text(encoding="utf-8", errors="replace")
    theirs = re.search(r'REVISION:([A-Za-z_$][\w$]*)', bundle)
    assert theirs, "no se pudo localizar la revision dentro del bundle"
    declared = re.search(rf'{re.escape(theirs.group(1))}="(\d+)"', bundle)
    assert declared, "no se pudo leer el valor de la revision del bundle"

    assert ours.group(1) == declared.group(1), (
        f"three propio r{ours.group(1)} frente a r{declared.group(1)} dentro de "
        "3d-force-graph. Ajusta THREE_VERSION en tools/fetch_vendor.py."
    )


def test_umd_bundle_exposes_the_global():
    text = (VENDOR / "3d-force-graph.min.js").read_text(encoding="utf-8", errors="replace")
    assert "ForceGraph3D" in text[:600], "el bundle debe exponer window.ForceGraph3D"


def test_no_stale_umd_three():
    """El three UMD r160 se retiro al migrar a modulos; si vuelve, hay dos copias."""
    assert not (VENDOR / "three.min.js").exists()


# --------------------------------------------------------------- servidor


@pytest.fixture(scope="module")
def client():
    return TestClient(app)


@pytest.mark.parametrize("path", [
    "/", "/css/glamdring.css", "/js/app.js", "/js/ontology.js",
    "/js/render/graph3d.js", "/js/render/models.js", "/js/render/links.js",
    "/js/ui/admin.js", "/js/ui/report.js",
    "/js/vendor/three.module.js", "/js/vendor/3d-force-graph.min.js",
    "/js/vendor/jsm/renderers/CSS2DRenderer.js",
])
def test_static_files_are_served(client, path):
    assert client.get(path).status_code == 200


def test_javascript_is_served_with_a_usable_mime(client):
    """Un modulo servido como text/plain lo rechaza el navegador entero."""
    content_type = client.get("/js/app.js").headers["content-type"]
    assert "javascript" in content_type


def test_index_loads_the_module_entrypoint(html):
    assert 'type="module" src="js/app.js"' in html
    # El bundle UMD tiene que ir ANTES: app.js usa el global ForceGraph3D.
    assert html.index("3d-force-graph.min.js") < html.index('type="module" src="js/app.js"')
