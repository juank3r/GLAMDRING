"""Descarga las librerias del frontend a web/js/vendor/.

Existe porque no hay npm en la maquina y porque los addons de three
(CSS2DRenderer, UnrealBloomPass, GLTFLoader) son modulos ES que importan otros
modulos: bajarlos a mano es un juego de cadenas rotas. El script resuelve los
imports relativos en cascada hasta que no queda nada pendiente.

    python tools/fetch_vendor.py

Los especificadores desnudos ('three', 'three/addons/...') NO se descargan: los
resuelve el importmap de index.html contra los ficheros que si bajamos.

Version de three: la MISMA que empaqueta 3d-force-graph internamente (r168).
Si no coinciden, mezclar objetos entre las dos copias rompe el post-procesado.
"""

from __future__ import annotations

import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

THREE_VERSION = "0.168.0"
SPRITETEXT_VERSION = "1.9.0"
FORCEGRAPH_VERSION = "1.73.4"

VENDOR = Path(__file__).resolve().parent.parent / "web" / "js" / "vendor"
CDN = "https://unpkg.com"

# Cada entrada es (url remota, ruta local relativa a vendor/).
ROOTS = [
    (f"{CDN}/three@{THREE_VERSION}/build/three.module.js", "three.module.js"),
    (f"{CDN}/three@{THREE_VERSION}/examples/jsm/renderers/CSS2DRenderer.js", "jsm/renderers/CSS2DRenderer.js"),
    (f"{CDN}/three@{THREE_VERSION}/examples/jsm/postprocessing/EffectComposer.js", "jsm/postprocessing/EffectComposer.js"),
    (f"{CDN}/three@{THREE_VERSION}/examples/jsm/postprocessing/RenderPass.js", "jsm/postprocessing/RenderPass.js"),
    (f"{CDN}/three@{THREE_VERSION}/examples/jsm/postprocessing/UnrealBloomPass.js", "jsm/postprocessing/UnrealBloomPass.js"),
    (f"{CDN}/three@{THREE_VERSION}/examples/jsm/postprocessing/OutputPass.js", "jsm/postprocessing/OutputPass.js"),
    (f"{CDN}/three@{THREE_VERSION}/examples/jsm/postprocessing/OutlinePass.js", "jsm/postprocessing/OutlinePass.js"),
    (f"{CDN}/three@{THREE_VERSION}/examples/jsm/loaders/GLTFLoader.js", "jsm/loaders/GLTFLoader.js"),
    (f"{CDN}/three-spritetext@{SPRITETEXT_VERSION}/dist/three-spritetext.mjs", "three-spritetext.mjs"),
    (f"{CDN}/3d-force-graph@{FORCEGRAPH_VERSION}/dist/3d-force-graph.min.js", "3d-force-graph.min.js"),
]

# Ficheros ya obsoletos que hay que borrar al migrar (three r160 UMD y su
# compañero, sustituidos por el build de modulos de r168).
STALE = ["three.min.js", "three-spritetext.min.js"]

IMPORT_RE = re.compile(r"""(?:from|import)\s*\(?\s*['"]([^'"]+)['"]""")


def fetch(url: str) -> str:
    request = urllib.request.Request(url, headers={"User-Agent": "glamdring-vendor/1.0"})
    with urllib.request.urlopen(request, timeout=60) as response:
        return response.read().decode("utf-8")


def local_of(url: str) -> str:
    """URL de unpkg -> ruta dentro de vendor/, conservando la estructura de jsm."""
    path = url.split("/", 3)[-1]
    if "/examples/jsm/" in path:
        return "jsm/" + path.split("/examples/jsm/", 1)[1]
    return path.rsplit("/", 1)[-1]


def resolve(base_url: str, specifier: str) -> str:
    """Resuelve un import relativo contra la URL del fichero que lo declara."""
    base = base_url.rsplit("/", 1)[0]
    parts = base.split("/")
    for chunk in specifier.split("/"):
        if chunk == ".":
            continue
        if chunk == "..":
            parts.pop()
        else:
            parts.append(chunk)
    return "/".join(parts)


def main() -> int:
    VENDOR.mkdir(parents=True, exist_ok=True)

    pending = list(ROOTS)
    done: set[str] = set()
    written = 0

    while pending:
        url, target = pending.pop(0)
        if url in done:
            continue
        done.add(url)

        try:
            body = fetch(url)
        except urllib.error.HTTPError as exc:
            print(f"  ERROR {exc.code} -> {url}", file=sys.stderr)
            return 1
        except urllib.error.URLError as exc:
            print(f"  SIN RED -> {url} ({exc.reason})", file=sys.stderr)
            return 1

        destination = VENDOR / target
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(body, encoding="utf-8")
        written += 1
        print(f"  {target:<52} {len(body) // 1024:>5} KB")

        # Solo se siguen los imports de los modulos ES; el UMD es autocontenido.
        if not target.endswith((".js", ".mjs")) or target == "3d-force-graph.min.js":
            continue
        for specifier in IMPORT_RE.findall(body):
            if not specifier.startswith("."):
                continue  # 'three' y 'three/addons/...' los resuelve el importmap
            child_url = resolve(url, specifier)
            if child_url not in done:
                pending.append((child_url, local_of(child_url)))

    for name in STALE:
        stale = VENDOR / name
        if stale.exists():
            stale.unlink()
            print(f"  eliminado obsoleto: {name}")

    print(f"\n{written} ficheros en {VENDOR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
