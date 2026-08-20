# Extender GLAMDRING

Recetas para las seis cosas que se añaden con más frecuencia. Cada una dice qué
ficheros se tocan y, más importante, **qué no hay que tocar porque se propaga solo**.

---

## 1. Un SIEM nuevo

Cuatro pasos. El resto del sistema no se entera.

### 1.1 El conector

Una sola responsabilidad: devolver registros **crudos**. No normaliza, no construye
grafo, no filtra.

```python
# glamdring/connectors/misiem.py
from .base import Connector, ConnectorError


class MiSiemConnector(Connector):
    name = "misiem"
    query_language = "MiQL"
    example_query = "SELECT * FROM eventos LAST 24 HOURS"

    def __init__(self, config=None):
        self.config = config or SETTINGS.misiem

    @property
    def configured(self) -> bool:
        return bool(self.config.url and self.config.token)

    async def fetch(self, query, time_from=None, time_to=None, limit=10_000):
        if not self.configured:
            raise ConnectorError(self.name, "MiSIEM no esta configurado.")
        import httpx
        async with httpx.AsyncClient(timeout=SETTINGS.query_timeout) as client:
            response = await client.post(f"{self.config.url}/api/search",
                                         json={"q": query, "limit": limit})
            if response.status_code >= 400:
                raise ConnectorError(self.name,
                                     f"HTTP {response.status_code}: {response.text[:300]}",
                                     status=response.status_code)
            return response.json()["results"][:limit]
```

`httpx` se importa **dentro** del método a propósito: así un despliegue que solo
trabaje con ficheros no necesita la dependencia.

### 1.2 Darlo de alta

```python
# glamdring/connectors/__init__.py
_FACTORIES = {..., "misiem": MiSiemConnector}
```

Con eso ya aparece en `GET /api/connectors` y en el diálogo de la interfaz.

### 1.3 La configuración

```python
# glamdring/config.py
@dataclass
class MiSiemConfig:
    url: str = ""
    token: str = ""

    @property
    def configured(self) -> bool:
        return bool(self.url and self.token)
```

Añádelo a `Settings`, a `load_settings()` y a `public_status()` — este último dice
**si** está configurado, nunca **con qué**.

### 1.4 El normalizador

```python
# glamdring/normalize/misiem.py
from .base import first, parse_time, register
from ..models import CLASS_AUTHENTICATION, ActorRef, HostRef, NormalizedEvent, make_uid


def matches(record):
    return isinstance(record, dict) and "misiem_event_id" in record


def normalize(record):
    return NormalizedEvent(
        uid=make_uid("misiem", record),
        time=parse_time(first(record, "ts", "timestamp")),
        source="generic",           # o añade "misiem" a SourceId en models.py
        origin="misiem",
        class_name=CLASS_AUTHENTICATION,
        activity="logon",
        severity=3,
        status="success",
        message=str(first(record, "msg") or "")[:400],
        actor=ActorRef(user=first(record, "user")),
        device=HostRef(hostname=first(record, "host")),
        raw=record,
    )


register("misiem", matches, normalize, priority=10)
```

Y el import con efecto secundario:

```python
# glamdring/normalize/__init__.py
from . import misiem  # noqa: F401
```

**Prioridad:** menor número = se evalúa antes. Los específicos van a 10, el
genérico a 99. Si tu `matches()` reclama un registro pero `normalize()` devuelve
`None`, el registro **no se pierde**: se prueba el siguiente candidato.

### 1.5 El test, sin el SIEM delante

```python
import httpx, pytest, respx
from glamdring.connectors.misiem import MiSiemConnector


@pytest.mark.asyncio
@respx.mock
async def test_misiem_fetch():
    respx.post("https://misiem.corp/api/search").mock(
        return_value=httpx.Response(200, json={"results": [{"misiem_event_id": 1}]}))
    registros = await MiSiemConnector(MiSiemConfig(url="https://misiem.corp",
                                                   token="x")).fetch("*")
    assert len(registros) == 1
```

Para el normalizador basta con un diccionario, sin red:

```python
def test_misiem_normaliza():
    evento = normalize_record({"misiem_event_id": 1, "ts": "2026-08-19T09:00:00Z",
                               "user": "CORP\\jlopez", "host": "WKS-0421"})
    assert evento.actor.user == "CORP\\jlopez"
```

**No hay que tocar:** ni el grafo, ni la API, ni el frontend, ni la ontología.

---

## 2. Un tipo de entidad

```python
# glamdring/graph/ontology.py
ENTITIES = {
    ...,
    "container": {"label": "Contenedor", "color": "#38bdf8", "model": "server",
                  "shape": "box", "glyph": "📦", "rank": 2, "size": 6},
}
```

Y emitirlo desde la regla que corresponda:

```python
# glamdring/graph/extract.py
def _process_activity(collector, event):
    ...
    if event.raw.get("container_id"):
        container = collector.add("container", event.raw["container_id"])
        collector.link(process_key, container, "ran_on")
```

**No hay que tocar:** el frontend lo recibe por `GET /api/ontology`, y la leyenda,
los chips de filtro, los colores y el desplegable del panel de administrador se
actualizan solos.

---

## 3. Una relación

```python
# glamdring/graph/ontology.py
RELATIONS = {
    ...,
    "mounted": {"label": "monta", "color": "#22d3ee", "dashed": False, "weight": 2},
}
```

`weight` pesa en el cálculo de riesgo y en la distancia del layout. `dashed: True`
significa **relación inferida o contextual, no un hecho duro del log**, y se pinta
con trazo discontinuo: en forense esa es una distinción que no se puede perder.

Después, emítela desde `extract.py` con `collector.link(a, b, "mounted")`.

---

## 4. Una figura 3D

Un constructor que devuelva un `THREE.Group` de **~2 unidades de alto** centrado en
el origen. Quien lo llama se encarga de escalarlo al radio que toque, así que los
tamaños salen comparables sin ajustar cada figura a mano.

```javascript
// web/js/render/models.js
function container(ctx) {
  const group = new THREE.Group();
  const shell = mat(shade(ctx.color, 0.5), 0.1);

  group.add(mesh(geo('ct.body', () => new THREE.BoxGeometry(1.6, 1.1, 1.1)), shell));

  // Las nervaduras: lo que hace que se reconozca como contenedor y no como caja.
  const rib = geo('ct.rib', () => new THREE.BoxGeometry(0.06, 1.05, 0.04));
  for (let i = -3; i <= 3; i++) {
    group.add(mesh(rib, shell, i * 0.2, 0, 0.57));
  }

  const led = mesh(geo('ct.led', () => new THREE.SphereGeometry(0.08, 6, 5)),
                   glow(ctx.screenColor), 0.6, 0.42, 0.58);
  if (ctx.alarm) pulse(led, 3.4, 0.25, 1);
  group.add(led);
  return group;
}

const BUILDERS = { ..., container };
```

Los ayudantes disponibles: `geo(clave, fabrica)` cachea geometrías, `mat(color,
emisivo)` y `glow(color)` cachean materiales, `mesh(geo, mat, x, y, z)` posiciona,
`shade(hex, factor)` oscurece para las partes en sombra, `pulse(objeto)` late y
`spin(objeto)` gira. Las cachés importan: sin ellas, un grafo de 400 nodos crearía
400 geometrías idénticas.

`ctx` trae `color` (del tipo o del modo de color activo), `severityColor`,
`screenColor` y `alarm`.

Luego referénciala como `model` en la ontología. **Aparece sola** en el desplegable
del panel, porque ese desplegable se construye con `availableModels()`.

---

## 5. Un ajuste en el panel de administrador

Solo hay que declararlo. El control se genera solo, con sus límites, y queda
validado en el servidor por la **misma** definición.

```python
# glamdring/appearance.py

# 1. El valor de fábrica
def _default_render():
    return {..., "outlineSelection": True}

# 2. El tipo y el rango
SPEC = {
    "render": {..., "outlineSelection": ("bool",)},
}
```

Tipos disponibles: `("color",)`, `("bool",)`, `("int", min, max)`,
`("number", min, max)`, `("enum", [...])`, `("str", maxlen)`.

Ponle nombre legible en el frontend:

```javascript
// web/js/ui/admin.js
const FIELD_LABELS = { ..., outlineSelection: 'Contorno en la selección' };
```

Y úsalo donde toque:

```javascript
// web/js/render/graph3d.js
if (opt('render', 'outlineSelection', true)) { /* ... */ }
```

Documéntalo en `docs/APPEARANCE.md` y en [[Admin-Panel]].

> Si el ajuste es una opción **de construcción** (`controlType`, `extraRenderers`,
> `rendererConfig`), añádelo también a `signatureOf()` para que el cambio provoque
> la reconstrucción de la instancia. Si no, el control no hará nada.

---

## 6. Un formato de informe

Un renderizador que tome el diccionario de `report/builder.py` y devuelva texto:

```python
# glamdring/report/csv_entities.py
import csv, io


def render(report):
    salida = io.StringIO()
    escritor = csv.writer(salida)
    escritor.writerow(["riesgo", "tipo", "entidad", "papel", "eventos"])
    for item in report["entities"]:
        escritor.writerow([item["risk"], item["typeLabel"], item["label"],
                           item["roleLabel"], item["events"]])
    return salida.getvalue()
```

```python
# glamdring/report/__init__.py
FORMATS = {
    ...,
    "csv": ("text/csv; charset=utf-8", "csv", lambda r: csv_entities.render(r)),
}
```

Con eso ya está en `POST /api/report`. Para que aparezca en el diálogo, añádelo a
`FORMATS` en `web/js/ui/report.js`.

**Todos los formatos parten del mismo diccionario.** Ese paso intermedio es lo que
garantiza que dos formatos del mismo incidente no se contradigan.

---

## Los tests

| Fichero | Cubre |
|---|---|
| `test_normalize.py` | canonicalización, los cuatro normalizadores, formatos de fecha |
| `test_graph.py` | extracción, agregación, fusiones, filtros, N saltos, timeline |
| `test_enrich.py` | papeles, clusters, figuras, pesos del riesgo |
| `test_appearance.py` | saneado, persistencia, rutas del panel, subida de `.glb` |
| `test_report.py` | narrativa, IOCs, los cuatro formatos, escapado de HTML |
| `test_api.py` | todas las rutas con `TestClient` |
| `test_web.py` | integridad del frontend sin ejecutar JavaScript |

`test_web.py` merece una mención: comprueba que **todo `import` y todo asset
resuelve a un fichero real**, que los `id` que busca el JavaScript existen en el
HTML, y que las dos copias de three coinciden en revisión. Un `import` roto deja la
página en blanco con un simple 404 en la consola, y ese test lo caza sin abrir un
navegador.

Ninguno necesita red ni credenciales: todo corre contra `samples/`.

```bash
pytest -q                              # todo
pytest tests/test_enrich.py -v         # un fichero
pytest -k "fusion or merge" -v         # por nombre
```

### Añadir datos de ejemplo

Si tu caso necesita eventos nuevos, mételos en `samples/` con el formato **crudo**
del fabricante, no ya normalizado. Así los normalizadores se ejercitan de verdad, y
`test_api.py::test_demo_loads_all_samples` comprueba que `unmatched == 0`.

---

Relacionadas: [[Architecture]] · [[Normalizers]] · [[Admin-Panel]]
