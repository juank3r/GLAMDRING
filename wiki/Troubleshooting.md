# Diagnóstico

Síntomas, causas y las trampas que cuestan encontrar porque **no lanzan ningún
error**.

---

## Las tres trampas de la librería

Estas tres se descubrieron cargando la aplicación en un navegador real. Ninguna
aparece en la consola, ninguna rompe un test unitario, y las tres dejan la
herramienta rota o a medias. Están documentadas aquí porque volverán a morder a
quien toque el renderizador.

### 1. La forma del constructor

**Síntoma:** la página carga, los paneles se pintan, el grafo se descarga y se
procesa… y el lienzo no existe. Consola limpia, cero errores.

**Causa:** la versión vendorizada (`3d-force-graph` 1.73.4) usa la forma *kapsule*:

```javascript
graph = ForceGraph3D(opciones)(contenedor);   // ✅ correcto con este bundle
```

La documentación del repositorio oficial enseña la otra forma, que es de una
versión **posterior**:

```javascript
graph = new ForceGraph3D(contenedor, opciones); // ❌ no crea el lienzo y no protesta
```

Con este bundle, esa segunda forma no hace absolutamente nada y no lanza
excepción. Se puede seguir encadenando `.nodeId()`, `.linkColor()` y todo lo demás
sin que salte nada.

**Cómo detectarlo:**

```javascript
document.querySelectorAll('#graph canvas').length   // 0 = no se construyó
```

**Si algún día se sube de versión**, hay que revisar esta línea en
`web/js/render/graph3d.js`.

### 2. Colisión de nombres de campo

**Síntoma:** la consola se llena de
`THREE.BufferGeometry.computeBoundingSphere(): Computed radius is NaN` en cada
fotograma, y las aristas curvas desaparecen.

**Causa:** `three-forcegraph` guarda su objeto `Curve` interno en **`link.__curve`**.
Al usar ese mismo nombre para nuestra curvatura, el accesor `linkCurvature` leía un
objeto `Curve` donde esperaba un número, y la librería construía un `TubeGeometry`
a partir de basura.

**La regla:** todo lo que escribimos en nodos y aristas lleva el prefijo **`__gd`**.

| Nuestro | De la librería (no tocar) |
|---|---|
| `__gdCurve`, `__gdCurveRot` | `__curve` |
| `__gdFirst`, `__gdLast` | `__data` |
| `__gdLevel` | `__threeObj`, `__lineObj` |
| `__gdTmin`, `__gdTmax` | `__arrowObj`, `__photons`, `__indexColor` |

**Cómo detectarlo:**

```javascript
const g = (await import('/js/render/graph3d.js')).default;
g.currentData().links.filter(l => typeof l.__gdCurve !== 'number');  // debe ser []
```

### 3. Coordenadas a medio asignar

**Síntoma:** el mismo `Computed radius is NaN`, pero en las líneas discontinuas o
en las etiquetas de arista.

**Causa:** `linkPositionUpdate` también se llama en los fotogramas en que un
extremo **aún no tiene posición** — justo después de `graphData()`, o con un nodo
oculto por el cursor del replay. Escribir `start.x + …` con `undefined` mete `NaN`
en la geometría, y a partir de ahí el objeto desaparece de la escena para siempre:
el `NaN` no se limpia solo.

**La solución** está en `web/js/render/links.js`: la función `usable()` valida los
dos extremos antes de tocar nada, y oculta el objeto si aún no son utilizables.

---

## Las dos copias de three

En la página hay **dos** instancias de three: la nuestra (módulo ES) y la que
`3d-force-graph` empaqueta dentro de su bundle UMD.

Eso es aceptable **solo si son la misma revisión (r168)**. Con la misma versión
conviven sin problema, porque three identifica objetos por flags (`.isObject3D`,
`.isMaterial`) y no por `instanceof`. Con revisiones distintas, el post-procesado
revienta con errores de shader que no dicen nada útil.

Verás siempre este aviso, y **es normal**:

```
WARNING: Multiple instances of Three.js being imported.
```

Hay un test que impide que la cosa se desmadre:

```bash
pytest tests/test_web.py::test_three_revisions_match
```

Si falla, ajusta `THREE_VERSION` en `tools/fetch_vendor.py` a la revisión que
empaquete la versión de `3d-force-graph` que tengas y vuelve a vendorizar:

```bash
python tools/fetch_vendor.py
```

---

## La página se queda en blanco

Por orden de probabilidad:

| Comprobación | Qué mirar |
|---|---|
| ¿404 en la consola? | un `import` roto. `pytest tests/test_web.py` lo caza sin abrir el navegador |
| ¿`ForceGraph3D` existe? | `typeof window.ForceGraph3D` debe ser `"function"`. Si no, el bundle UMD no cargó |
| ¿hay lienzo? | `document.querySelector('#graph canvas')` — ver [trampa 1](#1-la-forma-del-constructor) |
| ¿el importmap está bien? | tiene que ir **antes** que cualquier `<script type="module">` |
| ¿WebGL disponible? | `document.createElement('canvas').getContext('webgl2')` |

---

## Problemas de ingesta

### «Subí 500 eventos y solo aparecen 300»

Mira `GET /api/ingest-log`. Distingue tres casos:

- **`duplicates`** — el mismo evento ya estaba. El `uid` es un hash del registro
  crudo, así que reenviar el mismo fichero no duplica nada. Es lo esperado si la
  misma telemetría llega por dos caminos.
- **`unmatched`** — ningún normalizador supo interpretar el registro. **Debería ser
  0.** Si sube, hace falta un normalizador nuevo o el formato no se detectó bien;
  prueba a forzarlo con `format_hint`.
- **`dropped`** — se alcanzó el tope de `MAX_EVENTS` (500.000).

### «Los eventos aparecen con la hora de ahora»

Es el fallo más traicionero de la ingesta: no rompe nada visible, pero coloca los
eventos en el momento de la ingesta y **la cronología deja de significar nada**.

Pasa cuando `parse_time()` no reconoce el formato de fecha y cae a "ahora". Para
comprobarlo:

```bash
python -c "
from glamdring.normalize.base import parse_time
print(parse_time('Aug 19 2026 09:16:02'))"
```

Formatos ya cubiertos: epoch en segundos y milisegundos, ISO-8601 con y sin zona,
`MMM dd yyyy HH:mm:ss` (el `rt` de CEF), `dd MMM yyyy`, los de Windows y syslog
RFC3164 sin año. Si tu fuente usa otro, añádelo a `_TIME_FORMATS` **antes** de los
que no llevan año.

Hay un test que comprueba que ningún evento de los ficheros de ejemplo acaba con la
hora actual:

```bash
pytest tests/test_normalize.py::test_no_sample_event_falls_back_to_now
```

---

## Nodos que no cuadran

### «Aparecen máquinas que no existen en mi parque»

Probablemente sean **nombres de producto**. QRadar mete en `logsourcename` a veces
la máquina que reporta (`SRV-DC01`) y a veces el producto que lo hace
(`TrendMicro-AV`, `Bluecoat-Proxy`). Convertir un nombre de producto en un host
llena el grafo de equipos inventados.

`looks_like_product()` en `glamdring/normalize/qradar_events.py` filtra los
fabricantes y categorías conocidos. Si tu parque usa otro producto que se cuela,
añádelo a `_PRODUCT_MARKERS`. El valor sigue estando en `origin`, así que el dato
no se pierde.

### «La misma cosa aparece dos veces»

Las tres fusiones de `graph/build.py` son deliberadamente prudentes: **si hay
ambigüedad, no funden**.

| Caso | Se funde si | NO se funde si |
|---|---|---|
| `ip:X` en un host | un host declara esa IP | dos hosts la reclaman |
| fichero sin ruta | comparte hash con uno con ruta | hay varias rutas con ese hash |
| proceso sin ruta | mismo host y mismo ejecutable | hay varias rutas con ese nombre |

Los dos últimos «no se funde» son **hallazgos**, no defectos: dos rutas distintas
con el mismo hash son copias reales, y dos `svchost.exe` en rutas distintas es
exactamente lo que hay que mirar.

Para que la fusión IP↔host funcione, algún evento tiene que enseñar **hostname e IP
juntos**. Los normalizadores de red lo aprovechan: en una conexión saliente el
origen *es* la máquina que reporta, así que ahí se aprende su dirección.

### «Faltan usuarios»

`canon_user()` descarta a propósito las cuentas de máquina (`WKS-0421$`) y las de
servicio de Windows (`SYSTEM`, `NETWORK SERVICE`, `ANONYMOUS LOGON`). Aparecen en
todos los eventos y unirían el grafo entero por el sitio equivocado.

---

## Rendimiento

| Síntoma | Qué tocar en el panel |
|---|---|
| va a tirones al girar | **Render → Detalle de nodos** y **Detalle de aristas** abajo |
| tarda en asentarse | **Física → Ticks hasta parar** abajo, o **Evitar solapes** desactivado |
| el resplandor se come los fotogramas | **Render → Resplandor (bloom)** desactivado |
| demasiado texto | **Etiquetas → nodos: inteligente** y subir el umbral de riesgo |
| las partículas asfixian | **Aristas → Partículas de flujo** desactivado |
| el ratón responde con retraso | **Render → Interacción con el ratón** desactivado mientras navegas |

Por encima de `heavyThreshold` (350 nodos por defecto) la calidad de las figuras
baja sola, y por encima de `GLAMDRING_MAX_GRAPH_NODES` (1500) el backend recorta a
los de mayor riesgo y lo avisa en la barra de estado con «grafo recortado».

Si la máquina no tiene GPU decente, este perfil va bien:

```json
{
  "render": { "bloom": false, "fog": false, "modelQuality": "medium",
              "nodeResolution": 8, "heavyThreshold": 150 },
  "links":  { "particles": false },
  "physics": { "collide": false, "cooldownTicks": 120 }
}
```

---

## El perfil visual

### «Cambié algo y ahora todo el equipo lo ve»

Correcto: el perfil vive en el **servidor** (`config/appearance.json`) y es uno solo
para todos. Es deliberado, para que una captura signifique lo mismo para quien la
envía y para quien la recibe. **Perfil → Restablecer de fábrica** vuelve atrás.

### «Cambié el tipo de control de cámara y parpadeó todo»

`controlType`, el motor de etiquetas (`sprite` / `css2d`) y `rendererConfig` son
opciones **de construcción**, no setters. Cambiarlas obliga a levantar una instancia
nueva del grafo. Se hace solo, conservando datos, cámara y selección, pero se nota.

### «El perfil se corrompió»

Un JSON roto no deja la herramienta sin arrancar: `_read_stored()` lo ignora y
sigue con los valores de fábrica. Si quieres empezar limpio, borra el fichero:

```bash
rm config/appearance.json
```

Restablecer **borra el fichero** en lugar de escribir los valores por defecto, para
que una versión futura que cambie esos valores beneficie al equipo sin tener que
volver a pulsar el botón.

---

## Conectores

| Código | Significa | Qué mirar |
|---|---|---|
| `409` | el conector no tiene credenciales | ¿existe `.env`? ¿se reinició el servidor tras editarlo? |
| `502` | el SIEM falló o rechazó la consulta | el mensaje trae el error literal del SIEM |
| timeout | la búsqueda tarda más que `GLAMDRING_QUERY_TIMEOUT` | acota la ventana, o súbelo |

Con Splunk on-prem y certificado autofirmado, `SPLUNK_VERIFY_TLS=0`. Solo si sabes
contra qué servidor estás hablando.

---

## Tabla rápida

| Síntoma | Causa probable | Dónde mirar |
|---|---|---|
| página en blanco, consola limpia | forma del constructor | `graph3d.js`, `construct()` |
| `Computed radius is NaN` | colisión `__curve` o coordenadas sin asignar | `links.js`, prefijo `__gd` |
| errores de shader al activar bloom | revisiones de three distintas | `pytest tests/test_web.py` |
| eventos con la hora actual | formato de fecha no reconocido | `_TIME_FORMATS` en `normalize/base.py` |
| máquinas inventadas | nombres de producto de QRadar | `_PRODUCT_MARKERS` |
| entidades duplicadas | falta el evento que une hostname e IP | fusiones en `build.py` |
| `unmatched > 0` en la ingesta | falta un normalizador | `normalize/`, `register(...)` |
| grafo recortado | tope de nodos | `GLAMDRING_MAX_GRAPH_NODES` |

---

Relacionadas: [[Getting-Started]] · [[Architecture]] · [[Admin-Panel]]
