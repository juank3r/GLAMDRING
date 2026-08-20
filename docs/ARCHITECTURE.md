# Arquitectura

## Las seis etapas

```
┌────────────┐  ┌───────────┐  ┌──────────────┐  ┌─────────┐  ┌──────────┐  ┌──────────┐
│ CONNECTORS │─▶│ NORMALIZE │─▶│ EXTRACT+BUILD│─▶│ ENRICH  │─▶│QUERY/API │─▶│  RENDER  │
│SPL/KQL/AQL │  │ OCSF-lite │  │ grafo tipado │  │ papeles │  │ filtros  │  │ three.js │
└────────────┘  └───────────┘  └──────────────┘  └─────────┘  └──────────┘  └──────────┘
  dict crudo   NormalizedEvent   Node + Link      role/cluster   GraphDoc      WebGL
```

Cada etapa tiene un contrato explícito, así que se puede sustituir una sin tocar las
demás. **Regla de oro: el frontend solo conoce `GraphDoc`.** Da igual si viene de
Splunk en vivo, de un fichero CEF o de un fixture de test.

Encima de la tubería hay dos servicios transversales:

- **`appearance.py`** — el perfil visual del equipo, en `config/appearance.json`.
  Lo consumen el frontend (para pintar) y `enrich` (para los pesos del riesgo).
- **`report/`** — el informe del incidente, que parte del mismo `GraphDoc` y de los
  mismos eventos que ve el analista en pantalla.

---

## 1. Conectores — `glamdring/connectors/`

Una sola responsabilidad: devolver registros crudos. No normalizan, no construyen
grafo, no filtran. Añadir un SIEM nuevo son unas 60 líneas y nada más cambia.

```python
async def fetch(query, time_from, time_to, limit) -> list[dict]
```

| Fichero | Flujo |
|---|---|
| `splunk.py` | `POST /servicesNS/-/{app}/search/jobs/export` con `output_mode=json`; respuesta NDJSON, una línea por resultado. Se descartan las líneas `preview: true` para no duplicar. |
| `sentinel.py` | Dos caminos: `azure-monitor-query` si está instalado, si no REST contra `api.loganalytics.io` con token client-credentials de Entra ID. Log Analytics ya añade una columna `Type` con el nombre de la tabla. |
| `qradar.py` | Tres pasos: `POST /api/ariel/searches` → polling de `GET /api/ariel/searches/{id}` hasta `COMPLETED` → `GET .../results` con cabecera `Range`. Las ofensas van por `/api/siem/offenses`. |
| `files.py` | Fichero subido, texto pegado o ruta local. Es el que más se usa: casi nadie tiene credenciales de API del SIEM, pero todo el mundo puede exportar una búsqueda. |

---

## 2. Normalización — `glamdring/normalize/`

Registro con prioridad: gana el primero que dice «esto es mío». Los específicos
(prioridad 10) van antes que el genérico (prioridad 99), que **nunca devuelve None**
y sirve de red de seguridad. Un normalizador que lanza una excepción no tumba la
ingesta: se pasa al siguiente candidato.

```python
matches(record)   -> bool
normalize(record) -> NormalizedEvent | None
```

### El modelo: OCSF-lite

Subconjunto pragmático de OCSF con las clases que alimentan el grafo:

`Authentication` · `Process Activity` · `Network Activity` · `File System Activity`
· `DNS Activity` · `Email Activity` · `Account Change` · `Detection Finding`

**`raw` nunca se descarta.** Todo nodo y toda arista pueden volver al log literal.
Sin eso la herramienta no es defendible en un informe.

### Canonicalización — la pieza crítica

En `normalize/base.py`. Poco vistosa y determinante:

| Función | Qué resuelve |
|---|---|
| `canon_user` | `CORP\JLopez` = `jlopez@corp.com` = `JLOPEZ` → `jlopez`. Descarta cuentas de máquina (`WKS-0421$`) y de servicio (`SYSTEM`), que aparecen en todos los eventos y unirían el grafo por el sitio equivocado. |
| `canon_host` | `WKS-0421.corp.local` → `wks-0421`, dejando pasar las IP intactas. |
| `canon_path` | Minúsculas y separador unificado; NTFS no distingue mayúsculas. |
| `parse_time` | Epoch en segundos **y en milisegundos** (QRadar), ISO-8601 con y sin zona, formatos de Windows y de syslog. Todo sale en UTC. |
| `parse_severity` | Palabras (Sentinel), magnitud 1-10 (QRadar) y 0-10 (CEF) → escala 0-5. |

---

## 3. Extracción y agregación — `glamdring/graph/`

### `extract.py` — qué merece ser un nodo

La tentación es convertir cada campo en un nodo, y el resultado es una bola de pelo
ilegible. Las reglas son deliberadamente conservadoras:

- Solo hay nodo si hay **identidad estable**: un usuario, un host, un hash. Un
  puerto o un id de sesión son propiedades.
- Un extremo de red con hostname **e** IP es **un** nodo `host` con la IP como
  propiedad, no dos nodos. El hostname es la identidad estable; la IP cambia.
- Los procesos se anclan a su host (`wks-0421|c:\...\powershell.exe`). Si no,
  `powershell.exe` sería un único nodo compartido por todo el dominio.

Reglas por clase de evento:

| Evento | Aristas que genera |
|---|---|
| Logon 4624 correcto | `user −authenticated→ host`, `ip −connected→ host` |
| Logon 4625 fallido | `user −failed_auth→ host` |
| Logon tipo 3/10 correcto entre dos hosts | `hostA −lateral→ hostB` |
| Proceso 4688 / Sysmon 1 | `parent −spawned→ proc`, `user −executed→ proc`, `proc −ran_on→ host` |
| Conexión Sysmon 3 / DeviceNetwork | `proc −connected→ ip\|dominio`, `dominio −resolved→ ip` |
| Fichero Sysmon 11 | `proc −wrote→ file`, `file −has_hash→ hash` |
| Alerta | `alert −affects→ *` sobre todas las entidades que menciona |

### `build.py` — agregación

Miles de eventos colapsan en decenas de nodos y aristas. 400 logons del mismo
usuario contra el mismo servidor son **una** arista con `count=400`, no 400 líneas.

Cada arista guarda los `eventUids` que la produjeron (recortados a 200; el recuento
real sigue en `count`), que es lo que alimenta el inspector.

**Riesgo (0-100)** — heurística de priorización, no un veredicto:

```
severidad × 12   (0-60, factor dominante: viene del SIEM)
+ tácticas × 6   (máx 18)
+ grado × 2      (máx 12)
+ volumen/25     (máx 5, el volumen apenas cuenta)
+ peso rel./10   (máx 5)
+ 15 si es alerta
```

El volumen pesa poco a propósito: que una máquina sea habladora no la hace
peligrosa. Un servidor con 50.000 eventos informativos no debe tapar a la
workstation con una alerta crítica.

### `query.py` — dos tipos de filtro, y no son lo mismo

- **Sobre eventos** (tiempo, severidad, fuente, texto, táctica): cambian qué se
  agrega, así que **el grafo se reconstruye**. Filtrar por tiempo y dejar los
  `count` de las aristas al total sería mentir.
- **Sobre el grafo ya construido** (tipos, relaciones, foco a N saltos, tope de
  nodos): podas topológicas que no alteran los recuentos.

**Capas de la kill-chain** (`assign_levels`): el criterio principal es la táctica
MITRE. Los nodos sin táctica (una IP no tiene táctica) heredan por BFS la capa
mínima de sus vecinos; lo que sigue sin capa cae al orden natural de la ontología.
Después se compactan a enteros consecutivos para no dejar columnas vacías.

Se calcula en servidor y **no se usa `dagMode()` de la librería**: dagMode exige un
grafo acíclico y un grafo de incidente real casi nunca lo es (un proceso escribe un
fichero que otro proceso del mismo host vuelve a ejecutar).

---

## 4. API — `glamdring/api/`

| Método | Ruta | Qué hace |
|---|---|---|
| GET | `/api/health` | estado + conectores configurados (nunca las credenciales) |
| GET | `/api/ontology` | tipos, colores y formas; el frontend sobrescribe su copia |
| GET | `/api/connectors` | conectores, lenguaje de consulta y ejemplo |
| POST | `/api/ingest` | fichero subido, texto pegado o ruta local |
| POST | `/api/demo` | carga todo `samples/` |
| POST | `/api/query` | consulta en vivo a un SIEM |
| GET | `/api/graph` | grafo con todos los filtros |
| GET | `/api/graph/neighbors` | vecindad de N saltos |
| GET | `/api/timeline` | histograma para el slider y el replay |
| GET | `/api/events` | **logs crudos** de unos uids o de un nodo |
| GET | `/api/export` | grafo completo sin recortes, para el informe |

Los filtros se aplican **en servidor**: con 100.000 eventos no tiene sentido mandar
todo al navegador y filtrar allí.

Códigos de error con intención: `400` consulta mal formada, `409` conector sin
credenciales, `502` el SIEM falló. El analista tiene que poder distinguir «mi
consulta está mal» de «el SIEM no responde».

### El contrato `GraphDoc`

```jsonc
{
  "meta": { "counts": {...}, "sources": [...], "truncated": false, "notes": [] },
  "nodes": [{
    "id": "host:wks-0421",        // clave canónica "<tipo>:<valor normalizado>"
    "type": "host", "label": "WKS-0421",
    "firstSeen": "...", "lastSeen": "...",
    "eventCount": 128, "maxSeverity": 5, "risk": 87, "degree": 9,
    "sources": ["splunk", "sentinel"], "tactics": ["lateral-movement"],
    "props": { "ip": "10.4.2.11", "level": 3, "eventUids": [...] }
  }],
  "links": [{
    "id": "l17", "source": "user:jlopez", "target": "host:wks-0421",
    "type": "authenticated", "count": 12, "severity": 3,
    "firstSeen": "...", "lastSeen": "...", "eventUids": [...]
  }]
}
```

`id`, `source` y `target` con esos nombres exactos porque son los que
`3d-force-graph` espera por defecto: cero accesores que reconfigurar.

---

## 4b. Enriquecido — `glamdring/graph/enrich.py`

La diferencia con `extract.py` es de alcance. Allí se decide **qué** es un nodo
mirando UN evento; aquí se decide **qué papel juega** mirando el grafo entero ya
montado. Una IP no es hostil por sí misma: lo es porque es externa, porque una
alerta apunta a ella y porque el tráfico que sale hacia ella está etiquetado como
mando y control.

Escribe tres cosas en `node.props`:

- **`role`** — `hostile` · `victim` · `suspicious` · `asset` · `neutral`. Es lo que
  decide la figura 3D, así que el mismo `host` sale como rack sano o como puesto
  con la alarma encendida.
- **`cluster`** — comunidades por propagación de etiquetas. Se recorren los nodos
  en orden **determinista** (no aleatorio como en el algoritmo original) para que
  dos ejecuciones den lo mismo: un cluster que cambia de número en cada refresco
  haría bailar los colores.
- **`deviceClass`** y **`model`** — puesto / servidor / router / cortafuegos,
  deducido del hostname, y la figura que corresponde.

Va **después** de la poda a propósito: el papel depende de los vecinos, y
calcularlo sobre el grafo completo para luego recortar dejaría nodos marcados como
víctimas por una alerta que ya no se ve.

Aquí viven también los **pesos del riesgo**, que el panel de administrador puede
cambiar en caliente. Están aquí y no en `build.py` porque dos copias de la fórmula
acabarían con el grafo y el informe puntuando distinto.

---

## 4c. Perfil visual e informes

- **`appearance.py`** — carga, sanea y guarda `config/appearance.json`. Todo lo que
  entra se valida contra un `SPEC` clave a clave, y ese mismo `SPEC` viaja al
  navegador para que el panel construya sus controles con los rangos reales.
  Escritura atómica (temporal + rename): si el proceso muere a mitad, el perfil
  anterior sigue intacto en vez de quedarse truncado.
- **`report/`** — `builder.py` monta una estructura intermedia y `html.py`,
  `markdown.py` y `stix.py` la renderizan. Ese paso intermedio evita el problema
  clásico de que el HTML y el Markdown del mismo incidente cuenten cosas distintas.
  `narrative.py` convierte eventos en frases con plantillas, sin modelo de lenguaje:
  en un informe forense eso no es una limitación sino un requisito.

Detalle completo del panel en [APPEARANCE.md](APPEARANCE.md).

---

## 5. Frontend — `web/js/`

Módulos ES con `importmap`, servidos por el propio FastAPI. Sin `npm install`, sin
empaquetador, sin paso de compilación.

| Módulo | Responsabilidad |
|---|---|
| `ontology.js` | copia cliente; `adopt()` toma la del servidor, `applyProfile()` aplica el perfil encima |
| `api.js` | cliente HTTP; propaga el mensaje real del backend a la interfaz |
| `render/models.js` | **las 15 figuras 3D procedurales** |
| `render/sprites.js` | iconos por `CanvasTexture` para la calidad baja |
| `render/links.js` | texto en aristas, gradiente, trazo discontinuo, curvatura |
| `render/colors.js` | los siete modos de color y la leyenda de cada uno |
| `render/forces.js` | fuerza de colisión propia con rejilla espacial |
| `render/graph3d.js` | el `ForceGraph3D`, las disposiciones y la reconstrucción |
| `ui/filters.js` | panel izquierdo → parámetros de `/api/graph` |
| `ui/timeline.js` | histograma en canvas, brush y replay |
| `ui/inspector.js` | panel derecho y logs crudos bajo demanda |
| `ui/interactions.js` | menú contextual, atajos y ayuda |
| `ui/admin.js` | panel de administrador generado desde el `spec` del servidor |
| `ui/report.js` | diálogo de informe y captura del lienzo |
| `app.js` | estado único; todo cambio pasa por `reload()` |

### Dos copias de three, y por qué importa

`3d-force-graph` se carga como script clásico porque su bundle UMD es autocontenido;
vendorizar su versión ESM arrastraría a mano todo su árbol de dependencias
(`three-forcegraph`, `three-render-objects`, `kapsule`…). Eso deja **dos copias de
three** en la página: la nuestra y la suya.

Con la **misma revisión (r168)** conviven sin problema, porque three identifica
objetos por flags (`.isObject3D`, `.isMaterial`) y no por `instanceof`. Con
revisiones distintas el post-procesado revienta con errores de shader que no dicen
nada. Hay un test que lo comprueba: `tests/test_web.py::test_three_revisions_match`.

### Trampas de la librería que costaron encontrar

Las tres se manifiestan **sin lanzar ningún error**, que es lo que las hace caras:

1. **La forma del constructor.** La versión 1.73.4 usa la forma kapsule
   `ForceGraph3D(config)(elemento)`. La documentación del repositorio enseña
   `new ForceGraph3D(elemento, config)`, que es de una versión posterior: con este
   bundle no crea el lienzo y no protesta. La página se queda negra.
2. **Colisión de nombres de campo.** `three-forcegraph` guarda su curva interna en
   `link.__curve`. Usar ese mismo nombre hacía que nuestro accesor `linkCurvature`
   leyera un objeto `Curve` en lugar de un número; la librería construía un tubo a
   partir de basura y llenaba la consola de `Computed radius is NaN`. **Todo lo que
   escribimos en nodos y aristas lleva el prefijo `__gd`.**
3. **Coordenadas a medio asignar.** `linkPositionUpdate` también se llama en los
   fotogramas en que un extremo aún no tiene posición. Sin comprobarlo se escriben
   NaN en la geometría y el objeto desaparece de la escena para siempre.

### Las disposiciones

Un solo `ForceGraph3D` sirve las tres. No se recrea el grafo al cambiar de vista:
solo cambia cómo se fijan las posiciones.

- **explore** — simulación libre, `fx` sin fijar.
- **killchain** — `node.fx = level × 130`. Se fija solo X; la simulación resuelve
  Y/Z. El eje X cuenta la historia y no puede fallar por ciclos.
- **timeline3d** — `node.fx` proporcional a `firstSeen`.

### El replay

No reconstruye nada: usa `nodeVisibility`/`linkVisibility` contra un cursor
temporal. Los nodos aparecen ya en su posición final y la animación no da bandazos.
Las marcas de tiempo se precalculan a número en `decorate()`: hacer `Date.parse` en
cada frame sería carísimo.

### Detalles de render que importan

- **Curvatura de multiaristas**: dos relaciones distintas entre el mismo par se
  pintan una encima de otra y solo se ve una. Se reparten en abanico con
  `linkCurvature` + `linkCurveRotation`.
- **Partículas**: `linkDirectionalParticles` proporcional al `log10` del `count`.
  El volumen de eventos se ve fluir literalmente por la arista.
- **Grosor y radio logarítmicos**: 500 eventos no pueden ser 500 veces más gruesos,
  y el radio va con `sqrt(risk)` porque lineal taparía media escena.
- **Halos**: los nodos de severidad ≥4 llevan un halo. Es un `Sprite` y no un anillo
  plano porque un anillo visto de canto desaparece; un sprite siempre mira a cámara.
- **Rendimiento**: por encima de 600 nodos bajan `nodeResolution` y `linkResolution`
  y se apagan las partículas. Con muchos nodos solo se etiquetan los de riesgo alto.

---

## Decisiones y por qué

| Decisión | Alternativa descartada | Motivo |
|---|---|---|
| OCSF-lite propio | OCSF completo | ~400 clases para alimentar 13 tipos de nodo |
| Almacén en memoria | Neo4j / Postgres | un analista, un incidente; 100k eventos ≈ 200 MB |
| Filtrar en servidor | Filtrar en cliente | los `count` de las aristas dependen del filtro |
| `fx` fijado por defecto | `dagMode()` | dagMode exige aciclicidad; los incidentes reales tienen ciclos. Con `onDagError(() => false)` es viable, y está disponible en el panel |
| Figuras procedurales | modelos `.glb` descargados | cero assets, licencias claras, se recolorean solas, funcionan sin red. El `.glb` propio se puede subir igualmente |
| Papel calculado en servidor | deducirlo en el navegador | el informe y el grafo tienen que dibujar la misma figura |
| Módulos ES + importmap | React + Vite | el frontend se sirve tal cual; no hay `npm install` ni build |
| Perfil visual en servidor | localStorage por analista | una captura significa lo mismo para quien la envía y para quien la recibe |
| `forceCollide` propio | vendorizar `d3-force-3d` | el bundle UMD no lo expone y era una sola función |
| Narrativa con plantillas | modelo de lenguaje | la misma evidencia debe producir siempre el mismo texto |
| `.env` leído a mano | pydantic-settings | 30 líneas, una dependencia menos, precedencia explícita |

---

## Extender

**Un SIEM nuevo**: clase en `connectors/` que implemente `fetch()`, alta en
`connectors/__init__.py`, y un normalizador en `normalize/` con `register(...)`.

**Un tipo de entidad nuevo**: entrada en `graph/ontology.py` (color, figura, forma,
glifo, rank) y usarla en `graph/extract.py`. El frontend se entera solo por
`/api/ontology`, y el panel de administrador le añade sus controles sin tocar nada.

**Una figura 3D nueva**: un constructor en `web/js/render/models.js` que devuelva
un `THREE.Group` de ~2 unidades de alto, alta en `BUILDERS`, y referenciarla como
`model` en la ontología. Aparece sola en el desplegable del panel.

**Un ajuste nuevo en el panel**: entrada en `SPEC` de `glamdring/appearance.py` con
su tipo y su rango. El control se genera solo, con sus límites, y queda validado en
el servidor por la misma definición. Documentarlo en `docs/APPEARANCE.md`.

**Un formato de informe nuevo**: un renderizador que tome el diccionario de
`report/builder.py` y una entrada en `FORMATS`.

**Una relación nueva**: entrada en `RELATIONS` con su peso, y emitirla desde la
regla de `extract.py` que corresponda.
