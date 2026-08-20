# Referencia de la API

Todos los endpoints cuelgan de `/api`. El frontend se sirve desde la misma
aplicación en `/`, así que no hay CORS que configurar ni orígenes que cruzar.

La documentación interactiva que genera FastAPI está en `/docs`.

---

## Cómo leer esta página

Varios parámetros usan **alias en camelCase** distintos del nombre del campo en
Python (`minSeverity` → `min_severity`, `from` → `time_from`). En la API se usa
siempre el alias; aquí se documenta el alias.

Los filtros de lista (`sources`, `tactics`, `types`, `relations`, `classes`,
`uids`) se pasan **separados por comas** en la cadena de consulta, no repitiendo
el parámetro:

```bash
curl "http://localhost:8000/api/graph?types=user,host&sources=splunk,qradar"
```

**Los filtros se aplican en el servidor**, no en el navegador. Con cien mil
eventos no tiene sentido mandarlo todo al cliente para filtrar allí, y además los
recuentos de las aristas dependen del filtro: una arista que agregaba 400 logons
tiene que decir 12 si la ventana temporal solo deja 12.

### Códigos de error

Los códigos están elegidos para que el analista distinga qué ha pasado sin abrir
la consola:

| Código | Significa |
|---|---|
| `400` | la petición está mal formada: formato desconocido, fichero ilegible, nombre no válido |
| `409` | el estado no permite la operación: no hay eventos cargados, o el conector no tiene credenciales |
| `413` | el contenido es demasiado grande (fichero subido, modelo `.glb`, captura del grafo) |
| `422` | validación de Pydantic: un campo con el tipo equivocado |
| `502` | el fallo es del SIEM o de la consulta, no del servidor |

---

## Metadatos

### `GET /api/health`

Estado del servicio y de la investigación en curso. Es lo primero que pide el
frontend al arrancar para decidir si carga el grafo o enseña el estado vacío.

```json
{
  "status": "ok",
  "events": 52,
  "sources": ["generic", "qradar", "sentinel", "splunk"],
  "span": { "from": "2026-08-19T08:58:12+00:00", "to": "2026-08-19T10:15:00+00:00" },
  "lastIngest": "2026-08-19T12:04:11.882Z",
  "connectors": {
    "splunk":   { "configured": false, "url": "" },
    "sentinel": { "configured": false, "workspace": "" },
    "qradar":   { "configured": false, "url": "" },
    "files":    { "configured": true }
  },
  "limits": { "maxResults": 50000, "maxGraphNodes": 1500 }
}
```

`connectors` dice **si** cada conector está configurado, nunca **con qué**. La URL
sale enmascarada al host y el workspace de Sentinel se recorta. Hay un test que
comprueba que la respuesta no contiene ninguna de las palabras `password`,
`client_secret`, `splunk_token` ni `qradar_token`.

### `GET /api/ontology`

Tipos de entidad, relaciones, papeles, severidad, tácticas, orígenes y modos de
color. El frontend sobrescribe con esto su copia local, de modo que **añadir un
tipo se hace en un solo sitio** (`glamdring/graph/ontology.py`) y la interfaz se
entera sola.

### `GET /api/connectors`

Conectores disponibles, si están configurados, su lenguaje de consulta y una
consulta de ejemplo. El diálogo de "Consultar SIEM" se construye con esto.

```json
{"connectors": [
  {"name": "files", "configured": true, "queryLanguage": "ruta o fichero subido",
   "exampleQuery": "samples/splunk_windows.json"}
]}
```

### `GET /api/samples`

Ficheros de ejemplo disponibles en `samples/`, con su tamaño.

### `GET /api/ingest-log`

Historial de las últimas 50 ingestas: de dónde vino cada una, cuántos eventos
entraron, cuántos se descartaron por duplicados y el total acumulado. Sirve para
responder "¿por qué hay menos eventos de los que subí?".

---

## Ingesta

### `POST /api/ingest`

Multipart. Acepta **una** de estas tres formas:

| Campo | Uso |
|---|---|
| `file` | fichero subido (JSON, NDJSON, CSV, CEF, LEEF, syslog) |
| `text` | contenido pegado directamente |
| `path` | ruta en el disco del servidor |

Campos opcionales: `format_hint` para forzar el formato cuando la detección se
equivoca, y `reset` para vaciar la investigación antes de ingerir.

```bash
curl -F "file=@export.json" http://localhost:8000/api/ingest
```

```json
{"read": 21, "normalized": 21, "unmatched": 0,
 "added": 21, "duplicates": 0, "dropped": 0, "total": 21,
 "format": "json", "origin": "upload:export.json"}
```

`unmatched` son los registros que **ningún normalizador supo interpretar**.
Debería ser 0; si sube, hace falta un normalizador nuevo.

`path` está desactivado por defecto (`GLAMDRING_ALLOW_FILE_PATHS=0`): un endpoint
que lee rutas arbitrarias del disco es una lectura de ficheros locales servida en
bandeja. Los ficheros de `samples/` se leen siempre.

### `POST /api/demo`

Carga todos los ficheros de `samples/`. Es la puerta de entrada de la herramienta:
sin esto habría que tener un SIEM delante para ver si funciona.

```bash
curl -X POST http://localhost:8000/api/demo
```

Devuelve un desglose por fichero y los totales. Vacía la investigación antes,
salvo que se pase `reset=false`.

### `POST /api/query`

Consulta en vivo contra un SIEM. Cuerpo JSON:

```json
{
  "connector": "splunk",
  "query": "index=wineventlog EventCode IN (4624,4625,4688)",
  "from": "-24h",
  "to": null,
  "limit": 10000,
  "reset": false
}
```

`from` y `to` aceptan ISO-8601 o **atajos relativos** (`-24h`, `-7d`, `-30m`),
que es como piensa el analista y no en marcas de tiempo absolutas.

Devuelve `409` si el conector no tiene credenciales y `502` si el SIEM falla o
rechaza la consulta. El resultado se **fusiona** con lo que ya hay: se pueden
encadenar consultas a varios SIEM y el grafo las une.

### `POST /api/reset`

Vacía la investigación en curso.

---

## Grafo

### `GET /api/graph`

El endpoint principal. Devuelve un [`GraphDoc`](#el-contrato-graphdoc) con todos
los filtros aplicados.

| Parámetro | Tipo | Qué hace |
|---|---|---|
| `from`, `to` | ISO-8601 o relativo | ventana temporal |
| `minSeverity` | 0-5 | severidad mínima del evento |
| `sources` | lista | `splunk,sentinel,qradar,generic` |
| `tactics` | lista | slugs MITRE (`lateral-movement`, …) |
| `classes` | lista | clases OCSF (`Authentication`, `Process Activity`, …) |
| `q` | texto | búsqueda libre sobre eventos, incluido el log crudo |
| `types` | lista | tipos de entidad a conservar |
| `relations` | lista | tipos de relación a conservar |
| `focus` | id de nodo | pivotar sobre un nodo |
| `hops` | 1-5 | saltos alrededor del foco |
| `maxNodes` | entero | tope; por defecto `GLAMDRING_MAX_GRAPH_NODES` |

Los cinco primeros filtran **eventos** y provocan que el grafo se reconstruya. Los
demás son podas **topológicas** sobre el grafo ya montado y no alteran los
recuentos. La distinción importa: filtrar por tiempo y dejar los `count` al total
sería mentir.

```bash
curl "http://localhost:8000/api/graph?minSeverity=4&types=user,host&from=-24h"
```

Cuando el grafo supera `maxNodes` se conservan los de **mayor riesgo**, se marca
`meta.truncated` y se añade una nota en `meta.notes`. La interfaz lo avisa en la
barra de estado: un recorte silencioso se lee como "esto es todo lo que hay".

### `GET /api/graph/neighbors`

Vecindad de N saltos desde un nodo. Es el "expandir" del menú contextual y del
doble clic.

```bash
curl "http://localhost:8000/api/graph/neighbors?node=host:wks-0421&hops=1"
```

Devuelve `404` si el nodo no existe en la investigación.

### `GET /api/timeline`

Histograma de eventos para el slider y el replay.

| Parámetro | Por defecto | Qué hace |
|---|---|---|
| `buckets` | 120 (10-1000) | número de barras |
| `minSeverity` | 0 | severidad mínima |
| `sources` | — | filtro de origen |
| `q` | — | búsqueda libre |

```json
{"bucketSeconds": 30,
 "buckets": [{"t": "2026-08-19T08:58:12+00:00", "count": 1, "maxSeverity": 2}]}
```

### `GET /api/events`

**Los logs crudos.** Es la ruta que hace la herramienta defendible: todo lo que se
ve en el grafo se puede contrastar con el registro original del SIEM.

| Parámetro | Qué hace |
|---|---|
| `uids` | lista de identificadores de evento (los que trae cada arista en `eventUids`) |
| `node` | id de nodo del que se quieren sus eventos |
| `limit` | 1-2000, por defecto 200 |

```bash
curl "http://localhost:8000/api/events?node=host:wks-0421&limit=5"
```

Cada evento devuelto lleva su `raw` completo, con los campos sensibles tachados.

### `GET /api/export`

El grafo **sin recortar**, para adjuntar a un informe o volver a importarlo.
Acepta `from`, `to` y `minSeverity`.

---

## Aspecto

### `GET /api/appearance`

Devuelve tres cosas: el perfil efectivo, los valores de fábrica y el **`spec`** con
el tipo y el rango de cada control.

El `spec` viaja con el perfil para que el panel construya sus sliders con los
rangos reales del servidor, en lugar de duplicarlos en el JavaScript y que se
desincronicen a la primera.

```json
{"appearance": {...}, "defaults": {...},
 "spec": {"sections": {"render": {"bloomStrength": ["number", 0.0, 4.0]}}},
 "colorModes": [{"id": "type", "label": "Tipo de entidad"}]}
```

### `PUT /api/appearance`

Aplica un parche y lo persiste. El cuerpo es un objeto con las secciones a
cambiar; solo hace falta mandar lo que cambia.

```bash
curl -X PUT http://localhost:8000/api/appearance \
     -H "Content-Type: application/json" \
     -d '{"theme": {"accent": "#ff8800"}, "render": {"bloom": false}}'
```

```json
{"appearance": {...}, "rejected": ["render.inventado"]}
```

Se informa de lo descartado **en lugar de fallar entero**: si el panel manda diez
ajustes y uno está mal, es mejor aplicar nueve y decir cuál no que perder los diez.
Lo desconocido se descarta, lo fuera de rango se recorta y lo que no es del tipo
esperado se ignora.

### `POST /api/appearance/reset`

Vuelve a fábrica **borrando el fichero**, no escribiendo los valores por defecto.
Así, si una versión futura cambia esos valores, el equipo se beneficia sin tener
que volver a pulsar el botón.

### `POST /api/appearance/model/{name}`

Sube un `.glb` que sustituye a una figura procedural. Multipart, campo `file`.

Se comprueba la **cabecera** del fichero (`glTF`) y no solo la extensión: lo que se
sube acaba sirviéndose como estático al navegador de todo el equipo. Máximo 25 MB.
El nombre debe encajar en `[A-Za-z0-9._-]{1,64}`.

### `DELETE /api/appearance/model/{name}`

Quita el `.glb` y devuelve la figura procedural a su sitio.

---

## Informes

### `POST /api/report`

Genera el informe del incidente. Cuerpo JSON:

| Campo | Qué hace |
|---|---|
| `format` | `html` · `markdown` · `json` · `stix` · `iocs` |
| `title` | opcional; si se omite se genera a partir de las víctimas |
| `analyst` | opcional, para la cabecera |
| `image` | data-URL con la captura del grafo (solo tiene sentido en HTML) |
| `download` | si `true`, añade `Content-Disposition: attachment` |
| `from`, `to`, `minSeverity`, `sources`, `tactics`, `types`, `q` | los mismos filtros del grafo |

```bash
curl -X POST http://localhost:8000/api/report \
     -H "Content-Type: application/json" \
     -d '{"format": "markdown", "download": false}' -o informe.md
```

La respuesta **no es JSON**: es el documento, con el `Content-Type` que
corresponda. `409` si no hay eventos o si los filtros no dejan ninguno; `400` si el
formato es desconocido o la captura no es un data-URL de imagen válido.

El grafo y la lista de eventos se construyen con los **mismos** filtros, para que
la cronología y la tabla de entidades hablen del mismo subconjunto. Con filtros
distintos el informe se contradiría a sí mismo.

### `GET /api/report/preview`

La estructura del informe **sin renderizar**, para la vista previa del diálogo.
Acepta `from`, `to` y `minSeverity`.

### `GET /api/iocs`

Indicadores extraídos del grafo actual.

| Parámetro | Qué hace |
|---|---|
| `minSeverity` | 0-5 |
| `flat` | si `true`, texto plano en vez de JSON |

```bash
curl "http://localhost:8000/api/iocs?flat=true"
```

Nunca incluye direcciones RFC1918: una lista de bloqueo perimetral con la propia
red dentro es, en el mejor de los casos, inútil.

---

## El contrato `GraphDoc`

Es **lo único** que consume el frontend. Da igual si viene de Splunk en vivo, de un
CEF pegado a mano o de un fixture de test.

```jsonc
{
  "meta": {
    "generated": "2026-08-19T12:04:11Z",
    "window": { "from": null, "to": null },
    "counts": { "events": 52, "nodes": 38, "links": 74, "clusters": 2, "levels": 6 },
    "sources": ["splunk", "sentinel", "qradar", "generic"],
    "truncated": false,
    "notes": []
  },
  "nodes": [{
    "id": "host:wks-0421",          // clave canónica "<tipo>:<valor normalizado>"
    "type": "host",
    "label": "wks-0421",
    "firstSeen": "2026-08-19T08:58:12+00:00",
    "lastSeen":  "2026-08-19T09:52:44+00:00",
    "eventCount": 24,
    "maxSeverity": 5,
    "risk": 96,
    "degree": 11,
    "sources": ["splunk", "sentinel"],
    "tactics": ["execution", "lateral-movement"],
    "props": {
      "ip": "10.4.2.11",
      "role": "victim",             // lo calcula enrich.py
      "model": "workstation",       // la figura 3D que le toca
      "deviceClass": "workstation",
      "cluster": 0,
      "level": 3,                   // capa en la vista kill-chain
      "external": false,
      "eventUids": ["a1b2c3d4e5f60718"]
    }
  }],
  "links": [{
    "id": "l17",
    "source": "user:jlopez",
    "target": "host:wks-0421",
    "type": "authenticated",
    "count": 12,
    "severity": 3,
    "firstSeen": "...",
    "lastSeen": "...",
    "eventUids": ["...", "..."],    // -> GET /api/events?uids=...
    "sources": ["splunk"],
    "props": { "logon_type": "red" }
  }]
}
```

`id`, `source` y `target` llevan esos nombres exactos porque son los que
`3d-force-graph` espera por defecto: cero accesores que reconfigurar.

`eventUids` se recorta a 200 por nodo y por arista para que el JSON no explote; el
recuento real sigue en `count`.

---

Relacionadas: [[Architecture]] · [[Connectors]] · [[Extending]]
