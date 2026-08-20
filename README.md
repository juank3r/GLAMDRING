# GLAMDRING

**Convierte los logs planos de tu SIEM en un grafo 3D navegable del incidente.**

Splunk, Sentinel y QRadar te dan tablas de texto. Durante un incidente el analista
tiene que reconstruir mentalmente *quién tocó qué, desde dónde y en qué orden*
saltando entre búsquedas SPL, KQL y AQL. Esa reconstrucción es el cuello de botella
real del triaje, y además es imposible de comunicar a nadie más.

GLAMDRING pone una capa de lectura encima: entidades (usuario, host, proceso, IP,
fichero, alerta) como nodos, acciones (autentica, lanza, conecta, escribe, dispara)
como aristas dirigidas, y el tiempo como dimensión de primera clase.

**El SIEM sigue siendo la fuente de verdad; GLAMDRING es el mapa.** Cualquier nodo
o arista se abre y muestra el log literal que lo generó.

---

## Arranque rápido

```powershell
# Requiere Python 3.11+
cd GLAMDRING
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

uvicorn glamdring.main:app --reload --port 8000
```

Abre <http://localhost:8000> y pulsa **Demo**. No hace falta ningún SIEM ni ninguna
credencial: los ficheros de `samples/` traen un incidente completo repartido entre
los cuatro formatos soportados.

En Linux/macOS el entorno se activa con `source .venv/bin/activate`.

**No hace falta Node ni `npm install`**: el frontend son módulos ES servidos tal
cual, con las librerías vendorizadas en `web/js/vendor/`. Si alguna vez hay que
volver a bajarlas: `python tools/fetch_vendor.py`.

---

## Qué hace

### Normaliza cuatro fuentes a un modelo común

| Fuente | Qué entiende |
|---|---|
| **Splunk** | `WinEventLog:Security` (4624, 4625, 4648, 4688, 4720), Sysmon (1, 3, 11, 22), sourcetypes de firewall/proxy/DNS y campos CIM |
| **Sentinel / Defender** | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `SigninLogs`, `EmailEvents`, `SecurityAlert`, `SecurityIncident` |
| **QRadar** | Resultados Ariel (`starttime`, `sourceip`, `magnitude`, `categoryname`…) y ofensas |
| **CEF / LEEF / syslog** | CEF 0.x, LEEF 1.0 y 2.0, syslog RFC5424 y RFC3164, y JSON arbitrario como red de seguridad |

El destino común es un subconjunto pragmático de [OCSF](https://schema.ocsf.io/),
el esquema vendor-neutral impulsado por AWS y Splunk.

### Deduplica de verdad

La pieza más importante y la menos vistosa. Sin ella, la misma cosa aparecería
varias veces y el grafo mentiría:

- `CORP\jlopez` (Splunk), `jlopez@corp.com` (Sentinel) y `jlopez` (QRadar) → **un** usuario.
- `SRV-DC01` y `10.4.1.5` → **una** máquina, fundiendo la IP en el host que la declara.
- `m.exe` (nombrado en una alerta) y `C:\Windows\Temp\m.exe` (visto por Sysmon) →
  **un** fichero, unidos por su hash.
- `explorer.exe` con ruta y sin ruta, en el mismo host → **un** proceso.

Y lo que **no** debe ser un nodo tampoco lo es: las cuentas de máquina (`WKS-0421$`),
las de servicio de Windows, los nombres de producto que QRadar mete en
`logsourcename` (`TrendMicro-AV` no es una máquina del parque) y las aplicaciones
cloud, que son servicios y no equipos.

### Figuras que se reconocen de un vistazo

Los nodos no son bolitas. Cada entidad se dibuja con una figura construida con
primitivas de three: un servidor es un rack con pilotos, un puesto de trabajo es un
monitor cuya pantalla se pone roja si está comprometido, un cortafuegos es un muro,
un usuario es una figura con un aro azul… y **el atacante es una figura encapuchada**.

La figura no depende solo del tipo sino del **papel** que juega en el incidente, que
el backend calcula a partir de la IP (pública o RFC1918), las tácticas MITRE
presentes y la cercanía a las alertas:

| Papel | Qué significa |
|---|---|
| **Hostil** | infraestructura del atacante |
| **Víctima** | entidad propia con impacto confirmado |
| **Sospechosa** | entidad propia con indicios sin confirmar |
| **Activo sano** | entidad propia sin hallazgos |
| **Contexto** | artefacto forense de apoyo |

Así, el mismo `host` sale como rack sano o como puesto con la alarma encendida, y
una IP externa con tráfico de mando y control se reconoce desde el otro extremo de
la escena sin leer una sola etiqueta. Se puede sustituir cualquier figura por un
`.glb` propio desde el panel de administrador.

### Cuatro vistas del mismo grafo

- **Explorar** — force-directed libre. Los clústeres emergen solos; se arrastra, se
  gira y se pivota. Las partículas que recorren las aristas son el volumen de
  eventos: el tráfico se ve fluir.
- **Kill-chain** — el eje X pasa a ser la táctica MITRE, de acceso inicial a impacto.
  La historia del ataque se lee de izquierda a derecha, con la táctica dominante
  rotulada sobre cada capa.
- **Cronología** — el eje X es el tiempo del primer avistamiento.
- **Replay** — ▶ en la barra inferior: los nodos y aristas aparecen según ocurrieron,
  sin que el layout se mueva, y cada arista suelta un destello en su momento exacto.

### Siete formas de colorear el mismo grafo

El grafo es el mismo; lo que cambia es qué dimensión se lleva el color, porque
"¿qué tipo de cosa es esto?" y "¿quién es el atacante?" son preguntas distintas:
**tipo de entidad · papel · severidad · riesgo · origen del dato · táctica MITRE ·
comunidad**. Se cambia desde la barra superior o con `c`.

### Interacción de verdad

Hover que resalta la vecindad, clic que enfoca la cámara, ctrl+clic para comparar
varias entidades, doble clic para traer vecinos nuevos del servidor sin perder lo
que ya tenías colocado, clic derecho con menú contextual (pivotar, ocultar, fijar,
copiar como IOC, buscar), arrastrar para anclar, y atajos de teclado con ayuda en `?`.

### Panel de administrador

Un panel con diez pestañas donde el sysadmin ajusta casi todo: tema y paleta,
calidad de figuras, bloom, niebla, rejilla, física de la simulación, etiquetas,
aristas, cámara, colores y figura de cada tipo de entidad, y los pesos del cálculo
de riesgo.

**Los controles no están escritos a mano**: se generan a partir del `spec` que manda
el servidor, con el rango real de cada campo, así que añadir un ajuste es tocar
`appearance.py` y aparece solo. La configuración vive en `config/appearance.json`
**en el servidor**: un único perfil para todo el equipo.

Detalle completo en [docs/APPEARANCE.md](docs/APPEARANCE.md).

### Informes automáticos

Botón **Informe** o `r`. Se genera de forma determinista a partir del grafo, sin
modelo de lenguaje: la misma evidencia produce siempre el mismo texto y cada línea
se puede rastrear hasta su log.

Incluye resumen ejecutivo, **cronología narrada en español**
(*«09:15 — jlopez ejecutó powershell.exe en WKS-0421 con la línea de comandos
ofuscada»*), cadena de ataque MITRE con evidencias, tabla de entidades por riesgo,
indicadores de compromiso y acciones de contención recomendadas.

Cuatro formatos: **HTML autocontenido** (con la captura del grafo incrustada,
imprimible a PDF con Ctrl+P), **Markdown** (para Jira, TheHive o el wiki),
**JSON/STIX-lite** y **lista plana de IOCs** lista para pegar en un firewall.

La lista de IOCs nunca incluye direcciones RFC1918: una lista de bloqueo perimetral
con la propia red dentro es, en el mejor de los casos, inútil.

### Trazabilidad total

Pincha un nodo o una arista y el inspector te da sus métricas, su papel, sus tácticas
MITRE, sus vecinos… y los **logs originales del SIEM**, tal cual llegaron. Un grafo
bonito del que no se puede volver al log crudo no sirve para un informe.

---

## Consultar el SIEM en vivo

Copia `.env.example` a `.env` y rellena solo el SIEM que uses. Luego, botón **SIEM**:

| Conector | Autenticación | Ejemplo |
|---|---|---|
| Splunk | token de servicio (`Authorization: Splunk <token>`) | `index=wineventlog EventCode IN (4624,4625,4688)` |
| Sentinel | Service Principal con *Log Analytics Reader* | `DeviceProcessEvents \| where Timestamp > ago(24h)` |
| QRadar | token en la cabecera `SEC` | `SELECT * FROM events LAST 24 HOURS LIMIT 5000` |

Las ventanas temporales aceptan ISO-8601 o atajos relativos: `-24h`, `-7d`, `-30m`.
Detalles de permisos y flujos en [docs/CONNECTORS.md](docs/CONNECTORS.md).

---

## Arquitectura

```
CONNECTORS  →  NORMALIZE  →  EXTRACT/BUILD  →  ENRICH  →  QUERY/API  →  RENDER
SPL/KQL/AQL    OCSF-lite     grafo tipado     roles     filtros      three.js
```

Seis etapas desacopladas con contratos explícitos. El frontend solo conoce
`GraphDoc` (JSON), así que da igual si viene de Splunk en vivo, de un CEF pegado a
mano o de un fixture de test.

Diseño completo en [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); entidades y
relaciones en [docs/ONTOLOGY.md](docs/ONTOLOGY.md).

---

## Sin build de JavaScript

El frontend son módulos ES con un `importmap`, servidos por el propio FastAPI. Sin
`npm install`, sin empaquetador, sin paso de compilación.

| Librería | Versión | Por qué esa |
|---|---|---|
| `three.module.js` | **r168** | la MISMA revisión que empaqueta `3d-force-graph` |
| `3d-force-graph.min.js` | 1.73.4 | UMD autocontenido; expone `window.ForceGraph3D` |
| `three-spritetext.mjs` | 1.9.0 | importa `three` como especificador desnudo |
| `jsm/` | r168 | `CSS2DRenderer`, `UnrealBloomPass`, `OutlinePass`, `GLTFLoader` |

**La coincidencia de revisión no es un detalle.** Hay dos copias de three en la
página (la nuestra y la interna del bundle). Con la misma revisión conviven sin
problema, porque three identifica objetos por flags (`.isObject3D`) y no por
`instanceof`. Con revisiones distintas el post-procesado revienta con errores de
shader que no dicen nada. Hay un test que lo comprueba
(`tests/test_web.py::test_three_revisions_match`).

Los iconos de calidad baja se dibujan con `CanvasTexture`: cero ficheros de assets,
nítidos a cualquier zoom, y funcionan en un portátil sin red.

---

## Tests

```powershell
pip install -r requirements-dev.txt
pytest -q
```

Ninguno necesita red ni credenciales: todo corre contra `samples/`. Además de la
lógica, se comprueba la integridad del frontend (que todo import y todo asset
resuelva, que los `id` que busca el JavaScript existan en el HTML, y que las dos
copias de three coincidan).

---

## Seguridad

- Los secretos solo viajan por variables de entorno. `.env` está en `.gitignore`.
- `/api/health` informa de qué conectores hay configurados, **nunca con qué**.
- Los campos tipo `password`, `token`, `api_key` o `authorization` se tachan del log
  crudo antes de guardarlo: el inspector enseña el registro entero, y los logs de
  autenticación a veces arrastran credenciales.
- Todo lo que entra al perfil visual se sanea clave a clave contra un `spec`: lo
  desconocido se descarta y lo fuera de rango se recorta.
- Los `.glb` que se suben se validan por la **cabecera** del fichero, no por la
  extensión: acaban sirviéndose como estáticos al navegador de todo el equipo.
- La lectura de rutas del disco del servidor está desactivada por defecto
  (`GLAMDRING_ALLOW_FILE_PATHS=0`).
- No hay autenticación de usuarios. Pensado para correr en local o detrás de un
  proxy que la ponga.

---

## Límites conocidos

- **Un proceso, una investigación.** El almacén es en memoria
  (`glamdring/store.py`). Es lo correcto para un analista triando en su portátil;
  para multiusuario hay que sustituir esa clase por un backend con clave de sesión
  — y nada más, porque nadie fuera de ella toca los eventos.
- Por encima de ~350 nodos la calidad de las figuras baja sola, y por encima de
  ~1.500 el backend recorta a los de mayor riesgo y lo avisa en la barra de estado.
- El scoring de riesgo y la deducción del papel son heurísticas de priorización, no
  veredictos.
- La clase de equipo (puesto / servidor / router / cortafuegos) se deduce del
  hostname. Acierta en un parque con nomenclatura corporativa; en uno sin ella, hay
  que corregirla desde el panel.
- Las consultas a Splunk usan modo export; para búsquedas de horas haría falta
  pasar a modo job con polling.
- **STIX-lite no es STIX 2.1.** Los objetos tienen la forma correcta y sirven para
  alimentar un TIP, pero no es un bundle completo ni pretende serlo.
