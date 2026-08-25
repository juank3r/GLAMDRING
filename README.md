# GLAMDRING

<div align="center">

![GLAMDRING: el incidente de la demo, con las entidades como figuras y las acciones como aristas dirigidas](docs/glamdring.png)

</div>

**Convierte los logs planos de tu SIEM en un grafo 3D navegable del incidente.**
Entidades (usuario, host, proceso, IP, fichero, alerta) como nodos, acciones
(autentica, lanza, conecta, escribe, dispara) como aristas dirigidas y el tiempo como
eje. El SIEM sigue siendo la fuente de verdad: cada nodo y cada arista abren el log
literal que los generó.

---

## Arranque rápido

Requisito: **Python 3.11+**.

```powershell
cd GLAMDRING
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File tools\run.ps1
```

- Abre <http://localhost:8000> y pulsa **Demo** (52 eventos, 38 entidades) o
  **Demo mínima** (6 eventos, 10 nodos, 16 aristas) para ver la forma del grafo sin
  nada encima.
- Sin SIEM y sin credenciales: `samples/` trae el incidente repartido entre los
  cuatro formatos de ingesta soportados.
- `tools\run.ps1` (51 líneas) cierra lo que hubiera y arranca **siempre en :8000**.
  Acepta `-Port 8080` y `-Reload` (la recarga levanta un proceso más, el vigilante,
  por eso se pide a propósito y no viene puesta).
- Servidores vivos de sesiones anteriores:
  `powershell -ExecutionPolicy Bypass -File tools\stop_servers.ps1`. Busca por línea
  de comandos y no solo por puerto, para cazar también al vigilante de `--reload`.
  Acepta `-Keep 8000` y `-WhatIf`.
- Linux/macOS: `source .venv/bin/activate` y `uvicorn glamdring.main:app --port 8000`.
  `run.ps1` es solo para PowerShell.
- **Sin Node y sin `npm install`**: el frontend son módulos ES servidos tal cual, con
  las librerías vendorizadas en `web/js/vendor/`. Para volver a bajarlas:
  `python tools/fetch_vendor.py`.

---

## Qué hace

### Normaliza cuatro formatos a un modelo común

| Fuente | Qué entiende |
|---|---|
| **Splunk** | `WinEventLog:Security` (4624, 4625, 4648, 4688, 4720), Sysmon (1, 3, 11, 22), sourcetypes de firewall/proxy/DNS y campos CIM |
| **Sentinel / Defender** | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `SigninLogs`, `EmailEvents`, `SecurityAlert`, `SecurityIncident` |
| **QRadar** | Resultados Ariel (`starttime`, `sourceip`, `magnitude`, `categoryname`…) y ofensas |
| **CEF / LEEF / syslog** | CEF 0.x, LEEF 1.0 y 2.0, syslog RFC5424 y RFC3164, y JSON arbitrario como red de seguridad |

- El destino común es un subconjunto pragmático de [OCSF](https://schema.ocsf.io/),
  el esquema vendor-neutral impulsado por AWS y Splunk.
- De los cuatro, solo tres tienen conector en vivo (`glamdring/connectors/`: splunk,
  sentinel, qradar). CEF/LEEF/syslog entra por fichero, con `files`.

### Deduplica de verdad

La pieza más importante y la menos vistosa. Sin ella, la misma cosa aparecería
varias veces y el grafo mentiría:

- `CORP\jlopez` (Splunk), `jlopez@corp.com` (Sentinel) y `jlopez` (QRadar) → **un** usuario.
- `SRV-DC01` y `10.4.1.5` → **una** máquina, fundiendo la IP en el host que la declara.
- `m.exe` (nombrado en una alerta) y `C:\Windows\Temp\m.exe` (visto por Sysmon) →
  **un** fichero, unidos por su hash.
- `explorer.exe` con ruta y sin ruta, en el mismo host → **un** proceso.

Y lo que **no** debe ser un nodo tampoco lo es:

- Las cuentas de máquina (`WKS-0421$`) y las de servicio de Windows.
- Los nombres de producto que QRadar mete en `logsourcename`: `TrendMicro-AV` no es
  una máquina del parque.
- Las aplicaciones cloud, que son servicios y no equipos.

### Figuras que se reconocen de un vistazo

| Entidad | Figura |
|---|---|
| Servidor | rack con pilotos |
| Puesto de trabajo | monitor cuya pantalla se pone roja si está comprometido |
| Cortafuegos | muro |
| Usuario | figura con un aro azul |
| Atacante | figura encapuchada |

La figura no depende solo del tipo sino del **papel** en el incidente, que el backend
deduce de la IP (pública o RFC1918), las tácticas MITRE presentes y la cercanía a las
alertas:

| Papel | Qué significa |
|---|---|
| **Hostil** | infraestructura del atacante |
| **Víctima** | entidad propia con impacto confirmado |
| **Sospechosa** | entidad propia con indicios sin confirmar |
| **Activo sano** | entidad propia sin hallazgos |
| **Contexto** | artefacto forense de apoyo |

Cómo se consigue que se vean bien:

- La cámara arranca en `orbit` y no en `trackball` (`appearance.py:137`): trackball no
  fija el eje vertical y arrastrando se puede rodar el mundo hasta ver a una persona
  boca abajo.
- `web/js/render/orient.js` (115 líneas) gira cada fotograma las figuras que tienen
  frente. Tres modos: `fixed`, `yaw` (por defecto, conserva la vertical) y `billboard`.
- Solo giran las **10** figuras declaradas en `ontology.FACING_MODELS` y servidas por
  `/api/ontology`: workstation, server, router, firewall, person, attacker, envelope,
  alert, document, key. Las simétricas (globe, cloud, hashcube, gear, endpoint) y los
  `.glb` subidos no se giran.
- Se gira la figura, no el grupo del nodo, para que la etiqueta no orbite.
- Cualquier figura se sustituye por un `.glb` propio desde el panel de administrador.

### Cuatro vistas del mismo grafo

- **Explorar** (`1`) — force-directed libre. Las partículas que recorren las aristas
  son el volumen de eventos: el tráfico se ve fluir.
- **Kill-chain** (`2`) — el eje X pasa a ser la táctica MITRE, de acceso inicial a
  impacto, con la táctica dominante rotulada sobre cada capa.
- **Cronología** (`3`) — el eje X es el tiempo del primer avistamiento.
- **Replay** (`espacio`) — nodos y aristas aparecen según ocurrieron, sin que el
  layout se mueva, y cada arista suelta un destello en su momento exacto.

### Seguir a una entidad: el incidente contado paso a paso

- Tecla `s` o menú contextual «Seguir a esta entidad» (`web/js/ui/follow.js`, 279 líneas).
- La pantalla se queda **solo con la vecindad de esa entidad**: en la demo, de 38
  nodos a 18. Lo que sobra desaparece, no se atenúa.
- La cámara vuela de acto en acto. Barra con progreso, paso anterior/siguiente,
  reproducir/pausar y velocidad (lento, normal, rápido).
- **Revelado progresivo**: en cada paso aparece lo que acaba de ocurrir y nada de lo
  que viene después. Medido sobre `jlopez`: 2 nodos visibles en el paso 1, 10 en el
  15, los 18 en el 30. Reutiliza el cursor temporal del Replay.
- Las frases **no se redactan en el front**: vienen de `report.narrative`, el mismo
  motor que escribe la cronología de los informes, así que el recorrido en pantalla y
  el informe dicen literalmente lo mismo.
- Cada paso trae la arista por la que ocurrió, con quién fue, si la entidad actuó o se
  lo hicieron, y los uids para abrir el log original.
- Al salir se restauran grafo, cámara y selección.

El motor es `GET /api/graph/story?node=<id>` (`glamdring/graph/story.py`, 122 líneas):

- Devuelve en **una sola llamada** los actos en orden y el subgrafo aislado a la
  vecindad. Van juntos a propósito: pedirlos por separado abriría la puerta a que no
  cuadren.
- Colapsa repeticiones consecutivas por la misma arista: catorce fallos de login
  idénticos son un hecho, no catorce paradas de cámara.
- Tope de **120 pasos** (`story.MAX_STEPS`). Si trunca, recorta por gravedad pero
  devuelve en orden temporal.
- Sobre la demo, `jlopez` da 30 pasos y aísla 18 de los 38 nodos. Cubierto por
  `tests/test_story.py`.

### Modo automático

- Botón **Auto** o tecla `t` (`web/js/ui/auto.js`, 186 líneas).
- Recorre las entidades del incidente una tras otra y al terminar vuelve a empezar.
  Pensado para dejarlo en una pantalla del SOC y para explicar un caso sin conducir.
- El orden lo pone `construirCola()`: por la hora de **primera aparición**, no por
  riesgo. Ir por riesgo enseñaría el desenlace antes que el principio.
- Salta el contexto forense de apoyo y las entidades con menos de dos acciones.
- Se para en cuanto alguien toca el lienzo.

### Siete formas de colorear el mismo grafo

- El color se asigna por una de estas siete dimensiones: **tipo de entidad**,
  **papel**, **severidad**, **riesgo**, **origen del dato**, **táctica MITRE** y
  **comunidad**.
- Se cambia desde la barra superior o con `c`.

### Interacción

| Gesto | Resultado |
|---|---|
| hover | resalta la vecindad |
| clic | selecciona y enfoca la cámara |
| ctrl + clic | añade a la selección múltiple, para comparar entidades |
| doble clic | trae vecinos nuevos del servidor sin mover lo ya colocado |
| clic derecho | menú contextual: pivotar, ocultar, fijar, copiar como IOC, buscar, seguir |
| arrastrar un nodo | lo ancla en su sitio |
| `s` · `t` | seguir a la entidad seleccionada · recorrido automático en bucle |
| `espacio` · `f` | reproducir/pausar la cronología · encuadrar todo el grafo |
| `c` · `/` | cambiar el modo de color · ir al buscador |
| `a` · `r` · `?` | panel de administrador · informe · ayuda de atajos |

El inspector de un nodo o una arista da sus métricas, su papel, sus tácticas MITRE,
sus vecinos y los **logs originales del SIEM**, tal cual llegaron.

### Panel de administrador

Diez pestañas (`web/js/ui/admin.js`):

- Siete de aspecto y comportamiento: **Tema, Render, Física, Etiquetas, Aristas,
  Cámara, Interacción** (paleta, calidad de figuras, bloom, niebla, rejilla…).
- **Ontología**: color, figura y visibilidad de cada tipo de entidad, con subida de
  `.glb` propios.
- **Reglas**: los pesos de la puntuación de riesgo, que deciden el orden en que el
  analista mira las cosas y el tamaño de cada figura.
- **Perfil**: importar, exportar y restablecer de fábrica.
- Los controles **no están escritos a mano**: se generan del `spec` que manda el
  servidor con el rango real de cada campo, así que añadir un ajuste es tocar
  `glamdring/appearance.py`.
- La configuración vive en `config/appearance.json` **en el servidor**: un único
  perfil para todo el equipo. Detalle en [docs/APPEARANCE.md](docs/APPEARANCE.md).

### Informes automáticos

Botón **Informe** o `r`.

- **Determinista y sin modelo de lenguaje: la misma evidencia produce siempre el mismo
  texto**, y cada línea se puede rastrear hasta su log.
- Contiene: resumen ejecutivo; cronología narrada en español (*«09:15 — jlopez ejecutó
  powershell.exe en WKS-0421 con la línea de comandos ofuscada»*); cadena de ataque
  MITRE con evidencias; tabla de entidades por riesgo; indicadores de compromiso;
  acciones de contención recomendadas.
- Cinco formatos: **HTML autocontenido** (con la captura del grafo incrustada,
  imprimible a PDF con Ctrl+P), **Markdown** (para Jira, TheHive o el wiki),
  **JSON completo**, **STIX-lite** (indicadores para un TIP) y **lista plana de IOCs**
  lista para pegar en un firewall.
- La lista de IOCs nunca incluye direcciones RFC1918: una lista de bloqueo perimetral
  con la propia red dentro es, en el mejor de los casos, inútil.

### Detección de ransomware y atribución

Catálogo incorporado: **305 herramientas** de intrusión clasificadas por categoría y
grupo, **17 perfiles de grupo** y **299 notas de rescate** reales. Con eso mira cada
línea de comandos por tres vías:

| Vía | Qué busca | Ejemplo |
|---|---|---|
| Herramienta | binarios del repertorio conocido, con su categoría | `rclone.exe` → exfiltración |
| Comportamiento | 13 firmas sobre la línea de comandos, independientes del nombre del fichero | `vssadmin delete shadows` |
| Nota de rescate | el nombre de fichero característico de cada familia | `akira_readme.txt` |

- Sobre los hallazgos calcula qué **etapas del despliegue** se han alcanzado (de
  «acceso inicial» a «cifrado») y propone una **atribución ponderada**.
- **La atribución es una hipótesis de trabajo, nunca un veredicto**: estas herramientas
  las usan muchos grupos y también los administradores legítimos. El aviso va impreso
  en todos los informes.

```powershell
# Un incidente de ejemplo por cada grupo (17 ficheros en samples/apt/)
python tools/make_apt_samples.py
curl http://localhost:8000/api/threat
```

### Rendimiento

- **Cache del grafo construido.** `build_graph()` solo depende de los filtros de
  evento (ventana, severidad, fuente, táctica, clase, texto); los de tipo de entidad,
  tipo de relación, foco, saltos y tope actúan sobre el grafo ya construido, son
  baratos y son los que más se tocan en la interfaz.
- Se cachea por clave (versión del almacén + filtros de evento), LRU de **6 entradas**
  (`_CACHE_MAX`, `glamdring/graph/query.py`). `EventStore` lleva contador de versión
  que solo sube cuando entra algo de verdad: una reingesta de puros duplicados no
  invalida la cache. Cubierto por `tests/test_cache.py`.
- Medido: `/api/graph` de **9,5 s a 0,11 s**, un chip de filtro a **0,07 s**,
  `/api/graph/story` a **0,03 s**.
- **El resaltado ya no reconstruye la escena.** `refresh()` de 3d-force-graph no
  repinta: tira todos los objetos 3D y vuelve a llamar a `nodeThreeObject` por nodo
  (138 ms de hilo bloqueado con 228 nodos y 692 aristas, y se llamaba al pasar el
  ratón, al seleccionar, al deseleccionar y en cada fotograma del replay).
- Ahora los materiales se clonan una vez por nodo (`userData.gdMaterials`) y las
  etiquetas se crean perezosamente: resaltar **de 138 ms a 0,43 ms**, y el peor
  fotograma del replay **de 253 ms a 38 ms**.

---

## Consultar el SIEM en vivo

Copia `.env.example` a `.env` y rellena solo el SIEM que uses. Luego, botón **SIEM**:

| Conector | Autenticación | Ejemplo |
|---|---|---|
| Splunk | token de servicio (`Authorization: Splunk <token>`) | `index=wineventlog EventCode IN (4624,4625,4688)` |
| Sentinel | Service Principal con *Log Analytics Reader* | `DeviceProcessEvents \| where Timestamp > ago(24h)` |
| QRadar | token en la cabecera `SEC` | `SELECT starttime, sourceip, destinationip, username, qidname(qid), magnitude, categoryname(category) FROM events LAST 24 HOURS` |

- En AQL, `categoryname` y `qidname` son **funciones** sobre las columnas numéricas
  `category` y `qid`: con `SELECT *` llegan los enteros crudos y el normalizador de
  QRadar, que lee esos dos campos, clasifica peor.
- Las ventanas temporales aceptan ISO-8601 o atajos relativos: `-24h`, `-7d`, `-30m`.
- Permisos y flujos en [docs/CONNECTORS.md](docs/CONNECTORS.md).

---

## Arquitectura

```
CONNECTORS  →  NORMALIZE  →  EXTRACT/BUILD  →  ENRICH  →  QUERY/API  →  RENDER
SPL/KQL/AQL    OCSF-lite     grafo tipado     roles     filtros      three.js
```

- Seis etapas desacopladas con contratos explícitos.
- El frontend solo conoce `GraphDoc` (JSON): da igual si viene de Splunk en vivo, de
  un CEF pegado a mano o de un fixture de test.
- Diseño en [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); entidades y relaciones en
  [docs/ONTOLOGY.md](docs/ONTOLOGY.md).

---

## Sin build de JavaScript

- Módulos ES con un `importmap`, servidos por el propio FastAPI. Sin `npm install`,
  sin empaquetador, sin paso de compilación.

| Librería | Versión | Por qué esa |
|---|---|---|
| `three.module.js` | **r168** | la MISMA revisión que empaqueta `3d-force-graph` |
| `3d-force-graph.min.js` | 1.73.4 | UMD autocontenido; expone `window.ForceGraph3D` |
| `three-spritetext.mjs` | 1.9.0 | importa `three` como especificador desnudo |
| `jsm/` | r168 | `CSS2DRenderer`, `UnrealBloomPass`, `OutlinePass`, `GLTFLoader` |

- Hay dos copias de three en la página (la nuestra y la interna del bundle). Con
  revisiones distintas el post-procesado revienta con errores de shader; lo comprueba
  `tests/test_web.py::test_three_revisions_match`.
- Los iconos de calidad baja se dibujan con `CanvasTexture`: cero ficheros de assets,
  nítidos a cualquier zoom, y funcionan en un portátil sin red.

---

## Tests

```powershell
pip install -r requirements-dev.txt
pytest -q
```

- **295 tests** recolectados. Ninguno necesita red ni credenciales: todo corre contra
  `samples/`.
- Además de la lógica, se comprueba la integridad del frontend: que todo import y todo
  asset resuelva, que los `id` que busca el JavaScript existan en el HTML, y que las
  dos copias de three coincidan.

---

## Documentación

> **La documentación completa está en el directorio [`wiki/`](wiki/) de este repositorio.**
> Empieza por [Getting Started](wiki/Getting-Started.md)
> o por el [recorrido guiado del incidente de ejemplo](wiki/Demo-Incident.md).

| Dónde | Qué hay |
|---|---|
| `wiki/` (16 páginas) | manual de uso: Getting-Started, Demo-Incident, Views-and-Interaction, Visual-Language, Reports, Admin-Panel, Normalizers, Connectors, Ontology, Architecture, API-Reference, Extending, Troubleshooting |
| `docs/` | diseño interno: `ARCHITECTURE.md`, `ONTOLOGY.md`, `APPEARANCE.md`, `CONNECTORS.md`, `PENDIENTE.md` |
| `docs/diagrams/` | los seis SVG de «De un vistazo» |

- La pestaña Wiki de GitHub **está vacía**: las 16 páginas no se han podido empujar
  todavía (`docs/PENDIENTE.md`). Los enlaces de arriba apuntan al repo, que sí existe.

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

- **Un proceso, una investigación.** El almacén es en memoria (`glamdring/store.py`).
  Es lo correcto para un analista triando en su portátil; para multiusuario hay que
  sustituir esa clase por un backend con clave de sesión.
- Por encima de ~350 nodos la calidad de las figuras baja sola, y por encima de
  ~1.500 el backend recorta a los de mayor riesgo y lo avisa en la barra de estado.
- El scoring de riesgo y la deducción del papel son heurísticas de priorización, no
  veredictos.
- La clase de equipo (puesto / servidor / router / cortafuegos) se deduce del
  hostname. Acierta en un parque con nomenclatura corporativa; en uno sin ella, hay
  que corregirla desde el panel.
- Las consultas a Splunk usan modo export; para búsquedas de horas haría falta pasar
  a modo job con polling.
- **STIX-lite no es STIX 2.1.** Los objetos tienen la forma correcta y sirven para
  alimentar un TIP, pero no es un bundle completo ni pretende serlo.
- La valoración de amenaza solo sale por `GET /api/threat` y en los informes: no hay
  panel en la interfaz.

---

## Licencia y datos de terceros

- **No hay fichero `LICENSE` en el repo todavía**, así que el código no lleva licencia
  de uso explícita.
- Los datos de amenaza se vendorizan con `python tools/fetch_threat_intel.py` desde
  [Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix)
  (BushidoUK, **CC BY 4.0**) y [ransomware.live](https://ransomware.live)
  (Julien Mousqueton), cada uno bajo su propia licencia.

---

## De un vistazo

Seis SVG hechos a mano en [docs/diagrams/](docs/diagrams/): se leen en cualquier
navegador, se editan con un editor de texto y no dependen de ninguna herramienta.

### 1. Dónde encaja en la red

No instala agentes, no responde a incidentes y no sustituye al SIEM: lee lo que el
SIEM ya recogió y lo pinta.

![Arquitectura de red](docs/diagrams/01-arquitectura-red.svg)

### 2. Qué le pasa a un log desde que entra

Seis etapas, cada una con su contrato de entrada y salida. Abajo, el mismo registro
de Splunk atravesándolas todas.

![Arquitectura de datos](docs/diagrams/02-arquitectura-datos.svg)

### 3. Cómo se dibuja el grafo

Módulos ES con `importmap` y three.js r168, con la revisión fijada para que coincida
con la que trae `3d-force-graph`.

![Arquitectura visual](docs/diagrams/03-arquitectura-visual.svg)

### 4. Lo que aporta el perímetro

Un log de cortafuegos no dice qué proceso abrió la conexión, pero dice cuándo, cuánto
y hacia dónde. Cruzado con el endpoint, cierra el caso.

![Perímetro y cortafuegos](docs/diagrams/04-perimetro-firewall.svg)

### 5. Por qué hacen falta los cuatro SIEM

Cada uno ve bien una parte y mal las demás, y cada uno llama de una manera distinta a
la misma persona. La canonización es lo que los une.

![Los cuatro SIEM y la unificación](docs/diagrams/05-siems-unificacion.svg)

### 6. Cómo se detecta un despliegue de ransomware

Ocho etapas. Cuando se ve la octava ya es tarde, así que lo que se busca es el rastro
de las siete anteriores.

![Cadena de ransomware](docs/diagrams/06-cadena-ransomware.svg)

---

## Capacidades de cada SIEM, y qué pasa cuando hay dos

Ninguno lo ve todo. La pregunta útil no es cuál es mejor, sino **qué se pierde cuando
hay dos y nadie los cruza**.

![Capacidades comparadas de los cuatro SIEM](docs/diagrams/07-capacidades-siem.svg)

| | Endpoint | Identidad | Correo | Red y flujos | Perímetro | Cloud |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Splunk** | ●●● | ●○○ | ●○○ | ●●○ | ●●○ | ●○○ |
| **Sentinel / Defender** | ●●○ | ●●● | ●●● | ●○○ | ●○○ | ●●● |
| **IBM QRadar** | ●○○ | ●●○ | ●○○ | ●●● | ●●● | ●○○ |
| **CEF / LEEF / syslog** | ●○○ | ●○○ | ●○○ | ●●○ | ●●● | ●○○ |

`●●●` fuente principal · `●●○` aporta, con lagunas · `●○○` testimonial o ausente

| SIEM | Consulta | Su punto fuerte | Su punto ciego |
|---|---|---|---|
| **Splunk** | SPL, REST `:8089` | Línea de comandos completa, árbol de procesos, Sysmon y 4688 | Identidad cloud |
| **Sentinel / Defender** | KQL, Log Analytics | Inicios de sesión, phishing entregado, alertas del EDR ya correladas | Todo lo que no es Microsoft |
| **IBM QRadar** | AQL, Ariel | Quién habló con quién y cuántos bytes; ofensas ya agrupadas | Identifica por IP, no por nombre |
| **CEF / LEEF / syslog** | fichero o syslog crudo | El comodín: cortafuegos, proxy, antivirus, VPN, cabinas | Cada fabricante lo estira a su gusto |

### Por qué esto importa

Dos SIEM no son el doble de visibilidad, son **dos mitades que nadie junta**. Pasa en
dos escenarios muy corrientes:

- **Una empresa con dos SIEM.** Uno heredado y otro nuevo, o uno de TI y otro de OT. El
  ataque cruza los dos y cada analista mira solo el suyo.
- **Dos empresas que se fusionan.** Datos parecidos, herramientas distintas y una
  migración que dura años. Mientras tanto hay que investigar incidentes que atraviesan
  las dos redes.

GLAMDRING no sustituye a ninguno: los lee y los cose por las entidades comunes.

| Solo el SIEM A (Splunk) | Solo el SIEM B (QRadar) | Cosidos por equipo y hora |
|---|---|---|
| «jlopez ejecutó `powershell.exe` con la línea ofuscada en WKS-0421» | «10.4.2.11 sacó 4,2 GB hacia 45.132.88.17 en 40 minutos» | «jlopez ejecutó `powershell.exe` en WKS-0421 y doce minutos después ese mismo equipo sacó 4,2 GB» |
| No sabes si llegó a salir de la red | No sabes qué proceso fue ni quién | El caso, entero |

Lo que lo hace posible:

- **Un solo modelo.** Los cuatro caen a OCSF-lite, así que un proceso de Splunk y un
  flujo de QRadar se comparan.
- **La identidad se unifica.** `CORP\jlopez`, `jlopez@corp.com` y `jlopez` son un nodo,
  no tres. Y `10.4.1.5` se funde en `srv-dc01`.
- **Cada arista recuerda su origen**, así que siempre se vuelve al log del SIEM que lo tiene.

---

## Los 17 grupos de ransomware reconocidos

![Los 17 grupos de ransomware, sus herramientas por categoría y su nota característica](docs/diagrams/08-grupos-ransomware.svg)

Ordenados por tamaño del repertorio. Las ocho categorías van en orden de intrusión:
**RMM** control remoto · **Desc** reconocimiento · **Cred** robo de credenciales ·
**OffS** utillaje ofensivo · **Red** túneles · **Exfi** exfiltración ·
**Evas** evasión de defensas · **LOL** binarios del sistema.

| Grupo | Total | RMM | Desc | Cred | OffS | Red | Exfi | Evas | LOL | Nota que lo distingue |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|
| **ScatteredSpider** | 78 | 26 | 11 | 10 | 6 | 17 | 6 | 1 | 1 | — |
| **TheGentlemen** | 41 | 3 | 12 | 3 | 8 | 8 | 1 | 5 | 1 | `README-GENTLEMEN.txt` |
| **Warlock** | 26 | 2 | 2 | 2 | 3 | 8 | 1 | 3 | 5 | `How to decrypt my data.txt` |
| **BlackSuit** | 24 | 4 | 4 | 7 | 2 | 3 | 1 | 2 | 1 | `README.BlackSuit.txt` |
| **Akira** | 23 | 4 | 5 | 3 | 1 | 3 | 5 | 2 | — | `akira_readme.txt` |
| **BlackBasta** | 21 | 6 | 5 | 1 | 4 | — | 2 | 1 | 2 | `blackbasta1.txt` |
| **Qilin** | 18 | 1 | 2 | 1 | 3 | 1 | 1 | 6 | 3 | `DtMXQFOCos-RECOVER-README.txt` |
| **BianLian** | 16 | 6 | 5 | 1 | 1 | — | 2 | — | 1 | `Look at this instruction.txt` |
| **DragonForce** | 15 | — | 4 | 2 | 1 | — | 2 | 5 | 1 | `[rand].README.txt` |
| **Beast** | 13 | 1 | 4 | 3 | — | 2 | 2 | — | 1 | — |
| **EvilCorp** | 12 | 1 | 2 | 3 | 2 | — | 3 | — | 1 | — |
| **Interlock** | 11 | 2 | 2 | — | 1 | 1 | 2 | 2 | 1 | `!!!OPEN_ME!!!.txt` |
| **ProphetSpider** | 11 | — | 1 | 1 | 5 | — | 1 | — | 3 | — |
| **PLAY** | 10 | — | 1 | 1 | 2 | 1 | 1 | 3 | 1 | `readme2.txt` |
| **INC Ransom** | 9 | — | 2 | — | — | — | 5 | — | 2 | — |
| **Yurei** | 9 | 1 | 2 | — | 4 | — | — | — | 2 | — |
| **SafePay** | 8 | 1 | 1 | — | — | — | 3 | — | 3 | `readme_safepay.txt` |

Cómo leer la tabla:

- **El perfil pesa más que el total.** ScatteredSpider tiene 26 herramientas de control
  remoto y 17 de red: entra y se queda. INC Ransom tiene 5 de 9 en exfiltración: viene
  a llevarse datos.
- **La nota que distingue** es la única que no comparte con ningún otro grupo del
  catálogo. Los que ponen «—» solo usan nombres genéricos como `README.txt`, que no
  identifican nada: el motor los pondera con 0,1 frente al 10 de una nota propia.
- **Los emblemas del esquema son monogramas, no logotipos.** Estos grupos no tienen una
  marca redistribuible, y ponerles una inventada sería afirmar algo falso.

> **Esto no sirve para señalar a nadie.** Comparten afiliados y casi todos usan las
> mismas utilidades, que además usan los administradores legítimos. El solape orienta la
> búsqueda —dice qué mirar a continuación—, no dice quién fue.

El cuadro se genera desde el catálogo, no se escribe a mano:

```powershell
python tools/fetch_threat_intel.py   # actualiza el catálogo desde las fuentes
python tools/make_group_table.py     # regenera docs/diagrams/08-grupos-ransomware.svg
```

Datos: [Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix)
(BushidoUK, CC BY 4.0) y [ransomware.live](https://ransomware.live) (Julien Mousqueton).
