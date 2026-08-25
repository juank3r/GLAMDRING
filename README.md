# GLAMDRING

<div align="center">

![Gandalf empuñando Glamdring, en arte ASCII](docs/glamdring.png)

</div>

**Lee Splunk, Sentinel/Defender, QRadar y CEF/LEEF/syslog, y los convierte en un grafo
3D navegable del incidente.** Entidades como nodos, acciones como aristas dirigidas y el
tiempo como eje. El SIEM sigue siendo la fuente de verdad: cada nodo y cada arista abren
el log literal que los generó. Corre en local, un proceso, sin autenticación.

---

## Arranque rápido

Probado con **Python 3.12**.

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
- Sin SIEM y sin credenciales: `samples/` trae el incidente repartido entre los cuatro
  formatos de ingesta soportados.
- Frontend sin build: no hay `npm install`.
- `tools\run.ps1` (51 líneas) cierra lo que hubiera y arranca **siempre en :8000**.
  Acepta `-Port 8080` y `-Reload` (la recarga levanta un proceso más, el vigilante, por
  eso se pide a propósito y no viene puesta).
- Servidores vivos de sesiones anteriores:
  `powershell -ExecutionPolicy Bypass -File tools\stop_servers.ps1`. Busca por línea de
  comandos y no solo por puerto, para cazar también al vigilante de `--reload`. Acepta
  `-Keep 8000` y `-WhatIf`.
- Linux/macOS: `source .venv/bin/activate` y `uvicorn glamdring.main:app --port 8000`.
  `run.ps1` es solo para PowerShell.

---

## Qué hace

### Normaliza cuatro formatos a un modelo común

| Fuente | Qué entiende | Conector en vivo |
|---|---|---|
| **Splunk** | `WinEventLog:Security` (4624, 4625, 4648, 4688, 4720), Sysmon (1, 3, 11, 22), sourcetypes de firewall/proxy/DNS y campos CIM | sí, token de servicio |
| **Sentinel / Defender** | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `SigninLogs`, `EmailEvents`, `SecurityAlert`, `SecurityIncident` | sí, Service Principal con *Log Analytics Reader* |
| **QRadar** | Resultados Ariel (`starttime`, `sourceip`, `magnitude`, `categoryname`…) y ofensas | sí, token en la cabecera `SEC` |
| **CEF / LEEF / syslog** | CEF 0.x, LEEF 1.0 y 2.0, syslog RFC5424 y RFC3164, y JSON arbitrario como red de seguridad | — (entra por fichero, con `files`) |

- El destino común es un subconjunto pragmático de [OCSF](https://schema.ocsf.io/), el
  esquema vendor-neutral impulsado por AWS y Splunk (`glamdring/normalize/`).

![Los cuatro SIEM y la unificación](docs/diagrams/05-siems-unificacion.svg)

### Deduplicación

- `CORP\jlopez` (Splunk), `jlopez@corp.com` (Sentinel) y `jlopez` (QRadar) → **un** usuario.
- `SRV-DC01` y `10.4.1.5` → **una** máquina, fundiendo la IP en el host que la declara.
- `m.exe` (nombrado en una alerta) y `C:\Windows\Temp\m.exe` (visto por Sysmon) →
  **un** fichero, unidos por su hash.
- `explorer.exe` con ruta y sin ruta, en el mismo host → **un** proceso.

Y lo que **no** debe ser un nodo tampoco lo es:

- Las cuentas de máquina (`WKS-0421$`) y las cuentas integradas de Windows (SYSTEM,
  LOCAL SERVICE, NETWORK SERVICE, ANONYMOUS LOGON). Las cuentas de servicio del dominio,
  como `svc_backup`, sí son nodos: ahí sí hay alguien detrás.
- Los nombres de producto que QRadar mete en `logsourcename`: `TrendMicro-AV` no es una
  máquina del parque.
- Las aplicaciones cloud, que son servicios y no equipos.

### Figuras

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

- La cámara arranca en `orbit` y no en `trackball` (`appearance.py:137`): trackball no
  fija el eje vertical y arrastrando se acaba viendo a una persona boca abajo.
- `web/js/render/orient.js` gira cada fotograma las **10** figuras con frente que
  declara `ontology.FACING_MODELS` (workstation, server, router, firewall, person,
  attacker, envelope, alert, document, key); las simétricas y los `.glb` subidos no.
  Modos: `fixed`, `yaw` (por defecto, conserva la vertical) y `billboard`.
- Se gira la figura, no el grupo del nodo, para que la etiqueta no orbite. Cualquier
  figura se sustituye por un `.glb` propio desde el panel de administrador.
- Detalle en [Visual-Language](wiki/Visual-Language.md).

### Cuatro vistas del mismo grafo

- **Explorar** (force-directed libre), **Kill-chain** (el eje X pasa a ser la táctica
  MITRE, de acceso inicial a impacto), **Cronología** (el eje X es el tiempo del primer
  avistamiento) y **Replay** (nodos y aristas aparecen según ocurrieron, sin que el
  layout se mueva, y cada arista suelta un destello en su momento exacto).
- Las partículas que recorren las aristas son el volumen de eventos.
- Color por tipo de entidad, papel, severidad, riesgo, origen del dato, táctica MITRE o
  comunidad.
- Detalle en [Views-and-Interaction](wiki/Views-and-Interaction.md).

### Interacción

| Gesto | Resultado |
|---|---|
| hover | resalta la vecindad |
| clic | selecciona y enfoca la cámara |
| ctrl + clic | añade a la selección múltiple, para comparar entidades |
| doble clic | trae vecinos nuevos del servidor sin mover lo ya colocado |
| clic derecho | menú contextual: seguir, centrar la cámara, expandir vecinos, fijar, ocultar, copiar como IOC, copiar identificador, buscar |
| arrastrar un nodo | lo ancla en su sitio |
| `1` · `2` · `3` | explorar · kill-chain · cronología |
| `s` · `t` | seguir a la entidad seleccionada · recorrido automático en bucle |
| `espacio` · `f` | reproducir/pausar la cronología · encuadrar todo el grafo |
| `c` · `/` | cambiar el modo de color · ir al buscador |
| `a` · `r` · `?` | panel de administrador · informe · ayuda de atajos |

El inspector de un nodo o una arista da sus métricas, su papel, sus tácticas MITRE, sus
vecinos y los registros del SIEM que lo sustentan.

### Seguir a una entidad

- En la demo, sobre `jlopez`: de 38 nodos a **18** y **30 pasos**. Lo que sobra
  desaparece, no se atenúa, y en cada paso aparece lo que acaba de ocurrir y nada de lo
  que viene después (2 nodos visibles en el paso 1, 10 en el 15, los 18 en el 30).
- Las frases no se redactan en el front: vienen de `report.narrative`, el mismo motor
  que escribe la cronología del informe, así que el recorrido en pantalla y el informe
  dicen literalmente lo mismo.
- `GET /api/graph/story?node=<id>` devuelve en una sola llamada los actos en orden y el
  subgrafo aislado, colapsa repeticiones consecutivas por la misma arista (catorce
  fallos de login idénticos son un hecho, no catorce paradas de cámara) y topa en 120
  pasos (`glamdring/graph/story.py`, `tests/test_story.py`).
- Detalle en [Demo-Incident](wiki/Demo-Incident.md).

### Modo automático

- Recorre las entidades del incidente una tras otra y al terminar vuelve a empezar
  (`web/js/ui/auto.js`).
- El orden lo pone la hora de **primera aparición**, no el riesgo: ir por riesgo
  enseñaría el desenlace antes que el principio.
- Salta el contexto forense de apoyo y las entidades con menos de dos acciones, y se
  para en cuanto alguien toca el lienzo.

### Panel de administrador

- Diez pestañas: siete de aspecto y comportamiento (Tema, Render, Física, Etiquetas,
  Aristas, Cámara, Interacción), **Ontología** (color, figura y visibilidad por tipo, con
  subida de `.glb`), **Reglas** (los pesos del riesgo, que deciden el orden en que el
  analista mira las cosas y el tamaño de cada figura) y **Perfil** (importar, exportar,
  restablecer).
- Los controles no están escritos a mano: se generan del `spec` que manda el servidor
  con el rango real de cada campo, así que añadir un ajuste es tocar
  `glamdring/appearance.py`.
- La configuración vive en `config/appearance.json` **en el servidor**: un único perfil
  para todo el equipo.
- Detalle en [Admin-Panel](wiki/Admin-Panel.md) y [docs/APPEARANCE.md](docs/APPEARANCE.md).

### Informes automáticos

- **Determinista y sin modelo de lenguaje: la misma evidencia produce siempre el mismo
  texto**, y cada línea se puede rastrear hasta su log.
- Contiene resumen ejecutivo, cronología narrada en español, cadena de ataque MITRE con
  evidencias, tabla de entidades por riesgo, indicadores de compromiso y acciones de
  contención. Una línea tal cual sale: «jlopez ejecutó powershell.exe en wks-0421,
  lanzado por explorer.exe con la línea de comandos `powershell.exe -nop -w hidden -enc ...`».
- Cinco formatos: **HTML autocontenido** (con la captura del grafo incrustada,
  imprimible a PDF con Ctrl+P), **Markdown** (para Jira, TheHive o el wiki),
  **JSON completo**, **STIX-lite** (indicadores para un TIP) y **lista plana de IOCs**
  lista para pegar en un firewall.
- La lista de IOCs excluye RFC1918.
- Detalle en [Reports](wiki/Reports.md).

### Detección de ransomware y atribución

Catálogo incorporado: **305 herramientas** de intrusión clasificadas por categoría y
grupo, **17 perfiles de grupo** y **299 notas de rescate** reales. Con eso mira cada
línea de comandos por tres vías:

| Vía | Qué busca | Ejemplo |
|---|---|---|
| Herramienta | binarios del repertorio conocido, con su categoría | `rclone.exe` → exfiltración |
| Comportamiento | 13 firmas sobre la línea de comandos, independientes del nombre del fichero | `vssadmin delete shadows` |
| Nota de rescate | el nombre de fichero característico de cada familia | `akira_readme.txt` |

- Sobre los hallazgos calcula qué **etapas del despliegue** se han alcanzado (de «acceso
  inicial» a «cifrado») y propone una **atribución ponderada**.
- Los 17 están listados con su repertorio en
  [Los 17 grupos de ransomware reconocidos](#los-17-grupos-de-ransomware-reconocidos).
- **La atribución es una hipótesis de trabajo, nunca un veredicto**: estas herramientas
  las usan muchos grupos y también los administradores legítimos. El aviso va impreso en
  los informes narrativos (HTML, Markdown y JSON); STIX-lite y la lista plana de IOCs no
  llevan sección de atribución y por tanto tampoco el aviso.

```powershell
python tools/make_apt_samples.py    # escribe 17 incidentes de ejemplo en samples/apt/
curl -F "file=@samples/apt/Akira.json" http://localhost:8000/api/ingest
curl http://localhost:8000/api/threat
```

![Cadena de ransomware](docs/diagrams/06-cadena-ransomware.svg)

### Rendimiento

- `/api/graph`: **9,5 s → 0,11 s**, con cache LRU de 6 entradas (`_CACHE_MAX`,
  `glamdring/graph/query.py`) por versión del almacén y filtros de evento.
- Chip de filtro: **0,07 s**; `/api/graph/story`: **0,03 s**. Los filtros de tipo de
  entidad, de relación, foco, saltos y tope actúan sobre el grafo ya construido.
- `EventStore` sube de versión solo cuando entra algo de verdad: una reingesta de puros
  duplicados no invalida la cache (`tests/test_cache.py`).
- Resaltar: **138 ms → 0,43 ms**, clonando los materiales una vez por nodo
  (`userData.gdMaterials`) en vez de dejar que `refresh()` tire todos los objetos 3D y
  vuelva a llamar a `nodeThreeObject`.
- Peor fotograma del replay: **253 ms → 38 ms**.
- Las dos últimas son medidas de navegador sobre 228 nodos y 692 aristas; no hay banco
  de pruebas en el repo que las reproduzca, así que valen como orden de magnitud.
## Consultar el SIEM en vivo

Copia `.env.example` a `.env` y rellena solo el SIEM que uses. Luego, botón **SIEM**:

- Splunk: `index=wineventlog EventCode IN (4624,4625,4688)`
- Sentinel: `DeviceProcessEvents | where Timestamp > ago(24h)`
- QRadar: `SELECT starttime, sourceip, destinationip, username, qidname(qid), magnitude, categoryname(category) FROM events LAST 24 HOURS`
- En AQL, `categoryname` y `qidname` son **funciones** sobre las columnas numéricas
  `category` y `qid`: con `SELECT *` llegan los enteros crudos y el normalizador de
  QRadar, que lee esos dos campos, clasifica peor.
- Las ventanas temporales aceptan ISO-8601 o atajos relativos: `-24h`, `-7d`, `-30m`.
- Permisos y flujos en [docs/CONNECTORS.md](docs/CONNECTORS.md).

---

## Arquitectura

No instala agentes, no responde a incidentes y no sustituye al SIEM: lee lo que el SIEM
ya recogió y lo pinta.

![Arquitectura de red](docs/diagrams/01-arquitectura-red.svg)

```
CONNECTORS  →  NORMALIZE  →  EXTRACT/BUILD  →  ENRICH  →  QUERY/API  →  RENDER
SPL/KQL/AQL    OCSF-lite     grafo tipado     roles     filtros      three.js
```

- Cada etapa entrega un tipo: `dict` crudo → evento OCSF-lite → `GraphDoc`.
- El frontend solo conoce `GraphDoc` (JSON): da igual si viene de Splunk en vivo, de un
  CEF pegado a mano o de un fixture de test.
- Diseño en [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md); entidades y relaciones en
  [docs/ONTOLOGY.md](docs/ONTOLOGY.md).

![Arquitectura de datos](docs/diagrams/02-arquitectura-datos.svg)

---

## Sin build de JavaScript

Módulos ES con un `importmap`, servidos por el propio FastAPI. Las librerías van
vendorizadas en `web/js/vendor/`; para volver a bajarlas, `python tools/fetch_vendor.py`.

| Librería | Versión | Por qué esa |
|---|---|---|
| `three.module.js` | **r168** | la MISMA revisión que empaqueta `3d-force-graph` |
| `3d-force-graph.min.js` | 1.73.4 | UMD autocontenido; expone `window.ForceGraph3D` |
| `three-spritetext.mjs` | 1.9.0 | importa `three` como especificador desnudo |
| `jsm/` | r168 | `CSS2DRenderer`, `UnrealBloomPass`, `OutlinePass`, `GLTFLoader` |

- Hay dos copias de three en la página (la nuestra y la interna del bundle). Con
  revisiones distintas el post-procesado revienta con errores de shader; lo comprueba
  `tests/test_web.py::test_three_revisions_match`.
- Los iconos de calidad baja se dibujan con `CanvasTexture`: cero ficheros de assets y
  nítidos a cualquier zoom.

![Arquitectura visual](docs/diagrams/03-arquitectura-visual.svg)

---

## Tests

```powershell
pip install -r requirements-dev.txt
pytest -q
```

- ~300 tests, sin red ni credenciales.
- Además de la lógica, se comprueba la integridad del frontend: que todo import y todo
  asset resuelva y que los `id` que busca el JavaScript existan en el HTML.

---

## Documentación

> **La documentación completa está en el directorio [`wiki/`](wiki/) de este repositorio.**
> Empieza por [Getting Started](wiki/Getting-Started.md) o por el
> [recorrido guiado del incidente de ejemplo](wiki/Demo-Incident.md).

| Dónde | Qué hay |
|---|---|
| `wiki/` (14 páginas, más `_Sidebar` y `_Footer`) | manual de uso: Home, Getting-Started, Demo-Incident, Views-and-Interaction, Visual-Language, Reports, Admin-Panel, Normalizers, Connectors, Ontology, Architecture, API-Reference, Extending, Troubleshooting |
| `docs/` | diseño interno: `ARCHITECTURE.md`, `ONTOLOGY.md`, `APPEARANCE.md`, `CONNECTORS.md`, `PENDIENTE.md` |
| `docs/diagrams/` | los ocho SVG del documento: 01-07 hechos a mano, 08 generado por `tools/make_group_table.py` |

- La pestaña Wiki de GitHub **está vacía**: las 14 páginas no se han podido empujar
  todavía (`docs/PENDIENTE.md`). Los enlaces de arriba apuntan al repo, que sí existe.

---

## Seguridad

- Los secretos solo viajan por variables de entorno. `.env` está en `.gitignore`.
- `/api/health` informa de qué conectores hay configurados, **nunca con qué**.
- Los campos tipo `password`, `token`, `api_key` o `authorization` se tachan del log
  crudo antes de guardarlo: los logs de autenticación a veces arrastran credenciales.
- Todo lo que entra al perfil visual se sanea clave a clave contra un `spec`: lo
  desconocido se descarta y lo fuera de rango se recorta.
- Los `.glb` que se suben se validan por la **cabecera** del fichero, no por la
  extensión: acaban sirviéndose como estáticos al navegador de todo el equipo.
- La lectura de rutas del disco del servidor está desactivada por defecto
  (`GLAMDRING_ALLOW_FILE_PATHS=0`).
- No hay autenticación de usuarios. Pensado para correr en local o detrás de un proxy
  que la ponga.

---

## Límites conocidos

- **Un proceso, una investigación.** El almacén es en memoria (`glamdring/store.py`).
  Es lo correcto para un analista triando en su portátil; para multiusuario hay que
  sustituir esa clase por un backend con clave de sesión.
- Por encima de ~350 nodos la calidad de las figuras baja sola, y por encima de ~1.500
  el backend recorta a los de mayor riesgo y lo avisa en la barra de estado.
- Riesgo, papel y atribución: heurísticas de priorización (ver arriba).
- La clase de equipo (puesto / servidor / router / cortafuegos) se deduce del hostname.
  Acierta en un parque con nomenclatura corporativa; en uno sin ella, hay que corregirla
  desde el panel.
- Las consultas a Splunk usan modo export; para búsquedas de horas haría falta pasar a
  modo job con polling.
- **STIX-lite no es STIX 2.1.** Los objetos tienen la forma correcta y sirven para
  alimentar un TIP, pero no es un bundle completo ni pretende serlo.
- La valoración de amenaza solo sale por `GET /api/threat` y en los informes: no hay
  panel en la interfaz.

---

## Licencia y datos de terceros

- **No hay fichero `LICENSE` en el repo todavía**, así que el código no lleva licencia de
  uso explícita.
- Los datos de amenaza se vendorizan con `python tools/fetch_threat_intel.py` desde
  [Ransomware Tool Matrix](https://github.com/BushidoUK/Ransomware-Tool-Matrix)
  (BushidoUK, **CC BY 4.0**) y [ransomware.live](https://ransomware.live)
  (Julien Mousqueton), cada uno bajo su propia licencia.

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

| SIEM | Su punto fuerte | Su punto ciego |
|---|---|---|
| **Splunk** | Línea de comandos completa, árbol de procesos, Sysmon y 4688 | Identidad cloud |
| **Sentinel / Defender** | Inicios de sesión, phishing entregado, alertas del EDR ya correladas | Todo lo que no es Microsoft |
| **IBM QRadar** | Quién habló con quién y cuántos bytes; ofensas ya agrupadas | Identifica por IP, no por nombre |
| **CEF / LEEF / syslog** | El comodín: cortafuegos, proxy, antivirus, VPN, cabinas | Cada fabricante lo estira a su gusto |

Dos SIEM no son el doble de visibilidad, son **dos mitades que nadie junta**. Pasa en
dos escenarios muy corrientes:

- **Una empresa con dos SIEM.** Uno heredado y otro nuevo, o uno de TI y otro de OT. El
  ataque cruza los dos y cada analista mira solo el suyo.
- **Dos empresas que se fusionan.** Datos parecidos, herramientas distintas y una
  migración que dura años. Mientras tanto hay que investigar incidentes que atraviesan
  las dos redes.

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

Un log de cortafuegos no dice qué proceso abrió la conexión, pero dice cuándo, cuánto y
hacia dónde. Cruzado con el endpoint, cierra el caso:

![Perímetro y cortafuegos](docs/diagrams/04-perimetro-firewall.svg)

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

- **El perfil pesa más que el total.** ScatteredSpider tiene 26 herramientas de control
  remoto y 17 de red: entra y se queda. INC Ransom tiene 5 de 9 en exfiltración: viene a
  llevarse datos.
- **La nota que distingue** es la única que no comparte con ningún otro grupo del
  catálogo. Los que ponen «—» solo usan nombres genéricos como `README.txt`, que no
  identifican nada: el motor los pondera con 0,1 frente al 10 de una nota propia
  (`glamdring/threat/attribution.py:88` y `:93`).
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

---
