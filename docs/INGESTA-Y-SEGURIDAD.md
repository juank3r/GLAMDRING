# GLAMDRING: ingesta, tipos de log y seguridad del canal

Documento de repaso para el responsable del proyecto. Estado auditado sobre el arbol en disco, con las
comprobaciones ejecutadas en el `.venv` del proyecto (Python 3.12.10, fastapi 0.141.1, starlette 1.6.0,
httpx 0.28.1, uvicorn 0.52.4, pydantic 2.13.4).

Donde el diseno afirmaba una cosa y la verificacion la tumbo, aqui figura la version corregida, no la
original. Donde no se sabe, se dice.

---

## 1. Lo que hay hoy

| Pieza | Estado hoy | Dato |
| --- | --- | --- |
| Conectores | 4: splunk, sentinel, qradar, files | `connectors/__init__.py:18-23` (`_FACTORIES`) |
| Contrato del conector | `configured` + `fetch(query, time_from, time_to, limit) -> List[Dict]` | `connectors/base.py:29-57` |
| Normalizadores | 4 registrados: splunk_windows(10), sentinel_defender(10), qradar(10), generic(99) | `normalize/base.py:29-39` |
| Modelo comun | `NormalizedEvent`, 18 campos, 8 clases | `models.py:128-164`, clases en `models.py:31-38` |
| Formatos detectados | json, ndjson, csv, cef, syslog, empty | `normalize/detect.py:22-49` |
| Almacen | singleton de proceso en RAM, tope 500.000 eventos | `store.py:31`, `store.py:160` |
| Autenticacion de la API | **no existe**, 28 rutas abiertas | `main.py:59-75`, sin `dependencies=` |
| CORS / middleware | ninguno registrado, mismo origen por diseno | `main.py:3-6`; `add_middleware` = 0 aciertos |
| TLS hacia el SIEM | interruptor binario si/no | `config.py:66`, `config.py:91` |
| Tachado de secretos | solo por NOMBRE de clave, nunca por valor | `store.py:45` |
| Limite de subida | 200 MB, comprobado a trozos en el handler | `routes_ingest.py:20`, `:53-78` |
| Timeout de consulta | 120 s nominales, hasta mas de 360 s reales en QRadar | `config.py:104`; `qradar.py:103` |
| Tests de conectores | **cero**, no existe `tests/test_connectors.py` | `respx>=0.21` declarado en `requirements-dev.txt` |
| Tests de normalizacion | 46/46 en verde, pero solo de recuento | `tests/test_normalize.py:282-302` |
| Bind por defecto | `127.0.0.1` | `tools/run.ps1:75` |

Resumen honesto en tres frases:

- La capa de conectores es **correcta de forma y pobre de fondo**: contrato limpio, cero telemetria de
  truncado, cero reintentos, cero paginacion, cero pruebas.
- La normalizacion **cubre bien Windows/Defender y clasifica mal el perimetro**: dos de las once lineas
  del propio `samples/perimeter.cef` salen mal clasificadas y sin una sola arista.
- La seguridad del canal **no existe todavia**: sin autenticacion, con lectura de ficheros arbitrarios
  verificada end-to-end y con el tachado de secretos sin cubrir el caso que su propio docstring anuncia.

---

## 2. Integraciones SIEM

### 2.1 El contrato, y lo que le falta

- `Connector` (`connectors/base.py:29-57`) exige tres atributos de clase (`name`, `query_language`,
  `example_query`), la propiedad `configured` y la corrutina `fetch`.
- El conector devuelve registros **crudos**. Normalizar y almacenar es de `_ingest_records`
  (`api/routes_ingest.py:38-50`). Ese reparto se cumple en los cuatro conectores.
- Unica fuga consciente: Sentinel inyecta la clave `Type` en cada fila (`sentinel.py:101`, `:150`) porque
  el normalizador la necesita y Log Analytics no la trae.

Huecos del contrato, por orden de importancia:

1. **No hay forma de decir "esto viene truncado"**. `fetch` devuelve una lista pelada y la respuesta de
   `/api/query` no lleva marca alguna (`routes_ingest.py:274-276`). "El SIEM tenia 10.000" y "el SIEM tenia
   dos millones" son indistinguibles.
2. **No hay paginacion**: ningun conector expone cursor, offset ni continuation token, pese a que Splunk
   tiene `offset`, QRadar `Range` desplazable y Log Analytics `$skip`.
3. **No hay `ping()`**. La UI pinta un semaforo por conector con `describe()` y ese semaforo miente en
   Sentinel: `SentinelConfig.configured` solo mira `workspace_id` (`config.py:74-83`).
4. **No hay `close()` ni ciclo de vida**: cada `fetch` crea y destruye un `httpx.AsyncClient`
   (`splunk.py:75-76`, `qradar.py:65-67`, `sentinel.py:121`). Se cachea el objeto barato (el conector,
   `__init__.py:25`) y se tira el caro (el pool TLS).

### 2.2 Autenticacion por conector

| Conector | Como autentica | Variables | Problema concreto |
| --- | --- | --- | --- |
| Splunk | `Authorization: Splunk <token>` o Basic | `SPLUNK_URL/TOKEN/USERNAME/PASSWORD` | El mensaje de error solo cita `SPLUNK_URL / SPLUNK_TOKEN` y oculta la via usuario/contrasena que `configured` acepta (`splunk.py:51-52`, `config.py:60-71`) |
| Sentinel | SDK (`ClientSecretCredential` / `DefaultAzureCredential`) o REST client_credentials | `SENTINEL_WORKSPACE_ID`, `AZURE_*` | `configured` = solo `workspace_id`; token REST sin cache, dos round-trips por consulta (`sentinel.py:120-131`) |
| QRadar | cabecera `SEC: <token>` + `Version:` | `QRADAR_URL/TOKEN/API_VERSION` | Cabeceras reconstruidas en cada peticion (`qradar.py:87`, `:119`); `QRADAR_VERIFY_TLS=0` aceptado en silencio |
| Files | ninguna, `configured` siempre True | `GLAMDRING_ALLOW_FILE_PATHS` | La puerta no cierra: ver seccion 4.1 |

### 2.3 Los cinco fallos operativos que mas duelen

1. **Sentinel bloquea el event loop.** `_fetch_sdk` es `async def` pero llama al cliente **sincrono**
   `LogsQueryClient.query_workspace(...)` sin `to_thread` (`sentinel.py:62-87`, linea 82). Con el SDK
   instalado, una consulta congela toda la aplicacion hasta `server_timeout` = 120 s: ni `/api/health`,
   ni el frontend, ni la consulta de otro analista.
   Es invisible en pruebas porque el SDK esta **comentado** en `requirements.txt`.
2. **El limite se aplica despues de descargarlo todo.** Solo QRadar acota en servidor, y solo la
   recuperacion (`Range: items=0-{limit-1}`, `qradar.py:87`): la busqueda Ariel se ejecuta entera.
   Sentinel recorta con `rows[:limit]` ya en RAM (`sentinel.py:58`); Splunk materializa el NDJSON completo
   con `response.text` antes de parsear una linea (`splunk.py:89`).
3. **`limit` no esta validado.** `QueryRequest.limit` es un `int` sin `ge=1` (`routes_ingest.py:32`).
   `limit=0` llega a Splunk como `count=0`, que en su REST API significa **sin limite**; un negativo se
   convierte en `Range: items=0-0` (una fila) en QRadar y en `[:-n]` en Sentinel y Files, que descarta las
   ultimas filas sin decir nada.
4. **El `status` HTTP del SIEM se recoge y se tira.** `ConnectorError.status` se rellena en casi todos los
   sitios y no se lee en ninguno (`routes_ingest.py:270-272`, `main.py:78-82`): un 401 de token caducado,
   un 400 de AQL mal escrita y un 503 de SIEM caido salen los tres como el mismo 502.
   Es justo la distincion que el docstring de `ConnectorError` dice querer preservar (`base.py:15-26`).
5. **Fallos de red sin envolver.** Splunk captura `httpx.HTTPError` (`splunk.py:77-81`); QRadar no envuelve
   nada (`qradar.py:72-92`, `:106`, `:117`) y la via REST de Sentinel tampoco (`sentinel.py:122-142`).
   Un SIEM apagado sale como **500 Internal Server Error** sin mensaje util, no como 502.
   Ademas `response.json()` puede lanzar `ValueError` sin proteger en `qradar.py:77,92,110,125` y
   `sentinel.py:131,142` si un portal cautivo devuelve HTML con codigo 200.

### 2.4 El presupuesto de tiempo real es multiplo del configurado

- `GLAMDRING_QUERY_TIMEOUT` se documenta como "segundos por consulta al SIEM" (`config.py:104`, `:155`).
- En httpx ese valor es **por operacion**, no un presupuesto total.
- QRadar: create + N sondeos + results, cada uno con 120 s, mas un deadline propio de otros 120 s
  (`qradar.py:103`). Peor caso realista **por encima de 360 s**.
- Sentinel REST: dos peticiones de 120 s (token + query). Splunk: un export que gotea nunca dispara el
  read timeout. `/api/query` no impone ningun techo global (`routes_ingest.py:263-272`).

### 2.5 Ventana temporal: cuatro semanticas para el mismo parametro

| Conector | Que hace con `time_from` / `time_to` |
| --- | --- |
| Splunk | `earliest_time` / `latest_time` en ISO, y solo si vienen (`splunk.py:70-73`) |
| Sentinel | rellena por defecto (ahora, ahora-24h) y manda `timespan` (`sentinel.py:50-53`) |
| QRadar | `START <ms> STOP <ms>` anadido al final de la AQL (`qradar.py:129-142`) |
| Files | **los ignora en silencio** (`files.py:35-43`) |

Dos fallos ocultos ahi:

- La deteccion de clausula propia de QRadar es una busqueda de subcadena fragil:
  `if " last " in lowered or " start " in lowered or "stop " in lowered` (`qradar.py:136`). El ultimo va
  **sin espacio inicial**, asi que cualquier campo acabado en `stop ` desactiva la ventana.
- `parse_moment` devuelve `None` ante un valor mal formado (`graph/query.py:282-301`): un `from` con
  errata se convierte silenciosamente en "sin ventana".

### 2.6 QRadar: busquedas huerfanas

- `fetch` hace tres pasos: POST `/api/ariel/searches`, sondeo cada 1,5 s (`_POLL_SECONDS`, `qradar.py:21`),
  GET de resultados.
- Al expirar el deadline se lanza `ConnectorError` y **no se llama a `DELETE /api/ariel/searches/{id}`**
  (`qradar.py:101-114`). La busqueda sigue consumiendo el QRadar del cliente y el `search_id` no sale nunca
  del fichero: no hay forma de reengancharse. Reintentar multiplica huerfanas.
- El polling es de intervalo fijo sin backoff: una busqueda de 2 minutos son 80 peticiones.
- La rama `offenses` (`qradar.py:69`, `:116-126`) es una cadena magica no documentada en `example_query`,
  ignora la ventana temporal y lleva `status=OPEN` cableado.

### 2.7 Registro de conectores: "perezoso" solo a medias

- El docstring dice que se instancian de forma perezosa para no obligar a tener los SDK
  (`connectors/__init__.py:1-6`), pero las **clases se importan de forma eager** en las lineas 13-16.
- Lo que salva el argumento es que cada conector importa `httpx`/`azure` **dentro** de `fetch`
  (`splunk.py:54-57`, `qradar.py:57-60`, `sentinel.py:64-68`). Es correcto por casualidad, no por diseno:
  un conector nuevo con `import httpx` arriba rompe el despliegue de solo-ficheros y nada lo detecta.
- `reset_cache()` (`__init__.py:42-44`) **no recarga `SETTINGS`**: vuelve a instanciar contra el mismo
  objeto creado al importar (`config.py:162`). Cambiar el `.env` exige reiniciar el proceso. No esta
  documentado y es el tipo de cosa que hace pasar un test y fallar produccion.

### 2.8 Coste exacto de anadir un conector

Obligatorio:

1. `glamdring/connectors/<nombre>.py` con `name`, `query_language`, `example_query`, `configured`, `fetch`,
   lanzando `ConnectorError(self.name, mensaje, status=...)` e importando el cliente HTTP dentro de `fetch`.
2. Import y entrada en `_FACTORIES` (`connectors/__init__.py:13-23`).

Si necesita credenciales: dataclass `<X>Config` con su `configured` (`config.py:60-95`), campo en `Settings`
(`config.py:98-107`), lectura en `load_settings()` (`config.py:132-159`) y **entrada en `public_status()`**
(`config.py:109-117`), que esta cableada a los cuatro actuales: si se olvida, el conector desaparece de
`/api/health` aunque siga saliendo en `/api/connectors`.

Correccion a la documentacion actual: `docs/CONNECTORS.md` y `wiki/Extending.md:12-58` afirman que hace falta
**un normalizador**. No es cierto. El generico de `cef.py:238-239` acepta cualquier dict con prioridad 99, asi
que un conector nuevo funciona sin normalizador. Funciona **peor** (entidades vacias), pero funciona, y la
documentacion pide mas trabajo del necesario sin explicar cual es el coste real de no hacerlo.

### 2.9 Cobertura de pruebas: cero

- No existe `tests/test_connectors.py`. `respx>=0.21` esta en `requirements-dev.txt` con el comentario
  "mockea httpx para probar conectores sin SIEM delante", y `wiki/Extending.md:124-132` incluye un ejemplo
  que no corresponde a ningun test existente.
- Sin pruebas de `_parse_export`, del polling de Ariel, de `_apply_window` ni del gate de `read_path`, que
  es exactamente donde esta el agujero de la seccion 4.1.
- Lo unico que `tests/test_api.py:44-49` toca es que `/api/connectors` liste y que `files` salga configurado.

### 2.10 Integraciones propuestas, por orden

| Orden | Integracion | Esfuerzo | Valor | Nota clave |
| --- | --- | --- | --- | --- |
| 1 | Defender XDR / MDE Advanced Hunting | bajo | alto | **Cero codigo de normalizador**: mismas tablas que `_TABLES` (`sentinel_defender.py:338-349`) |
| 2 | `GET /api/pivot` (volver al SIEM desde un nodo) | bajo | alto | No toca la capa de conectores; reutiliza `/api/query` |
| 3 | Contrato v2: `FetchResult` + `ping()` | medio | alto | Requisito de casi todo lo demas |
| 4 | Elastic / OpenSearch con normalizador ECS | alto | alto | El coste es el normalizador, no el conector |
| 5 | Okta u otro IdP SaaS | medio | alto | Unica cobertura de identidad fuera de Microsoft |
| 6 | Refresco en vivo de la ultima consulta | medio | medio | **Condicionado** a arreglar antes `sentinel.py:82` |
| 7 | Webhook de entrada (`POST /api/ingest/hook/{id}`) | medio | medio | **Bloqueado** hasta que exista autenticacion |
| 8 | CrowdStrike Falcon (y Chronicle, Cortex) | alto | medio | Ultimo a proposito: normalizador entero a medida |

Detalles que ahorran tiempo real:

- **Defender**: `POST https://graph.microsoft.com/v1.0/security/runHuntingQuery`, permiso de aplicacion
  `ThreatHunting.Read.All`, reutiliza `AZURE_TENANT_ID/CLIENT_ID/CLIENT_SECRET` que `load_settings()` ya lee
  (`config.py:143-148`). La respuesta trae `{"schema":[...],"results":[{...}]}`, ya son dicts: no hay que
  descomprimir `columns`/`rows`. `_base` lee `first(record,'TimeGenerated','Timestamp','EventTime')`
  (`sentinel_defender.py:85`), asi que el `Timestamp` de MDE entra solo. **Si** hay que inyectar `Type`
  como hace `sentinel.py:101`, porque `_guess_table` (`:62-78`) no distingue `DeviceEvents`.
- **Pivot**: la trampa es que los valores de nodo estan **canonicalizados**. `canon_user`
  (`normalize/base.py:198-214`) convierte `CORP\JLopez` en `jlopez`; `canon_host` (`:217-226`) convierte
  `WKS-0421.corp.local` en `wks-0421`. Una consulta construida con `node.id` y `=` devuelve **cero filas
  siempre, y en silencio**. El original esta en `label` y en las props (`graph/extract.py:109-121`,
  `123-147`, `150-170`, `188-206`). Y los nodos `process` tienen valor compuesto `<host>|<ruta>`
  (`extract.py:163`): hay que partir por el primer `|`.
- **Contrato v2**: mantener `fetch()` tal cual y anadir `FetchResult(records, truncated, cursor, took_ms,
  warnings)` mas `fetch_page()` con implementacion por defecto. La deteccion de truncado es barata y honesta:
  pedir `limit+1` y `truncated = len(rows) > limit`.

---

## 3. Tipos de log y normalizacion

### 3.1 Como se decide de quien es un registro

- `detect.py` **no** decide el dueno: solo decide el FORMATO del fichero (`detect.py:22-49`).
- El dueno lo decide `normalize_record` (`normalize/base.py:42-57`): recorre el registro por prioridad
  ascendente y se queda con el primero cuyo matcher da True y cuyo `normalize` no devuelve `None`.
- Los tres especificos **empatan a 10**. El desempate real es el orden de import en
  `normalize/__init__.py:17-20`, porque `_REGISTRY.sort` usa `key=item[0]` (estable).
  Orden efectivo comprobado: `splunk_windows, sentinel_defender, qradar, generic`.
- El arbitraje entre fabricantes depende de un orden de import comentado con un "No quitar", no de una regla.

Consecuencias verificadas:

- Defender reenviado a Splunk: Splunk lo reclama, no sabe convertirlo, y acaba **bien** en sentinel
  (`source=sentinel`, `origin=SecurityAlert`, sev=4). La cesion funciona cuando el primero falla del todo.
- Si Splunk reclama y **acierta a medias**, se queda el registro sin que nadie se entere: no hay log, ni
  contador por normalizador, y el `except Exception` de `base.py:49-52` se traga tambien las excepciones de
  un normalizador roto.

### 3.2 El contador `unmatched` no puede subir nunca

- `routes_ingest.py:44-47` calcula `unmatched = len(records) - len(events)` y lo documenta como "Deberia ser
  0: si sube, es que hace falta un normalizador nuevo".
- Es **estructuralmente siempre 0**: el matcher de generic es `isinstance(record, dict)` (`cef.py:238-239`)
  y su `normalize` nunca devuelve `None` (`cef.py:242-355`).
- La unica telemetria de cobertura que existe no puede detectar jamas que falte un normalizador. Una mala
  clasificacion es indistinguible de un acierto.

### 3.3 Fallos de clasificacion comprobados sobre el propio sample

Ejecutado sobre `samples/perimeter.cef`, el fichero de ejemplo del proyecto:

| Linea | Deberia ser | Sale como | Entidades / aristas |
| --- | --- | --- | --- |
| PAN-OS LEEF `cat=command-and-control` | Network Activity | **Process Activity**, `act=launch` | `[user:jlopez]` / **0 aristas** |
| Cisco Umbrella `DNS Request` | DNS Activity | **File System Activity**, `act=create` | `[user:jlopez]` / **0 aristas** |
| 3 lineas sshd | Authentication (bien) | Authentication (bien) | `[host:srv-dc01]` / **0 aristas** |
| FortiGate trafico | Network Activity (bien) | Network Activity | `host:fgt-perim-01` con **grado 0** |

Causas exactas:

- `cef.normalize` clasifica por orden AUTH, PROCESS, FILE, NETWORK (`cef.py:248-257`) sobre un blob de
  `name+message+action+category+signature+event_type+_raw`. `_PROC_HINTS` incluye `command`
  (`cef.py:234`) y `_FILE_HINTS` incluye `malware` (`cef.py:233`).
- Se pierden `src=10.4.2.11`, `dst=45.132.88.17` y el puerto 443 del C2; y el dominio C2 desaparece.
- `parse_syslog` (`cef.py:161-214`) deja todo el texto en `message` y **nadie lo vuelve a parsear**: el
  usuario (`invalid user administrator`) y la IP atacante estan en el texto y no se extraen. Una fuerza
  bruta SSH seguida de login correcto, el patron mas reconocible que hay, no dibuja nada.
- LEEF pierde la severidad del fabricante: `parse_leef` (`cef.py:128-158`) no captura `sev=` porque LEEF la
  lleva en el cuerpo y `CEF_KEY_ALIASES` (`cef.py:55-68`) no tiene entrada para `sev`. La linea que declara
  `sev=8` sale con **severity=2** (`cef.py:271`). El evento mas grave del fichero es el mas facil de filtrar.
- `_network_activity` (`extract.py:262-277`): con telemetria de perimetro el device es el cortafuegos y el
  src el equipo interno, y el cortafuegos entra en el grafo sin ninguna arista.

Y los tests no lo detectan: `tests/test_normalize.py` pasa **46/46 en 0,90 s**, pero sus asserts
(`:282-302`) son de recuento y de propiedades gruesas. Ninguna prueba afirma a que clase debe ir cada linea
ni que entidades debe producir.

### 3.4 Splunk: la ultima red convierte casi todo en un logon correcto

- Solo 9 EventCodes despachados (`splunk_windows.py:296-306`): 4624, 4648, 4625, 4688, 4720 y Sysmon 1, 3,
  11, 22.
- Si no hay EventCode conocido ni pista de sourcetype, la ultima red es
  `if first(record, "user", "Account_Name"): return _logon(record, True)` (`splunk_windows.py:335`).
- Como casi todo evento de Windows trae `Account_Name`, esa red se lo traga todo. Ejecutado:
  **4104** (`IEX DownloadString`), **7045** (servicio desde `C:\Windows\Temp\m.exe`), **4672**
  (`SeDebugPrivilege`) y **1102** (borrado del log de seguridad) salen los cuatro como
  `Authentication / act=logon / status=success / severity=2`, con la arista `user -authenticated-> host`.
- Un borrado de log (defense-evasion) se convierte en un login sano de severidad 2, que ademas es lo primero
  que filtra cualquier umbral.
- Splunk es el unico normalizador que **nunca llama a `parse_severity`**: todas las severidades son literales
  (`splunk_windows.py:111-113,155,194,239,261,279`). `urgency` de ES, `Severity` del TA y `RiskScore` se
  ignoran, y `CLASS_FINDING` ni siquiera se importa: los notables de ES no tienen donde caer.

### 3.5 Sentinel/Defender, QRadar y el generico

- Sentinel cubre 10 tablas (`sentinel_defender.py:338-349`). Todo lo demas se reclama y luego se abandona
  (`:352-357`), cae a generic y pierde la atribucion. Fuera quedan `DeviceRegistryEvents`,
  `IdentityLogonEvents`, `IdentityDirectoryEvents`, `AuditLogs`, `OfficeActivity`, `CloudAppEvents`,
  `CommonSecurityLog` y `Syslog`.
- **Y lo que sale es peor que perder el dato**: al caer a generic, `cef.normalize` busca la hora en
  `first(record,'time','timestamp','@timestamp','rt','_time','start')` (`cef.py:276`) y ninguna de esas
  claves existe en una tabla de Microsoft, que usa `TimeGenerated`. Ejecutado con `DeviceRegistryEvents`
  (persistencia en `CurrentVersion\Run`): sale `class=Detection Finding`, `source=generic`, **time = la hora
  actual** en vez de la del evento, un nodo alerta sin etiqueta y cero aristas. Es el bug de fechas que ya se
  corrigio para CEF (comentario en `base.py:87-89`), reaparecido por otra puerta.
- QRadar no puede emitir `CLASS_DNS` **nunca**: `dns` esta en `_NET_WORDS` (`qradar_events.py:84`) y las
  listas se evaluan en orden. Tampoco `CLASS_EMAIL` ni `CLASS_ACCOUNT`. El QID, que es la clave real de la
  taxonomia, no se usa para clasificar: solo como `origin` (`qradar_events.py:147`).
- Un login fallido de QRadar sin `destinationip` y con log source que "huele a producto" se queda **sin
  ninguna arista**: `extract._authentication` calcula `target = dst_key or device_key`
  (`extract.py:229-234`) y ambos son None. Ejecutado con `User Login Failure` magnitud 8 desde
  45.132.88.17: entidades `[user:jlopez, ip:45.132.88.17]`, relaciones `[]`.
- El payload base64 de Ariel se decodifica en `qradar_events.py:180-183` y se guarda en
  `raw['_payload_decoded']`. **No hay ni un solo lector** en todo el repo: se hace el trabajo y se tira.

### 3.6 Formatos que hoy ni siquiera se trocean

- El sniffer de csv acepta coma, punto y coma, tabulador y barra vertical (`detect.py:111`) pero **nunca
  llega a ejecutarse** para TSV ni para `;`: la deteccion previa exige comas (`detect.py:45-47`).
- Comprobado: un TSV con cabecera `time`/`user`/`src` separada por tabuladores se detecta como syslog y
  produce registros basura con una sola clave `message`. Lo mismo con un CSV cuya cabecera lleve un `=`, con
  logs clave=valor (Fortinet, SonicWall, Cisco ASA sin CEF) y con EVTX exportado a XML.
- ECS/Elastic es peor que perder el dato: `SourceId` admite `elastic` (`models.py:26`), la ontologia le da
  color (`ontology.py:192`) y `_unwrap` sabe desenvolver `hits.hits[]._source` (`detect.py:61-63`), pero
  **no existe normalizador**. Ejecutado: se crean nodos con el diccionario serializado como identidad,
  `host:{'name': 'wks-0421'}` y `user:{'name': 'jlopez'}`. Es corrupcion de los identificadores canonicos
  que `canon_host`/`canon_user` existen para garantizar.

### 3.7 Campos del modelo que no se usan

Conteo real de accesos `event.<campo>` en `graph/`, `report/`, `threat/` y `api/`:

| Campo | Accesos | Estado |
| --- | --- | --- |
| process | 44 | usado a fondo |
| file / dst / uid | 27 / 26 / 17 | usados |
| origin | 1 | solo en `extract.py:347`, y solo para Detection Finding |
| class_uid | 0 | decorativo (`models.py:158-160`) |
| mac | 0 | ningun normalizador lo escribe (`models.py:83`) |
| os | 0 escritores | lo lee `extract.py:136`, siempre None |
| session_id | 0 lectores | lo escribe solo `splunk_windows.py:122` |

`session_id` es el unico hilo que permitiria correlacionar 4624 con 4634/4688 del mismo logon, y se tira.
Sin `class_uid` el "subconjunto de OCSF" que promete `models.py:5-7` no es exportable a ningun data lake.

### 3.8 El `uid` no deduplica lo que dice deduplicar

- `make_uid` (`models.py:253-262`) hashea `source|json(raw)` y su docstring dice que sirve para deduplicar
  el mismo evento llegado por dos caminos.
- Es imposible que funcione: el uid lleva el prefijo de la fuente y el hash del crudo entero, distinto en
  cada SIEM por definicion. Probado: el mismo hecho como registro Splunk y como fila Defender da
  `52bf5da2c62dbd52` frente a `5ce09926484ad4ac`.
- El recuento de eventos por nodo (`build.py:96`) queda inflado en las fuentes solapadas.

### 3.9 La ontologia declara lo que ningun normalizador puede producir

- `ENTITIES` define 13 tipos (`ontology.py:26-40`); `extract.py` emite 10.
  Muertos: `account` (`:37`), `registry` (`:39`) y `url` (`:34`, solo viaja como prop del nodo dominio en
  `extract.py:211`).
- `RELATIONS` define 20 (`ontology.py:122-143`); `extract.py` emite 17.
  Muertas: `triggered` (`:135`), `downloaded` (`:140`) y `read` (`:132`, requiere `activity='read'`, que
  ningun normalizador escribe).
- Estan tambien en `web/js/ontology.js:44`, o sea que aparecen en la leyenda del frontend sin poder
  aparecer jamas en el grafo.

### 3.10 Plan de familias de log, por orden

**Fase 0, cerrar el contrato antes de anadir familias** (esfuerzo bajo, valor alto). Sin esto, cada familia
nueva se anade a ciegas:

1. `Activity` como `Literal` cerrado en `models.py` con los valores hoy dispersos, y formato acordado de
   `origin`: `fabricante:producto:stream` (`microsoft:defender:DeviceProcessEvents`, `windows:security:4104`).
2. `normalize/base.py:29-57`: prioridades distintas (splunk 10, ecs 15, sentinel 20, qradar 30, generic 99),
   `logging.warning` en el `except` que hoy se traga las excepciones, `raw['_normalizer']` y
   `raw['_claimed_by']`, y contadores por normalizador en `/api/meta`.
3. `cef.py:238-239`: que el matcher de generic exija al menos dos senales utiles (tiempo real + host, o
   src + dst, o proceso). Si solo produciria una alerta vacia fechada ahora, que devuelva `None`. Asi
   `unmatched` deja de ser estructuralmente 0.
4. `make_uid` con huella semantica (time truncado a segundo + class_name + `canon_user` + `canon_host` +
   `process.path` o `file.sha256` o `dst.ip`), guardando el hash del crudo en `raw['_raw_uid']`.
5. `tests/test_normalize.py`: tabla linea a linea de `samples/perimeter.cef` con clase, entidades y aristas
   esperadas, mas un test que fije el orden de `registry()`.

| Orden | Familia | Esfuerzo | Valor | Por que ahi |
| --- | --- | --- | --- | --- |
| 1 | Windows completo (Security ampliado, Sysmon, registro, servicios) | alto | alto | `threat/detect.py:310-405` solo lee `process.cmdline` y `message`: sin ella no hay motor |
| 2 | Identidad y cloud (Entra, MDI, CloudTrail, Okta) | alto | alto | Es por donde entra el atacante; hoy cobertura cero fuera de `SigninLogs` |
| 3 | ECS + formatos sin trocear (kv, TSV, EVTX XML) | medio | alto | Palanca mas barata: ECS es el sobre de todas las demas |
| 4 | Perimetro (DNS, proxy, cortafuegos) con bytes | medio | alto | Es donde esta el C2 y la exfiltracion, y es lo peor clasificado hoy |
| 5 | VPN y acceso remoto | medio | alto | Unico log que ata IP publica + usuario + IP interna |
| 6 | Correo (phishing, clics, reglas de buzon) | medio | alto | `CLASS_EMAIL` solo lo produce Sentinel hoy |
| 7 | Copias de seguridad | medio | alto | La etapa `inhibit` del motor solo dispara con cmdline; Veeam por consola no deja ninguna |
| 8 | Bases de datos | medio | medio | Unica familia que puede dar vida a la relacion `read` |
| 9 | Kubernetes y contenedores | alto | medio | Depende de que el cliente tenga cargas en contenedores |

Ampliaciones de modelo que estas familias exigen, y que conviene disenar de una vez:
`RegRef(key, value_name, value_data, operation)` mas `CLASS_REGISTRY`; `AuthRef(protocol, mfa, mfa_method,
conditional_access, risk_level, result_code, client_app)`; `ResourceRef(type, name, id, region, account)`
reutilizable por cloud, copias, BD y Kubernetes; `NetRef(bytes_in, bytes_out, protocol, action, rule)`;
`SessionRef(id, assigned_ip, start, end)`; y en `EmailRef`, `network_message_id`, que es la clave con la que
Microsoft une correo, URL, adjunto y clic, y hoy no se guarda.

---

## 4. Seguridad del canal

Antes de nada, dos encuadres honestos que cambian la severidad y que la verificacion adversarial corrigio:

- **Hoy el bind es de loopback**: `tools/run.ps1:75` arranca con `--host 127.0.0.1`, y los ejemplos de
  `docs/` y `wiki/` usan uvicorn sin `--host`, que tambien es loopback. No estamos ante una API abierta a
  internet: estamos ante la **ausencia de una frontera de privilegio en local**. Sigue justificando todo lo
  que viene, pero no hay que venderlo como exposicion a la red.
- **El vector cross-site si es real y no depende del bind**: no hay CORS ni tokens anti-CSRF, y una peticion
  simple `multipart/form-data` no lleva preflight. Cualquier pagina que visite el analista puede lanzar a
  ciegas `POST /api/reset` o `POST /api/ingest` contra `http://localhost:8000`. No leera la respuesta, pero
  el efecto de escritura ya se produjo.

### 4.1 MINIMO 1: cerrar la lectura arbitraria de ficheros

Es el incendio. Todo lo demas de esta seccion es defensa en profundidad.

La cadena completa, verificada end-to-end con `SETTINGS.allow_file_paths=False`:

1. `POST /api/query {'connector':'files','query':'.env'}` lleva a `routes_ingest.py:264-269` y a `files.py:42`.
2. `files.py:50`: `is_sample = _within(target, SAMPLES_DIR) or not target.is_absolute()`. La segunda
   condicion declara "muestra" a **toda ruta relativa** y se salta la puerta de la linea 52.
3. `files.py:59-61`: si `SAMPLES_DIR/basename` no existe, `target = Path(path).resolve()`, resolucion contra
   el **CWD del proceso**, que es la raiz del repo con `run.bat`.
4. `parse_syslog` (`cef.py:180`) acepta cualquier linea de texto y la guarda entera en `_raw`.
5. `GET /api/events` la devuelve linea a linea.

Resultados medidos:

| Llamada | Resultado |
| --- | --- |
| `read_path('.env.example')` | 36 registros |
| `read_path('glamdring/config.py')` | 128 registros |
| `read_path('../../../../../Windows/win.ini')` | 7 registros |
| `read_path('/Windows/win.ini')` | 7 registros |
| `read_path('../../../../../Windows/System32/drivers/etc/hosts')` | 20 registros |
| `POST /api/query` con esa ruta | 200, `{'read':20,...}` |
| `POST /api/ingest` con `path=../../../../../Windows/win.ini` | 200, `{'read':7,...}` |
| `read_path` con ruta absoluta con unidad (`C:` + `\Windows\win.ini`) | 400, unica variante bloqueada |

Con el proceso arrancado desde la raiz del repo, `path='.env'` entrega `SPLUNK_TOKEN`, `QRADAR_TOKEN` y
`AZURE_CLIENT_SECRET`. Y con ellos, permiso de busqueda sobre todo el SIEM del cliente.

**Tres correcciones al diseno del parche que la verificacion obliga a incorporar:**

1. **No apoyarse en `is_absolute()`.** En Windows devuelve `False` tambien para rutas con raiz pero sin
   unidad: `/Windows/win.ini`, la misma con barras invertidas, y `C:Windows/win.ini` (relativa a unidad) son
   todas "no absolutas". En Windows **no hace falta ni un solo `../`** para pasar la puerta. En POSIX esa
   misma cadena si es absoluta. Ese predicado no significa lo que parece.
2. **El dano lo consuma la linea 61, no la 50.** Si se arregla la clasificacion de la 50 pero se conserva el
   fallback `Path(path).resolve()`, el agujero sigue abierto. Hay que eliminarlo y comprobar la contencion
   **sobre la ruta ya resuelta**, en el unico punto donde se fija `target`.
3. La linea 60 antepone `SAMPLES_DIR / Path(path).name`. Si el basename coincide con una muestra existente
   (`perimeter.cef`, `qradar_ariel.json`, `sentinel_defender.json`, `splunk_windows.json`) gana la muestra y
   la travesia se queda en nada. **No es una mitigacion**: es solapamiento por nombre, y explica por que un
   PoC mal elegido podria parecer que no funciona.

Forma correcta del arreglo: resolver primero, decidir despues.

```python
base = SAMPLES_DIR.resolve()
raw = Path(path)
if raw.is_absolute() or raw.drive or raw.root:   # cubre 'C:\...', '/x' y '\x'
    target = raw.resolve()
else:
    cand = (base / raw).resolve()
    target = cand if cand.exists() else (base / raw.name).resolve()
try:
    target.relative_to(base)
    is_sample = True
except ValueError:
    is_sample = False
if not is_sample and not SETTINGS.allow_file_paths:
    raise ConnectorError(...)
```

`relative_to()` sobre rutas **ya resueltas** neutraliza `..` y enlaces simbolicos, que es lo que el `_within`
actual (`files.py:88-94`) no consigue porque se aplica a `target` antes de resolverlo.

Resto de la medida:

- `/api/demo` y `/api/incidents/load` siguen funcionando: pasan rutas absolutas bajo `SAMPLES_DIR`. El mismo
  tratamiento hace falta en `routes_ingest.py:194` y `:234`.
- Cuando `allow_file_paths` si este activo, no abrir el disco entero: nueva `GLAMDRING_FILE_ROOTS` (lista de
  directorios) y aceptar solo si `_within(target, root)` para alguno. Sin esa variable, `allow_file_paths=1`
  no habilita nada.
- **Rechazar `files` en `/api/query`** (`routes_ingest.py:253`): no hay razon funcional para que la ruta de
  consulta a SIEM en vivo acepte el conector de disco.
- El campo `path` de `/api/ingest` (`routes_ingest.py:103-105`) solo se acepta con `allow_file_paths`; si no,
  400 fijo sin tocar el disco.
- Unificar los mensajes de `files.py:53` y `files.py:64` en uno solo ("Ruta no disponible") con el mismo
  codigo: hoy el endpoint es un **oraculo de existencia de rutas**.
- Tests de regresion en `tests/test_api.py` con las siete rutas de la tabla de arriba.

### 4.2 MINIMO 2: autenticacion en toda la superficie HTTP

Estado: **no existe**. Verificado con la alternacion correcta (el `grep` del diseno original iba sin `-E`, y
en BRE la barra vertical es literal: habria dado 0 aciertos aunque el codigo estuviera lleno de `Depends()`):

```
grep -rnE 'Depends|HTTPBearer|HTTPBasic|APIKey|Security\(|add_middleware|middleware=|@app\.middleware|dependencies=|fastapi\.security|Authorization|X-API-Key' glamdring/ web/
```

Cero aciertos de autenticacion entrante. En runtime: `app.router.dependencies == []`, `app.user_middleware
== []`, **28 rutas** y 0 con `security` en el OpenAPI generado. Entre ellas `POST /api/ingest`,
`POST /api/reset`, `POST /api/query`, `POST /api/incidents/load`, `PUT /api/appearance`,
`POST` y `DELETE /api/appearance/model/{name}`, `GET /api/export` (6.079 bytes de logs sin credencial) y
`GET /openapi.json` (26.161 bytes con el mapa completo).

**Correccion importante al remedio.** Poner `dependencies=[Depends(...)]` en `FastAPI()` o en los
`include_router` **no cierra la superficie**. Medido sobre una replica de `main.py`:

| Ruta | Con `dependencies=` | Dependencia ejecutada |
| --- | --- | --- |
| `/api/meta` | 401 | si |
| `/config/models/m.glb` (mount, `main.py:89`) | 200 | **no** |
| `/` y `/index.html` (mount, `main.py:93`) | 200 | **no** |
| `/openapi.json` | 200 | **no** |
| `/docs`, `/redoc`, `/docs/oauth2-redirect` | 200 | **no** |

Motivo: `dependencies=` vive en `app.router.dependencies` y solo lo consumen los `APIRoute`. Los `app.mount()`
son `Mount` de Starlette, y los docs se registran con `self.add_route(...)` en
`fastapi/applications.py:1120, 1137, 1144, 1158`, que crea `Route` planos. **El hueco son 2 mounts mas 4
rutas de docs**, no solo los mounts.

**Segunda correccion, que produce un fallo que se leera como bug:** un middleware ASGI **no puede lanzar
`HTTPException`**. Corre por fuera de `ExceptionMiddleware`, asi que devuelve **500** en cada peticion. Hay
que devolver la respuesta:

```python
return await PlainTextResponse("no auth", status_code=401)(scope, receive, send)
```

Con esa variante, medido: 401 en las ocho rutas probadas, `/config/models/m.glb`, `/index.html` y
`/noexiste` incluidas.

Medida completa:

1. `glamdring/security.py` con `PRINCIPALS` cargados de un fichero (usuario a hash Argon2/bcrypt, mas rol)
   cuya ruta viene de `GLAMDRING_USERS_FILE`. Nunca contrasenas en el `.env`.
2. **Middleware ASGI** registrado con `app.add_middleware`, no `dependencies=`. Allowlist minima: `/` y los
   estaticos del login. `/api/health` tambien autenticado: hoy filtra que conectores hay configurados.
3. Sesion de navegador: `POST /api/login`, comparacion con `hmac.compare_digest`, cookie firmada con
   `SessionMiddleware`, `HttpOnly=True`, `Secure=True`, **`SameSite='Strict'`** y `max_age=8h`.
   `SameSite=Strict` mas comprobacion de `Origin`/`Sec-Fetch-Site` es lo que mata el vector CSRF descrito
   arriba. Sin eso, la cookie cierra la lectura y deja las rutas mutantes igual de alcanzables.
4. Automatizacion: `Authorization: Bearer <token>`, tokens en `GLAMDRING_TOKENS_FILE` guardados como sha256,
   con ambito `ingest` (solo escribir) o `read`.
5. Dos roles: `analyst` (leer, ingerir, informar) y `admin` (apariencia, subida de `.glb`, `/api/reset`,
   `/api/ingest-log`). Motivo concreto: `/api/reset` destruye el trabajo de otro y la subida de `.glb`
   escribe en un directorio servido como estatico bajo el mismo origen (`main.py:88-89`).
6. `main.py:59-68`: `docs_url=None, redoc_url=None, openapi_url=None` salvo `GLAMDRING_DEV=1`. Con
   `openapi_url=None` FastAPI tampoco monta `/docs`. Es defensa en profundidad: hoy esas cuatro rutas
   dependerian por completo de que el middleware exista y sea correcto.
7. `glamdring/__main__.py` como punto de entrada soportado: si `--host` no es loopback y no hay fichero de
   usuarios ni de tokens, el proceso se niega a arrancar.
8. `web/js/api.js`: `request()` y `download()` con `credentials:'same-origin'` y redireccion al login ante
   401. Es el unico fichero del frontend que hay que tocar.

### 4.3 MINIMO 3: limite de cuerpo y aislamiento del proceso

**El 413 llega tarde para el disco.** `_leer_acotado` (`routes_ingest.py:53-78`) esta bien escrito y acota la
RAM en trozos de 1 MB hasta `MAX_UPLOAD_BYTES = 200 MB` (`:20`). Pero para cuando el handler lee, Starlette ya
ha escrito el cuerpo entero en disco.

Verificado en `starlette/formparsers.py`:

- Linea 147: `spool_max_size = 1024 * 1024`. Linea 230: `SpooledTemporaryFile(max_size=self.spool_max_size)`.
- Medido: 1.048.576 bytes se quedan en RAM; **1.048.577 bytes hacen rollover** al directorio temporal del
  usuario. El rollover ocurre **siempre antes** de que empiece `_leer_acotado`.
- Lineas 181-188: `max_part_size` solo se aplica en la rama `self._current_part.file is None`. Y el
  discriminante no es "campo frente a fichero": es la **mera presencia del parametro `filename`**
  (`on_headers_finished`, linea 225). Medido: una parte con `filename=""` de 20 MB **se acepto**. El tope de
  1 MB sobre campos de formulario es honorifico frente a un cliente hostil.
- Lo unico que sigue en pie son los topes de cantidad: `max_files=1000`, `max_fields=1000`.

Precision sobre el modo de fallo: el impacto es **agotamiento del volumen temporal y de E/S**, no un OOM.
Si se describe como "el proceso se queda sin memoria", la frase es falsa y el revisor puede descartar el
hallazgo entero por ahi.

**Correccion al remedio.** Es cierto que uvicorn 0.52.4 no tiene ninguna opcion de tamano de cuerpo
(`--limit-concurrency` y `--limit-max-requests` son otra cosa; medido: 80 MB aceptados con ambas puestas, en
`h11` y en `httptools`). Pero de ahi **no** se sigue que el proxy sea la unica via: starlette 1.6.0, la que
ya esta instalada, trae `starlette/middleware/body_limit.py` con `RequestBodyLimitMiddleware`, que responde
413 y corta acumulando `total_size`.

Trampa verificada: **FastAPI 0.141.1 no reexporta `max_body_size`**. `FastAPI(max_body_size=1024*1024)` no
lanza `TypeError` ni avisa: lo traga por `**extra` y el limite **se ignora en silencio** (medido: cuerpo de
40 MB devuelve 200). Hay que montarlo a mano:

```python
from starlette.middleware.body_limit import RequestBodyLimitMiddleware
app.add_middleware(RequestBodyLimitMiddleware, max_body_size=200 * 1024 * 1024)
```

Dos rutas que el limite de cuerpo **no** arregla y que son de codigo:

- `routes_appearance.py:70-73`: `payload = await file.read()` **entero** y solo despues
  `if len(payload) > MAX_MODEL_BYTES` (25 MB). Es literalmente el antipatron que el docstring de
  `_leer_acotado` describe como el fallo que ya arreglaron. Sigue sin arreglar, y esa via si es RAM.
- `routes_report.py:65`: `MAX_IMAGE_BYTES` se comprueba sobre `text` cuando Pydantic ya ha parseado el JSON
  entero en memoria.

Aislamiento, para cualquier despliegue que no sea el portatil del analista:

- Proxy inverso obligatorio con `client_max_body_size 200m`, `limit_req_zone` a 10 r/s con burst,
  `proxy_read_timeout 150s` (por encima de los 120 s de `GLAMDRING_QUERY_TIMEOUT`), certificado real y HSTS.
  Sin TLS delante, la autenticacion del punto anterior se regala en el primer sniffer.
- uvicorn detras con `--host 127.0.0.1 --proxy-headers --forwarded-allow-ips 127.0.0.1`, para que la IP real
  llegue al registro de auditoria.
- **`TMPDIR`/`TEMP` propio y acotado**, porque ahi es donde Starlette derrama la subida. `PrivateTmp=yes` en
  systemd lo consigue solo. El usuario dedicado necesita un TEMP propio con cuota, no el compartido.
- Unidad systemd con `NoNewPrivileges=yes`, `ProtectSystem=strict`, `ProtectHome=yes`, `LimitCORE=0`,
  `MemoryMax=4G`, `TasksMax=64`, `ReadWritePaths=/var/lib/glamdring` y **`WorkingDirectory=` explicito**
  (defensa en profundidad para toda la familia de bugs de resolucion contra el CWD).
- Salida de red restringida por firewall a los hosts del SIEM y a `login.microsoftonline.com`.

### 4.4 MINIMO 4: credenciales fuera del `.env` y del entorno

`config.py:38` ejecuta `os.environ.setdefault(key, value)` por cada linea valida del `.env` (la 32 filtra
vacias, comentarios y lineas sin `=`). Confirmado que llega al bloque de entorno **Win32 real**, no solo al
dict de Python: `GetEnvironmentVariableW('SPLUNK_TOKEN')` devuelve el valor.

**Dos justificaciones del diseno original son falsas y hay que sustituirlas, no repetirlas:**

- **La herencia a subprocesos no aplica aqui.** Barrido de `subprocess`, `Popen`, `os.system`, `os.spawn`,
  `multiprocessing` y `startfile` sobre todo el proyecto: **cero coincidencias**. GLAMDRING no lanza ningun
  subproceso. El unico hijo real es el de `uvicorn --reload`, y va al reves: la app se carga en el **hijo**,
  asi que el padre vigilante nunca importa `glamdring.config` y su entorno esta limpio.
- **`/proc/PID/environ` no contiene estos secretos.** Ese fichero es la foto del `execve(2)`; `putenv`, que
  es lo que hace `os.environ.__setitem__`, escribe en el heap de libc y no lo toca. La via por
  `/proc/environ` es precisamente la unica que **no** da los tokens. Ademas la plataforma real del proyecto
  es Windows (`run.bat`, `.venv/Scripts/`): `/proc` no existe.

**Version correcta de la premisa:** los secretos quedan **residentes en el bloque de entorno del proceso
durante toda su vida**, donde son legibles por (a) cualquier dependencia importada, que solo necesita leer
`os.environ` y ve hasta las claves huerfanas que la configuracion no usa, (b) un volcado de memoria o crash
dump, (c) la lectura del PEB desde otro proceso del mismo usuario, y (d) cualquier traza que serialice el
entorno.

Y una advertencia para no cerrar el agujero a medias: **borrar la linea 38 no saca las credenciales del
proceso**. `SETTINGS` (`config.py:162`) las guarda en claro como atributos de dataclass durante toda la vida
del proceso: `SETTINGS.splunk.token`, `SETTINGS.splunk.password`, `SETTINGS.sentinel.client_secret`,
`SETTINGS.qradar.token`. Un volcado sigue exponiendolas.

Medidas:

1. **Eliminar `os.environ.setdefault`** (`config.py:38`). `load_dotenv()` ya devuelve el dict `loaded`; que
   `_env()` consulte primero `os.environ` y despues ese dict. Cinco lineas. Alternativa comprobada: hacer
   `pop` de las claves sensibles tras construir `Settings`, porque **ningun conector lee `os.environ`**, todos
   leen `SETTINGS` (`splunk.py:27`, `qradar.py:34`, `sentinel.py:34`).
2. **`chmod 600` del `.env` y documentarlo.** `.env.example` esta en modo **0644** y tanto el README como
   `docs/CONNECTORS.md` dicen "copia este fichero a `.env`": en Linux un `cp` conserva 644 y el fichero con
   los tres tokens queda legible por **cualquier usuario de la maquina**. Es estrictamente peor que el
   escenario que se describia. Arreglo inmediato e independiente del resto.
3. **Bug fail-open del parser del `.env`, arreglar ya.** No se recortan comentarios en linea, y el propio
   `.env.example` ensena ese estilo (`GLAMDRING_QUERY_TIMEOUT=120       # segundos por consulta al SIEM`).
   Medido: `SPLUNK_VERIFY_TLS=1       # comentario` produce el valor crudo `'1       # comentario'` y
   `_env_bool(...) = False`. **Un comentario en linea desactiva silenciosamente la verificacion TLS contra
   Splunk.** `_env_int` degrada de forma benigna al default; `_env_bool` no. Arreglo: cortar el valor en el
   primer espacio seguido de almohadilla antes del `strip()`, en `config.py:36`.
4. `glamdring/secrets.py` con `SecretProvider` y tres backends: `env` (solo desarrollo, con aviso al
   arrancar), `file` (0600, leido una vez) y `vault` (`azure-keyvault-secrets` con `ManagedIdentityCredential`).
   `load_settings()` (`config.py:130-158`) pide al provider en vez de a `os.environ`.
5. **Sentinel sin secreto**: `sentinel.py:76-78` ya cae a `DefaultAzureCredential`. Documentar identidad
   administrada o federacion de credenciales como via recomendada y dejar `AZURE_CLIENT_SECRET` como ultimo
   recurso. Es el unico conector donde se puede llegar a cero secretos almacenados.
6. **Splunk: prohibir Basic** salvo `SPLUNK_ALLOW_BASIC=1`. Hoy `config.py:71` acepta la configuracion con
   solo usuario y contrasena, y eso manda la contrasena en cada consulta; el propio `.env.example:12-14` lo
   admite y aun asi lo ofrece. Si hay token **y** pareja, ignorar la pareja y avisar en el log.
7. Rotacion: token de Splunk a 90 dias, service principal de Azure a 90 o sin secreto, token de QRadar (que
   no caduca solo) con procedimiento trimestral. Guardar `GLAMDRING_CRED_ROTATED_AT` y que `/api/health`, ya
   autenticado, avise al admin a 14 dias.
8. Minimo privilegio por credencial: Splunk con rol de busqueda limitado a los indices del caso; Sentinel con
   `Log Analytics Reader` sobre un solo workspace; QRadar con lectura Ariel y nada mas.
9. Test que compruebe que ninguna respuesta de la API contiene los valores configurados, `/api/health` y el
   informe HTML incluidos.

### 4.5 MINIMO 5: TLS hacia el SIEM

- `SPLUNK_VERIFY_TLS` y `QRADAR_VERIFY_TLS`, ambas con default `True` (`config.py:66`, `:91`), se pasan tal
  cual a httpx (`splunk.py:75`, `qradar.py:65`).
- Sentinel **no tiene bandera** (`sentinel.py:121` crea el cliente sin `verify`): hereda `True` y no se puede
  desactivar. Dejarlo asi.
- `.env.example:15-17` y `docs/CONNECTORS.md:29` describen el caso mas habitual (Splunk on-prem autofirmado) y
  ofrecen como **unica salida documentada** poner 0.

Por que importa: `verify=False` en httpx no solo ignora la cadena, tambien desactiva la comprobacion del
nombre de host. Lo que se entrega al primer intermediario es el token de servicio del SIEM en claro. Y el
flujo de vuelta queda manipulable: un atacante puede borrar del resultado los eventos que le incriminan y el
analista construye el grafo sobre datos amanados sin ningun indicio.

- No existe termino medio, aunque httpx acepta un `SSLContext` sin cambio de tipo.
- Nada en el codigo avisa cuando la verificacion esta apagada: un despliegue con TLS off es indistinguible de
  uno seguro mirando la salida del servidor.

Medidas:

1. Sustituir el booleano por tres valores: `SPLUNK_TLS_CA` (ruta a un PEM), `SPLUNK_TLS_FINGERPRINT` (sha256)
   y, como ultimo recurso, `SPLUNK_VERIFY_TLS=0`. Idem QRadar.
2. Helper compartido `glamdring/connectors/tls.py` con `ssl.create_default_context(cafile=cfg.tls_ca)`, pasado
   como `verify=<SSLContext>`. En httpx 0.28 pasar una cadena esta **deprecado** y emite `DeprecationWarning`.
3. Para el autofirmado on-prem, la recomendacion operativa es **fijado de certificado sin codigo adicional**:
   usar el propio certificado del servidor como `cafile`. Verificacion completa de cadena y de nombre contra
   exactamente ese certificado. Cuesta un fichero y es estrictamente mejor que `VERIFY_TLS=0`.
4. mTLS donde el SIEM lo soporte: httpx acepta `cert=(certfile, keyfile)`.
5. **Hacer ruidoso el modo inseguro**: `log.warning` al arrancar nombrando el host, `"tlsVerified": false` en
   `public_status()` y pintado en la interfaz, marca visible en el informe generado, y exigir
   `GLAMDRING_INSECURE_TLS_ACK=<host>` coincidente, para que un 0 heredado de un `.env` copiado no desactive
   nada por inercia.
6. Reescribir `.env.example:15-17` y `docs/CONNECTORS.md:29` para que el camino documentado sea el CA propio.
   Para proxies que inspeccionan TLS, la via es `SSL_CERT_FILE` con la CA corporativa, no desactivar nada.

### 4.6 MINIMO 6: tachado de secretos por valor, no por nombre de clave

- `store.py:23-27` define `_SECRET_KEYS` y `store.py:34-50` lo aplica, pero **solo** en la rama de diccionario
  y **solo** contra `str(key)` (`store.py:45`). Los valores y el texto libre pasan sin tocar.
- El docstring (`store.py:36-39`) dice que se tacha porque "los logs de autenticacion a veces arrastran
  credenciales en la linea de comandos o en cabeceras". **Ese es justamente el caso que no cubre.**
- Comprobado: ingiriendo `.env.example` por el vector de ruta, el store guarda
  `{'_raw': 'SPLUNK_TOKEN=<valor>', 'message': 'SPLUNK_TOKEN=<valor>'}` **sin redactar**, porque las claves son
  `_raw` y `message`.
- `store.py:41` corta en `depth > 6` y devuelve el subarbol **tal cual**: basta anidar el secreto siete
  niveles para que sobreviva aun con la clave correcta.

Esto no es teorico: el informe HTML "circula por correo" segun `routes_report.py:22-23`. Un `_raw` con
`net use` mas `/user:admin` y la contrasena, un cmdline con `-Password` o una cabecera `Authorization` citada
dentro de un mensaje salen por `/api/events`, por `/api/export` y dentro de ese informe.

Medidas (media tarde de trabajo):

1. Rama para `str` en `redact()`: `CLAVE=VALOR` y `CLAVE: VALOR` donde CLAVE case en `_SECRET_KEYS`;
   `/user:X PASS`; `-Password X` y `-AsPlainText`; `Authorization: <esquema> <blob>`; JWT
   (`eyJ[A-Za-z0-9_-]{10,}\.`); PEM (`-----BEGIN ... PRIVATE KEY-----`); `AKIA[0-9A-Z]{16}`; `xox[baprs]-`.
   Sustituir **solo el trozo del secreto**, no la linea entera, para que el evento siga siendo legible.
2. `store.py:41`: al pasarse de profundidad, devolver `REDACTED` o podar, nunca el original.
3. Tachar tambien el `origin`: `routes_ingest.py:274` guarda los primeros 80 caracteres de la SPL/KQL/AQL del
   analista y `routes_ingest.py:99` mete `file.filename` tal cual. `redact()` sobre el origin antes de
   `STORE.add()`, y saneado del filename a `[A-Za-z0-9_.-]{1,120}`.
4. Metrica: contar valores tachados por ingesta. Test que ingiera un fichero con las ocho formas de secreto y
   compruebe que ninguna sale por `/api/events`, `/api/export` ni el HTML del informe.
5. Decir en el docstring lo que el tachado **no** es: una red de seguridad, no un control. El control es no
   ingerir el fichero equivocado, y ese lo da el minimo 1.

### 4.7 Deseable despues del minimo

**Ciclo de vida del dato: particion por caso y TTL** (esfuerzo alto, valor alto).

- `store.py:2-6` asume "un proceso, una investigacion, un analista en su portatil". `docs/APPEARANCE.md:4`
  describe un despliegue de equipo donde "el sysadmin fija el estandar". Las dos lecturas no son compatibles
  y el codigo solo soporta la primera.
- `STORE` es una instancia unica (`store.py:160`) sin clave de sesion: dos analistas comparten cubo,
  cualquiera lee el incidente del otro y cualquiera lo borra con `/api/reset`.
- No hay TTL: lo ingerido vive hasta `/api/reset` o hasta que muera el proceso.
- `/api/ingest-log` (`routes_meta.py:54-57`) filtra de forma anonima la consulta que escribio el analista y
  las rutas ingeridas, o sea sobre que se esta investigando. Verificado:
  `origin='files:../../../../../Windows/System32/drivers/etc/hosts'`.
- Medida: `CASES: dict[str, EventStore]` con owner y `last_touch`; `case_id` por cookie o cabecera; tarea de
  TTL en el `lifespan` (`main.py:38-56`); `/api/reset` solo para el dueno o admin; ruta explicita de "cerrar
  caso" que devuelva acuse con recuento, para poder decirle al cliente **cuando** se destruyeron sus datos.
- **El borrado al cerrar el caso si es minimo imprescindible**: no se puede aceptar el log de un cliente sin
  poder decir cuando deja de existir. La particion por caso se puede posponer con un solo analista.

**Validacion de entrada** (esfuerzo medio, valor medio). El contraste es el hallazgo: el proyecto **sabe**
validar y lo hace bien en `/api/incidents/load` (`routes_ingest.py:184-189`), en la subida de `.glb`
(comprueba cabecera glTF y no la extension, `routes_appearance.py:67-78`) y en la data-URL del informe
(`routes_report.py:24`, `:58-67`). Y no valida nada en las dos rutas que reciben los datos mas sensibles.

- `routes_ingest.py:32`: `limit: int = Field(default=10_000, ge=1, le=50_000)`.
- `routes_graph.py:39`: `le=SETTINGS.max_graph_nodes`, para que `MAX_GRAPH_NODES` sea un limite y no un valor
  por defecto. Hoy `maxNodes=99999999` devuelve 200 y serializa el grafo entero.
- `format_hint` contra un conjunto cerrado `{json, ndjson, csv, cef, leef, syslog}`: hoy un hint desconocido
  cae al camino cef/syslog (`detect.py:85`) en vez de rechazarse.
- `normalize_all` (`normalize/base.py:60-68`) como generador consumido con `itertools.islice` hasta el hueco
  libre real del store, en vez de materializar la lista completa antes de que `store.py:125` aplique
  `MAX_EVENTS`. Y `store.py:132` reordena la lista entera en cada `add()`: muchas ingestas pequenas degradan
  el proceso de forma cuadratica.
- Profundidad de JSON: `json.loads` es recursivo y un JSON muy anidado produce `RecursionError`, que hoy sale
  como 500. Capturarlo como 400.
- Comprimidos: si se anaden `.gz` (los analistas exportan asi a menudo), leer a trozos con contador y abortar
  por encima de `MAX_UPLOAD_BYTES` descomprimidos o ratio 100:1. ZIP no.
- Comprobar `Content-Type` en `/api/ingest` y `/api/query`.

**Trazabilidad** (esfuerzo medio, valor medio). Hoy no hay forma de responder "quien consulto que y cuando":
solo queda el log de acceso de uvicorn y el registro de ingestas del store, que guarda las 50 ultimas
entradas en RAM (`store.py:141-143`), se pierde al reiniciar y no dice quien hizo nada.

- `glamdring/audit.py` como middleware ASGI registrado **despues** del de autenticacion, con una linea JSON
  por peticion a `/api`: instante UTC, `request_id`, principal y rol, IP real (de `X-Forwarded-For`), metodo,
  ruta, `case_id`, conector, consulta ya pasada por `redact()`, recuento, codigo y duracion.
- Linea por cada uso de credencial al abrir el cliente httpx (`splunk.py:75`, `qradar.py:65`,
  `sentinel.py:121`): conector, host destino, si TLS estaba verificado y **que** credencial (identificador,
  jamas el valor).
- El fichero de auditoria no debe vivir donde la aplicacion pueda reescribirlo: `chattr +a`, journald o el
  registro de eventos de Windows.
- Retencion mas larga que la del corpus (un ano), y **solo metadatos**: nunca contenido de eventos, o el
  registro de auditoria se convierte en la segunda copia de los datos del cliente.
- Una version basica (principal, ruta, consulta) es parte del minimo en cuanto haya un contrato de por medio.

**Invertir el sentido del tunel** (esfuerzo alto, valor medio). Es la arquitectura objetivo, no del minimo.

- Hoy el modelo es de extraccion: GLAMDRING abre conexiones salientes hacia el SIEM del cliente
  (`splunk.py:78`, `qradar.py:72`, `sentinel.py:134`) y custodia una credencial de larga duracion con permiso
  de busqueda sobre **todo** el SIEM.
- Un compromiso de esta herramienta se convierte en acceso de lectura al SIEM completo del cliente: un dano
  mucho mayor que el corpus del caso.
- Alternativa: colector dentro de la red del cliente que **empuja** a `POST /api/cases/{case_id}/events` con
  un token de ambito `ingest` sin permiso de lectura. Reutiliza `splunk.py`/`qradar.py`/`sentinel.py` tal cual
  como biblioteca: ya son clases con `fetch()` asincrono y sin dependencias del servidor web. La credencial
  del SIEM no sale del perimetro del cliente.
- Si la extraccion es inevitable, tunel WireGuard/Tailscale publicando **solo** el puerto de la API del SIEM.
  Regla que no se negocia: el tunel es transporte, no autenticacion; dentro se mantienen el TLS verificado y
  el token.
- En ningun caso exponer GLAMDRING hacia la red del cliente: el sentido va siempre del cliente hacia nosotros.

---

## 5. Que hacer primero

### 5.1 Antes de tocar datos de un cliente (bloqueante)

| # | Medida | Esfuerzo | Ficheros |
| --- | --- | --- | --- |
| 1 | Cerrar la lectura arbitraria de ficheros (resolver antes de decidir, matar el fallback de `files.py:61`, rechazar `files` en `/api/query`) | bajo | `connectors/files.py:48-61`, `api/routes_ingest.py:103-105`, `:253` |
| 2 | Autenticacion por **middleware ASGI** que devuelve `Response`, mas `docs_url=None` y cookie `SameSite=Strict` | medio | nuevo `security.py`, `main.py:59-75`, `web/js/api.js` |
| 3 | Limite de cuerpo: `RequestBodyLimitMiddleware` en proceso **y** `client_max_body_size` en el proxy; arreglar `routes_appearance.py:70` | bajo/medio | `main.py`, `routes_appearance.py:70-73`, config del proxy |
| 4 | Quitar `os.environ.setdefault` (`config.py:38`), `chmod 600 .env`, prohibir Basic en Splunk, cortar comentarios en linea en `config.py:36` | bajo | `config.py:36`, `:38`, `:71` |
| 5 | TLS hacia el SIEM: `TLS_CA`/`fingerprint` en vez del booleano, y `WARNING` ruidoso si se apaga | medio | `config.py:66`, `:91`, nuevo `connectors/tls.py` |
| 6 | `redact()` que mire valores y texto libre, y `depth>6` que pode en vez de devolver el original | bajo | `store.py:34-50` |
| 7 | Borrado verificable al cerrar el caso, con acuse y recuento | medio | `store.py:150-156`, `routes_ingest.py:279-283` |

Nota de alcance: el punto 5 solo aplica si se va a usar algun conector en vivo. Si solo se ingieren ficheros
exportados, no aplica.

### 5.2 Justo despues, por valor sobre esfuerzo

1. **Fase 0 de normalizacion** (esfuerzo bajo): vocabulario cerrado de `activity`, prioridades distintas,
   logging en el arbitraje, matcher de generic exigente y `make_uid` semantico. Sin esto, cada familia nueva
   se anade a ciegas y no habra forma de demostrar que algo se clasifica bien.
2. **`limit: ge=1`** y `maxNodes: le=` (esfuerzo trivial, dos lineas): hoy `limit=0` significa "sin limite"
   en Splunk.
3. **Contrato v2 del conector** (`FetchResult` con `truncated` y `cursor`, mas `ping()`): es requisito de la
   paginacion, del refresco en vivo y de respetar cualquier `Retry-After`.
4. **`asyncio.to_thread` en `sentinel.py:82`**: es el fallo mas caro de la capa de conectores y bloquea el
   refresco en vivo.
5. **Tests que fijen la clasificacion** linea a linea sobre `samples/perimeter.cef`, mas el primer
   `tests/test_connectors.py` con respx (la dependencia ya esta declarada).
6. **Conector Defender XDR/MDE**: valor alto con coste de normalizador cero.
7. **`GET /api/pivot`**: cierra el bucle de investigacion y no toca la capa de conectores.
8. **Familias de log 1 a 4** (Windows completo, identidad y cloud, ECS mas formatos sin trocear, perimetro).

### 5.3 Lo que no sabemos y hay que medir antes de decidir

- **Coste real de las familias 7 a 9** (copias, BD, Kubernetes): depende por completo del stack del cliente.
  No hay dato para estimarlo aqui.
- **Volumen tipico de una investigacion**: `MAX_EVENTS = 500.000` (`store.py:31`) y el reordenado cuadratico
  de `store.py:132` no se han medido con carga real.
- **Si el equipo destino usa Sentinel con SDK o via REST**: cambia por completo la prioridad del arreglo del
  event loop.
- **Comportamiento del parser de `.env` en Linux**: las comprobaciones se hicieron en Windows. La logica es
  la misma, pero los permisos del `.env` copiado con `cp` no se han verificado en un despliegue real.
- **Impacto de `RequestBodyLimitMiddleware` sobre las subidas legitimas grandes**: probado con cuerpos
  sinteticos, no con un export real de 150 MB.