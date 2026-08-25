<!-- Especificacion del vocabulario cerrado de activity.
     Sale de una auditoria en la que cada afirmacion se comprobo EJECUTANDO
     codigo sobre las muestras reales, y despues paso por un verificador cuyo
     encargo era tumbarla. De 45 hallazgos, 6 se cayeron ahi. -->

# Vocabulario cerrado de `activity` para GLAMDRING

## 0. Estado medido hoy (base de partida)

Censo real de `normalize_all` + `extract` sobre las cuatro muestras (52 eventos):

| activity | splunk | cef/generic | qradar | sentinel | total |
|---|---|---|---|---|---|
| `launch` | 9 | 1 | 0 | 2 | 12 |
| `logon_failed` | 4 | 2 | 1 | 1 | 8 |
| `connect` | 2 | 3 | 4 | 2 | 11 |
| `create` | 2 | 2 | 1 | 1 | 6 |
| `logon` | 1 | 1 | 1 | 1 | 4 |
| `alert` | 0 | 0 | 0 | 3 | 3 |
| `blocked` | 0 | 2 | 1 | 0 | 3 |
| `logon_remote` | 1 | 0 | 0 | 1 | 2 |
| `query` | 1 | 0 | 0 | 0 | 1 |
| `create_account` | 1 | 0 | 0 | 0 | 1 |
| `deliver` | 0 | 0 | 0 | 1 | 1 |

Emitibles pero no ejercitados por las muestras: `delete` (cef.py:351, sentinel:190), `modify` (sentinel:190), `unknown` (default). Consumido pero **nunca emitido**: `read` (extract.py:293) — rama muerta.

**Total real: 14 valores, sin definicion, sin unicidad y con la misma cosa en tres nombres.**

---

## 1. Los tres principios (cada uno respaldado por una medicion)

**P1 — El desenlace no es una activity; va en `status`.**
Medido: colapsando `blocked`→`connect` y `logon_failed`→`logon` dejando `status` intacto, sobre los 11 eventos que los llevan, el resultado de `extract()` (nodos + aristas), la frase de `narrative.describe()` y `is_key_event()` son **identicos en los 11 casos. Cero diferencias.** `extract.py:270` ya hace `activity == "blocked" or status == "failure"`, y `extract.py:232` ya hace `status == "failure" or activity == "logon_failed"`: la informacion esta duplicada y nunca discrepa (medido: `blocked` y `logon_failed` tienen `status='failure'` en el 100% de los casos). Son dos nombres que no ganan nada y que rompen la correlacion entre SIEM.

**P2 — Un valor solo existe si cambia un nodo, una arista o una frase.**
Contraprueba: `logon_remote`→`logon` **si** cambia la salida — la arista pasa de `('host:wks-0421','lateral','host:srv-dc01')` a `('host:wks-0421','connected',...)` y la frase pierde "que es la firma del movimiento lateral". Por eso `logon_remote` se queda y `blocked` se va.

**P3 — El valor es unico en todo el vocabulario, no dentro de su clase.**
Hoy `create` significa a la vez fichero creado, consulta DNS (CEF/Umbrella) y deteccion de antivirus (QRadar). Filtrar por activity obliga a filtrar tambien por clase. Con prefijo por objeto, `activity` es filtrable por si sola.

---

## 2. La lista cerrada — 34 valores

### 2.1 Authentication — `CLASS_AUTHENTICATION` (3002)

| valor | definicion | nodo / arista que produce |
|---|---|---|
| `logon` | Inicio de sesion local o interactivo en el equipo que lo registra. | `user` + `host`; arista `authenticated` (o `failed_auth` si `status=failure`). |
| `logon_remote` | Inicio de sesion iniciado desde otra maquina de la red (tipos 3 y 10, RemoteInteractive, SSH aceptado). | Ademas: `src`→`dst` con arista **`lateral`** si `status=success`. Es el unico valor que la dibuja. |
| `logon_explicit` | Autenticacion con credenciales distintas a las de la sesion actual (4648, runas, sudo, PsExec). | `user` = la cuenta **usada**, `dst` = servidor destino; arista `authenticated` hacia el destino. |
| `logoff` | Cierre de sesion (4634, 4647). | `user` + `host`, arista `authenticated` sin peso. Nunca `lateral`, nunca MITRE. |
| `auth_ticket` | Peticion o renovacion de ticket Kerberos (4768/4769, IdentityLogonEvents). | `user` + `service`/`host`; arista `authenticated`. |

### 2.2 Account Change — `CLASS_ACCOUNT` (3001)

| valor | definicion | nodo / arista |
|---|---|---|
| `account_create` | Se crea una cuenta de usuario o de servicio. | `user` + `host`, arista `persisted`. |
| `account_modify` | Cambio de contrasena, de atributos o de estado (alta/baja) de una cuenta. | idem. |
| `account_delete` | Se elimina una cuenta. | idem. |
| `group_member_add` | Una cuenta se anade a un grupo (4728/4732: Domain Admins). | `user` + `group`; arista `member_of`. Es escalada de privilegios, no un `account_modify` mas. |

### 2.3 Process Activity — `CLASS_PROCESS` (1007)

| valor | definicion | nodo / arista |
|---|---|---|
| `process_launch` | Creacion de proceso. | `process` (anclado al host) + `parent`; aristas `spawned`, `executed`, `ran_on`. |
| `process_terminate` | Fin de proceso (Sysmon 5). | `process` + `host`, arista `ran_on`. |
| `process_inject` | Un proceso escribe o crea un hilo en el espacio de otro (Sysmon 8, T1055). | **Dos** nodos `process` (Source/Target) + arista `injected_into`. |
| `process_access` | Un proceso abre un handle sobre otro (Sysmon 10; `GrantedAccess 0x1410` sobre lsass.exe = T1003.001). | **Dos** nodos `process` + arista `accessed`. |
| `module_load` | Carga de DLL o imagen en un proceso (Sysmon 7, DeviceImageLoadEvents). | `process` + `file`/`hash`, arista `loaded`. |

### 2.4 File System Activity — `CLASS_FILE` (1001)

| valor | definicion | nodo / arista |
|---|---|---|
| `file_create` | Se escribe un fichero nuevo en disco. | `file` (+`hash`); aristas `wrote`, `has_hash`, y **siempre** `host`↔`file`. |
| `file_modify` | Se altera el contenido o los metadatos de un fichero existente (incluye timestomp, Sysmon 2). | arista `modified`. |
| `file_delete` | Se borra un fichero (Sysmon 23, T1070.004). | arista `deleted`. |
| `file_read` | Se abre un fichero para lectura o se accede a su contenido. | arista `read`. Hoy `extract.py:293` ya lo espera y nadie lo emite. |
| `file_upload` | **SASE**: subida de fichero a una aplicacion cloud. | `file` + nodo `service` (de `event.app`); arista `uploaded_to`. |
| `file_download` | **SASE**: descarga desde una aplicacion cloud o desde la web. | arista `downloaded_from`. |
| `file_share` | **SASE**: se concede acceso a un fichero cloud (enlace publico, invitado externo). | `file` + `service` + `user` destinatario; arista `shared_with`. |

### 2.5 Registry Value Activity — `CLASS_REGISTRY` (**nueva**, uid OCSF 201003)

`models.py` no tiene esta clase, pero `enrich.py:48` **ya declara `"registry"` en `CONTEXT_TYPES`**: la ontologia lo contempla y `extract.py` no crea ese nodo en ningun sitio (verificado: cero apariciones de `registry` en extract.py).

| valor | definicion | nodo / arista |
|---|---|---|
| `registry_set` | Se crea o modifica una clave/valor de registro (Sysmon 12/13, DeviceRegistryEvents; Run keys = T1547.001). | nodo `registry:<hive\ruta>` + `process`; arista `persisted`. |
| `registry_delete` | Se borra una clave o valor. | arista `deleted`. |

### 2.6 Network Activity — `CLASS_NETWORK` (4001)

| valor | definicion | nodo / arista |
|---|---|---|
| `network_connect` | Conexion o flujo entre dos extremos, permitida o denegada segun `status`. | `src`/`dst` (`ip` o `domain`); arista `connected` o `blocked` segun `status`. |
| `tunnel_open` | **SASE/VPN/ZTNA**: se establece una sesion de tunel. | `user` + `service` + `ip`; arista `tunneled_to`. |
| `tunnel_close` | Fin de esa sesion. | idem, sin peso. |

**No se crea `network_traffic` para el volumen.** Los 700 MiB de `bytessent` no son un tipo de actividad distinto: son un campo que `NormalizedEvent` no tiene. Inventar una activity para llevarlos seria meter un dato en el nombre. La solucion es `bytes_in`/`bytes_out` en el modelo y en las props de la arista (que ya admite extras: hoy lleva `port`).

### 2.7 DNS Activity — `CLASS_DNS` (4003)

| valor | definicion | nodo / arista |
|---|---|---|
| `dns_query` | Resolucion de un nombre, con o sin respuesta. | nodo `domain` + `src`; arista `resolved_by`. La IP **respondida** (nunca el resolutor) va a `domain`→`ip` `resolved`. |

Un unico valor. `dns_response` no existe: la respuesta es un campo, no un hecho distinto.

### 2.8 Email Activity — `CLASS_EMAIL` (4009)

| valor | definicion | nodo / arista |
|---|---|---|
| `email_deliver` | El correo llega al buzon (`DeliveryAction=Delivered`; `Blocked` = mismo valor con `status=failure`). | `mailbox` origen y destino; aristas `sent_to`, `owns`, `contains_url`. |
| `email_quarantine` | El correo se entrega neutralizado o desviado (`Junked`, `Replaced`). No es exito ni fallo: es un tercer desenlace que `Status` (`success`/`failure`/`unknown`) no sabe expresar. | idem, severidad rebajada. |
| `email_access` | Acceso a elementos del buzon (CloudAppEvents `MailItemsAccessed`, T1114). | `user` + `mailbox`, arista `read`. |

### 2.9 Detection Finding — `CLASS_FINDING` (2004)

| valor | definicion | nodo / arista |
|---|---|---|
| `alert` | Un producto de deteccion o correlacion emite un hallazgo. | nodo `alert` + arista `affects` a todo lo que nombre. |
| `malware_detect` | Un AV/EDR identifica un artefacto malicioso. `status=failure` cuando la contencion fallo. | `alert` + `file` + `hash` + `host` + `user`, todos por `affects`. |
| `log_clear` | Se vacia un registro de auditoria (1102, `SecurityLogCleared`). Severidad minima 4. | `alert` + `host` + `user`, arista `affects`. |

### 2.10 Reservado

| valor | definicion |
|---|---|
| `unknown` | El normalizador reclamo el registro y no supo clasificarlo. **Es una senal de fallo, no un valor de trabajo**: debe contarse y exponerse en la ingesta, nunca llegar al grafo en silencio. |

---

## 3. Mapeo desde las cuatro fuentes de HOY

Solo filas con contenido real. `→` = de que valor actual viene.

| valor nuevo | Splunk / Sysmon | CEF / LEEF / syslog | QRadar | Sentinel / Defender |
|---|---|---|---|---|
| `logon` | 4624 (tipo 2/7/11) → `logon` | `Accepted password` sin IP remota → `logon` | `Login Success` → `logon` | SigninLogs → `logon` |
| `logon` (`status=failure`) | 4625 → `logon_failed` | sshd `Failed password` → `logon_failed` | `Multiple Login Failures` → `logon_failed` | `LogonFailed` → `logon_failed` |
| `logon_remote` | 4624 tipo 3/10 → `logon_remote` | **nuevo**: sshd `Accepted ... from <IP>` → hoy `logon` | `Login Success` con `sourceip` remota → hoy `logon` | RemoteInteractive/Network → `logon_remote`; **+`CachedRemoteInteractive`** (hoy cae a `logon`) |
| `logon_explicit` | **nuevo**: 4648 → hoy `logon` | — | — | — |
| `logoff` | **nuevo**: 4634/4647 → hoy `logon_remote` (con T1021 falso) | — | — | — |
| `auth_ticket` | 4768/4769 | — | — | IdentityLogonEvents (hoy sin handler) |
| `account_create` | 4720 → `create_account` | — | — | — |
| `group_member_add` | **nuevo**: 4728/4732 | — | — | — |
| `process_launch` | Sysmon 1 / 4688 → `launch` | proc con `process_name` → `launch` | `Process Create` → `launch` | DeviceProcessEvents → `launch` |
| `process_inject` | **nuevo**: Sysmon 8 → hoy `None` (0 nodos) | — | — | — |
| `process_access` | **nuevo**: Sysmon 10 → hoy `None` (0 nodos) | — | — | — |
| `module_load` | Sysmon 7 | — | — | DeviceImageLoadEvents (hoy sin handler) |
| `file_create` | Sysmon 11 → `create` | — | — | DeviceFileEvents `FileCreated` → `create` |
| `file_modify` | **nuevo**: Sysmon 2 | `delet`/otros → `modify` (rama viva, sin ejercitar) | — | `ActionType` con `modif` → `modify` |
| `file_delete` | **nuevo**: Sysmon 23 | `delet` en blob → `delete` | — | `ActionType` con `delete` → `delete` |
| `file_read` | — | — | — | — (hoy nadie lo emite) |
| `file_upload` / `download` / `share` | — | Zscaler/Netskope SASE (**futuro**) | — | CloudAppEvents (**futuro**) |
| `registry_set` | **nuevo**: Sysmon 12/13 → hoy `launch` | — | — | DeviceRegistryEvents (hoy sin handler) |
| `registry_delete` | **nuevo**: Sysmon 12 | — | — | idem |
| `network_connect` | Sysmon 3 → `connect` | Fortinet/Zscaler `accept` → `connect`; **LEEF PAN-OS C2** → hoy `launch` | `Firewall Permit`, `Proxy Allowed`, `Large Outbound Transfer` → `connect` | DeviceNetworkEvents → `connect` |
| `network_connect` (`status=failure`) | — | `deny` / `Web Request Blocked` → `blocked` | `Firewall Deny` → `blocked` | → `blocked` |
| `tunnel_open` / `tunnel_close` | — | SASE/VPN (**futuro**) | — | — |
| `dns_query` | Sysmon 22 → `query` | **Umbrella `DNS Request`** → hoy `create` (File System) | **InfoBlox `DNS Query`** → hoy `connect` (Network) | DeviceEvents `DnsQueryResponse` → `query` |
| `email_deliver` | — | — | — | EmailEvents `Delivered` → `deliver` |
| `email_quarantine` | — | — | — | **nuevo**: `Junked`/`Replaced` → hoy `deliver` |
| `alert` | — | alertas genericas → `alert` | ofensas → `alert` | SecurityAlert / SecurityIncident → `alert` |
| `malware_detect` | — | **Defender `Malware Detected`** → hoy `create` | **TrendMicro `Virus Detected`** → hoy `create` | DeviceEvents `AntivirusDetection` → hoy `query` (DNS) |
| `log_clear` | **nuevo**: 1102 | — | — | **nuevo**: `SecurityLogCleared` → hoy `query` (DNS, sev 1) |

---

## 4. Valores que DESAPARECEN

| desaparece | se traduce a | por que |
|---|---|---|
| `blocked` | `network_connect` + `status="failure"` | Medido: cero diferencia en nodos, aristas, frase e `is_key_event` sobre los 3 eventos. `extract.py:270` y `narrative.py:147` ya miran `status` en el mismo `or`. |
| `logon_failed` | `logon` / `logon_remote` + `status="failure"` | Medido: cero diferencia sobre los 8 eventos. `extract.py:232` ya lo trata como sinonimo de `status`. |
| `connect` | `network_connect` — **excepto** el `connect` de QRadar DNS, que va a `dns_query` | Renombrado por unicidad; la excepcion es el nucleo de la correlacion DNS. |
| `create` | `file_create` — **excepto** Umbrella (→`dns_query`), Defender y TrendMicro (→`malware_detect`) | Un mismo valor significaba hoy tres hechos distintos. |
| `launch` | `process_launch` — **excepto** el LEEF de PAN-OS con `cat=command-and-control` (→`network_connect`) | idem. |
| `query` | `dns_query` | Renombrado; absorbe los otros dos dialectos. |
| `create_account` | `account_create` | Orden `objeto_verbo`, coherente con el resto. |
| `deliver` | `email_deliver` | idem. |
| `delete` | `file_delete` | idem. |
| `modify` | `file_modify` | idem. |
| `read` | `file_read` | Hoy consumido en `extract.py:293` y emitido por nadie: rama muerta que pasa a estar viva. |
| `alert` | `alert` (se queda) | Ya es unico e idiomatico. |
| `unknown` | `unknown` (se queda) | Cambia de sentido: pasa de default silencioso a metrica de fallo. |

Saldo: **14 valores sin contrato → 34 con definicion, clase y nodo.** El crecimiento no es inflacion: 11 de los 34 cubren huecos donde hoy el evento se pierde entero o se clasifica al reves.

---

## 5. Lo que hay que tocar en `extract.py` para que esto rinda

Cuatro comprobaciones ejecutadas contra las muestras reales:

**A) `malware_detect` → `CLASS_FINDING` arregla los dos "jlopez creo m.exe" sin escribir codigo nuevo.** `_finding` ya cuelga la alerta de todo lo que el evento nombra. Medido, evento Defender de `perimeter.cef`:

- hoy: `[('user:jlopez','wrote','file:c:\windows\temp\m.exe'), (file,'has_hash',hash)]`, frase *"jlopez creo m.exe..."*, y **`host:srv-dc01` con grado 0**.
- propuesto: `alert --affects--> host:srv-dc01`, `--> user:jlopez`, `--> file:...m.exe`, `--> hash:b2c3...`, frase *"Se disparo la alerta «Malware Detected» sobre srv-dc01."*

Desaparece la arista `wrote` inventada y el DC queda conectado. Identico con el evento TrendMicro de QRadar (que ademas pasa de `status=success` a `failure`).

**B) `network_connect` para el C2 de PAN-OS: de 1 nodo suelto a 2 IP y 2 aristas.** Medido: hoy `nodos=['user:jlopez'], aristas=[]`; con `CLASS_NETWORK`/`network_connect`, `[('ip:10.4.2.11','connected','ip:45.132.88.17'), ('user:jlopez','authenticated','ip:10.4.2.11')]`.

**C) `dns_query` unifica el dominio y mata la arista `resolved` falsa.** Medido: Umbrella pasa de `nodos=['user:jlopez']` (frase *"jlopez creo un fichero en cdn-update-svc"*) a `['domain:cdn-update-svc.com']`; QRadar pierde la arista mentirosa `domain:cdn-update-svc.com --resolved--> ip:10.4.0.10` (el resolutor InfoBlox). Las tres fuentes convergen en la misma frase: *"10.4.2.11 resolvio el dominio cdn-update-svc.com."*

**D) Pero `_dns_activity` deja el dominio huerfano — hay que arreglarlo con el vocabulario.** Medido en los dos casos de (C): el nodo `domain` sale con **0 aristas**. Causa: `extract.py:304` enlaza `process_key or device_key` → dominio, y en un log de perimetro `device` es None mientras `event.src` si trae `10.4.2.11`. `_dns_activity` **nunca mira `event.src`**. Sin esa caida a `src`, unificar DNS produce un nodo de dominio bonito y desconectado, que es solo media mejora.

Ademas, para cerrar el vocabulario hacen falta tres cosas que hoy no existen en `extract.py`:
1. `CLASS_REGISTRY` en `_RULES` y un `_add_registry` que cree `registry:<hive\ruta>` — el tipo ya esta admitido en `enrich.CONTEXT_TYPES:48`.
2. Que `_file_activity` mire `event.app` y cree el nodo `service` para `file_upload`/`file_download`/`file_share` (hoy `service` solo lo crea `_authentication`).
3. Un `_add_process` de destino para `process_inject` y `process_access`: son los dos unicos valores con **dos** nodos `process` en un mismo evento.