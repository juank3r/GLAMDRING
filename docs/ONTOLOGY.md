# Ontología

Fuente de verdad: [`glamdring/graph/ontology.py`](../glamdring/graph/ontology.py).
El frontend la recibe por `GET /api/ontology` y sobrescribe su copia local, así que
**añadir un tipo se hace en un solo sitio**.

`model`, `shape` y `glyph` viven ahí a propósito: la decisión «un servidor se dibuja
como un rack» es semántica, no de presentación, y debe ser idéntica en el grafo, en
la leyenda y en el informe. El panel de administrador puede sobrescribirla, pero
para todo el equipo a la vez.

---

## Entidades (nodos)

| Tipo | Etiqueta | Color | Figura 3D | Clave canónica |
|---|---|---|---|---|
| `alert` | Alerta | `#ff2d55` | octaedro con anillo giratorio | `alert:<fuente>\|<uid>` |
| `user` | Usuario | `#4ea8ff` | figura humana con aro | `user:<usuario sin dominio, minúsculas>` |
| `host` | Host | `#4ade80` | puesto / rack / router / muro | `host:<hostname sin FQDN, minúsculas>` |
| `process` | Proceso | `#fb923c` | engranaje | `process:<host>\|<ruta en minúsculas>` |
| `file` | Fichero | `#d4a5ff` | hoja con esquina doblada | `file:<ruta en minúsculas>` |
| `ip` | IP | `#2dd4bf` | dispositivo genérico | `ip:<dirección>` |
| `domain` | Dominio | `#818cf8` | globo terráqueo | `domain:<fqdn en minúsculas>` |
| `hash` | Hash | `#94a3b8` | rejilla de cubos | `hash:<digest en minúsculas>` |
| `mailbox` | Buzón | `#f472b6` | sobre | `mailbox:<dirección>` |
| `account` | Cuenta cloud | `#22d3ee` | nube | `account:<id>` |
| `service` | Servicio | `#a3e635` | engranaje | `service:<nombre>` |
| `registry` | Registro | `#eab308` | llave | `registry:<clave>` |
| `url` | URL | `#a78bfa` | globo terráqueo | `url:<url>` |

Los colores están separados en matiz **y** en luminancia: la paleta anterior se
eligió a ojo y varios tonos se confundían a distancia, que es justo cuando hay que
poder distinguirlos. Y con figuras distintas el color deja de cargar con todo el
peso de la identificación.

## Papel en el incidente

El papel no es una propiedad del tipo sino del **contexto**, y es lo que decide qué
figura se dibuja. Lo calcula [`graph/enrich.py`](../glamdring/graph/enrich.py) sobre
el grafo ya montado.

| Papel | Color | Cuándo | Efecto en la figura |
|---|---|---|---|
| `hostile` | `#ff2d55` | externo + táctica de C2/exfiltración, o señalado por una alerta | figura **encapuchada** |
| `victim` | `#fb923c` | entidad propia con severidad ≥4 o táctica de impacto | alarma encendida |
| `suspicious` | `#eab308` | entidad propia con indicios sin confirmar | tono de aviso |
| `asset` | `#4ade80` | entidad propia sin hallazgos | figura tranquila |
| `neutral` | `#94a3b8` | artefacto forense de apoyo | sin acento |

Casos que el cálculo resuelve y que a ojo se escapan:

- Un buzón alojado en un dominio ya marcado como hostil **es del atacante**, aunque
  los buzones se consideren nuestros por defecto. Es lo que coloca a
  `billing@cdn-update-svc.com` del lado correcto.
- Un host tocado por una alerta no puede quedarse como activo sano aunque sus
  propios eventos sean informativos.
- Una IP RFC1918 **nunca** es hostil, por muy grave que sea el evento: será una
  víctima, pero no infraestructura del atacante.

## Clase de equipo

Para los `host` se deduce del hostname, y decide entre puesto de trabajo, rack,
router y cortafuegos: `srv`, `dc0`, `sql`, `exch` → servidor; `fw`, `asa`, `palo`,
`fgt` → cortafuegos; `rtr`, `gw`, `sw-`, `core-` → router; el resto, puesto.

Es una heurística de nomenclatura corporativa, no un inventario. Acierta en un parque
con convenciones y falla del lado seguro (puesto de trabajo) cuando no las hay; se
corrige desde el panel de administrador.

### Qué NO es un nodo

Decisión deliberada: convertir cada campo en nodo produce una bola de pelo ilegible.

- **Puertos, PIDs, ids de sesión** → propiedades del nodo o de la arista.
- **Cuentas de máquina** (`WKS-0421$`) y **cuentas de servicio de Windows**
  (`SYSTEM`, `NETWORK SERVICE`, `ANONYMOUS LOGON`) → se descartan en `canon_user`.
  Aparecen en todos los eventos y unirían el grafo por el sitio equivocado.
- **La IP de un host del que ya sabemos el hostname** → propiedad `ip` de ese host.
  El hostname es la identidad estable; la IP cambia. Si fueran dos nodos, la misma
  máquina aparecería partida en dos.

### Por qué los procesos se anclan al host

La clave de un proceso es `<host>|<ruta>`, no solo la ruta. Si fuera solo la ruta,
`powershell.exe` sería **un único nodo** compartido por todas las máquinas del
dominio, y el grafo diría que todo el parque está conectado entre sí. Anclado al
host, cada máquina tiene su propio `powershell.exe` y el movimiento lateral se ve.

---

## Relaciones (aristas)

`dashed` = relación inferida o contextual, no un hecho duro del log.
`weight` = peso en el cálculo de riesgo y en la distancia del layout.

Los colores exactos no se repiten aquí: viven en `RELATIONS`, en
[`graph/ontology.py`](../glamdring/graph/ontology.py). Duplicarlos en la
documentación solo garantiza que un día dejen de coincidir.

| Tipo | Etiqueta | Peso | Trazo | De → A |
|---|---|---|---|---|
| `triggered` | dispara | 5 | sólido | alert → * |
| `affects` | afecta a | 5 | sólido | alert → * |
| `lateral` | movimiento lat. | 5 | sólido | host → host |
| `spawned` | lanza | 4 | sólido | process → process |
| `persisted` | persiste en | 4 | sólido | user → host |
| `authenticated` | autentica en | 3 | sólido | user → host\|service |
| `executed` | ejecuta | 3 | sólido | user → process |
| `connected` | conecta con | 3 | sólido | process\|host → ip\|domain |
| `downloaded` | descarga | 3 | sólido | process → url |
| `failed_auth` | fallo login en | 2 | **discontinuo** | user → host |
| `wrote` | escribe | 2 | sólido | process → file |
| `deleted` | borra | 2 | sólido | process → file |
| `sent_to` | envía a | 2 | sólido | mailbox → mailbox |
| `contains_url` | contiene URL | 2 | **discontinuo** | mailbox → domain |
| `ran_on` | corre en | 1 | **discontinuo** | process → host |
| `read` | lee | 1 | **discontinuo** | process → file |
| `resolved` | resuelve a | 1 | **discontinuo** | domain → ip |
| `has_hash` | hash | 1 | **discontinuo** | file\|process → hash |
| `blocked` | bloqueado hacia | 1 | **discontinuo** | * → ip\|domain |
| `owns` | posee | 1 | **discontinuo** | user → mailbox |

El **trazo discontinuo no es decorativo**: marca las relaciones que son contexto o
inferencia y no un hecho duro del log. En forense esa es justo la distinción que no
se puede perder, y hasta ahora el dato estaba en la ontología y se ignoraba al
pintar: un hecho observado y una deducción salían exactamente iguales.

---

## Reglas de extracción

Una regla por clase de evento OCSF, en
[`glamdring/graph/extract.py`](../glamdring/graph/extract.py).

| Clase | Evento típico | Nodos | Aristas |
|---|---|---|---|
| `Authentication` | 4624 correcto | user, host, origen | `user −authenticated→ host`; `origen −connected→ host` |
| `Authentication` | 4624 tipo 3/10 con origen y destino | host, host | `hostA −lateral→ hostB` |
| `Authentication` | 4625 fallido | user, host | `user −failed_auth→ host` |
| `Process Activity` | 4688 / Sysmon 1 | user, host, proc, padre, hash | `padre −spawned→ proc`; `user −executed→ proc`; `proc −ran_on→ host`; `proc −has_hash→ hash` |
| `Network Activity` | Sysmon 3 / DeviceNetwork | host, proc, ip o dominio | `proc −connected→ destino`; `dominio −resolved→ ip` |
| `Network Activity` | firewall deny | host, ip | `origen −blocked→ ip` |
| `File System Activity` | Sysmon 11 | proc, file, hash | `proc −wrote→ file`; `file −has_hash→ hash` |
| `DNS Activity` | Sysmon 22 | proc, dominio, ip | `proc −connected→ dominio`; `dominio −resolved→ ip` |
| `Email Activity` | EmailEvents | mailbox ×2, user, dominio | `emisor −sent_to→ receptor`; `user −owns→ mailbox`; `mailbox −contains_url→ dominio` |
| `Account Change` | 4720 | user, host | `user −persisted→ host` |
| `Detection Finding` | SecurityAlert / ofensa | alert + todas sus entidades | `alert −affects→ *` |

---

## Severidad

Escala OCSF 0-6 comprimida a 0-5. Es lo único cálido de la interfaz: si algo está
naranja o rojo, importa.

| Nivel | Etiqueta | De dónde sale |
|---|---|---|
| 0 | Desconocida | sin dato |
| 1 | Informativa | por defecto |
| 2 | Baja | evento normal |
| 3 | Media | fallo de login, salida a IP pública, comando con técnica ATT&CK |
| 4 | Alta | `AlertSeverity=High`, magnitud QRadar 7-8, creación de cuenta |
| 5 | Crítica | `AlertSeverity=Critical`, magnitud QRadar 9-10 |

Traducciones en `parse_severity()`: palabras (Sentinel), magnitud 1-10 (QRadar),
0-10 (CEF) y syslog invertido (0 = emergencia).

**El redondeo es hacia arriba en los empates**, no el bancario de `round()`: en una
escala de riesgo hay que errar por exceso, y magnitud 9 de QRadar es crítica, no
alta.

La severidad se lee siempre a través de las pantallas, los pilotos y los halos de
las figuras, esté el grafo en el modo de color que esté.

---

## Tácticas MITRE

El orden de la lista **es** el orden de las capas de la kill-chain:

`reconnaissance` → `resource-development` → `initial-access` → `execution` →
`persistence` → `privilege-escalation` → `defense-evasion` → `credential-access` →
`discovery` → `lateral-movement` → `collection` → `command-and-control` →
`exfiltration` → `impact`

Si el SIEM ya etiqueta la técnica (Sentinel y Defender lo hacen), se usa la suya.
Si no, [`glamdring/mitre.py`](../glamdring/mitre.py) la infiere de la línea de
comandos: `powershell -enc` → T1027, `certutil -urlcache` → T1105,
`sekurlsa::logonpasswords` → T1003.001, `vssadmin delete shadows` → T1490…

Las reglas se recorren todas: `powershell -enc ... certutil -urlcache` merece T1027
**y** T1105.

---

## Añadir un tipo

1. Entrada en `ENTITIES` o `RELATIONS` de `glamdring/graph/ontology.py`.
2. Emitirla desde la regla que toque en `glamdring/graph/extract.py`.
3. Nada más. El frontend la recoge por `/api/ontology`, y la leyenda, los chips de
   filtro y los colores del grafo se actualizan solos.

---

## Fusiones: cuándo dos nodos son en realidad uno

Se aplican en [`graph/build.py`](../glamdring/graph/build.py) tras la agregación.
Todas comparten la misma regla de prudencia: **si hay ambigüedad, no se funde**,
porque unir dos cosas distintas es peor que dejarlas separadas.

| Fusión | Cuándo | Cuándo NO |
|---|---|---|
| `ip:X` → `host` | un host declara esa IP | dos hosts la reclaman (DHCP, NAT, inventario sucio) |
| `file` sin ruta → `file` con ruta | comparten hash | hay varias rutas con ese hash: son copias reales |
| `process` sin ruta → `process` con ruta | mismo host y mismo nombre de ejecutable | hay varias rutas con ese nombre — y esa ambigüedad **es** un hallazgo |

Sin la primera, `SRV-DC01` (que Splunk y Sentinel nombran por hostname) y `10.4.1.5`
(que QRadar y el firewall solo conocen por IP) serían dos nodos, y el grafo diría
que el tráfico sale de una máquina que no existe.

Para que funcione, los normalizadores de red adjuntan la IP local al equipo que
reporta: en una conexión saliente el origen **es** esa máquina, así que ahí se
aprende su dirección.
