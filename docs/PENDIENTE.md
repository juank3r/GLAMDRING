# Pendiente

Estado a 25 de agosto de 2026. Todo lo de abajo esta publicado en main y con los
380 tests en verde.

## Por donde se retoma: CEF, LEEF y syslog

Es lo siguiente, y ya esta el terreno mirado. `glamdring/normalize/cef.py`.

Cinco hallazgos altos, todos reproducidos (el detalle en
[HALLAZGOS-CLASIFICACION.md](HALLAZGOS-CLASIFICACION.md)):

1. **LEEF pierde la severidad.** `sev=8` sale como severidad 2 porque
   `CEF_KEY_ALIASES` no tiene entrada para `sev`, asi que `first(record,
   "cef_severity", "severity", "priority")` no encuentra nada y se cae al
   `3 if failure else 2`. El evento mas grave del fichero acaba siendo el mas
   facil de filtrar. Arreglo: anadir el alias.

2. **`parse_syslog` no vuelve a mirar el texto.** En
   `Failed password for invalid user administrator from 10.4.2.11` el usuario y
   la IP se quedan dentro de la cadena. Una fuerza bruta SSH seguida de login
   correcto -el patron mas reconocible que hay- no dibuja nada. Las tres lineas
   9, 10 y 11 de `samples/perimeter.cef` son exactamente eso.

3. **La escalera de palabras clasifica al reves.** El orden es AUTH, PROC,
   FILE, NET, y las listas se pisan:
   - `_FILE_HINTS` contiene `"malware"`, asi que la linea 6 (Umbrella,
     `DNS Request` con `cs1=Malware`) casa como FICHERO antes que como red y
     sale con activity `create`. Ni dominio ni aristas.
   - `_PROC_HINTS` contiene `"command"`, que casa con
     `cat=command-and-control`: la linea 8 (LEEF de PAN-OS, trafico C2) sale
     como `launch`. Se pierde la conexion 10.4.2.11 -> 45.132.88.17.

4. **`Malware Detected` sale como creacion de fichero.** Linea 7, Defender, con
   `act=quarantine_failed`. El informe lo redacta como "jlopez creo m.exe": el
   antivirus dice que NO pudo contenerlo y la herramienta lo cuenta como si el
   usuario hubiera creado un fichero. Tiene que ser `malware_detect` en
   `CLASS_FINDING` con status de fallo.

5. **Traducir al vocabulario cerrado**: `logon_failed` -> `logon` + status,
   `blocked` -> status, `connect` -> `network_connect`, `create` ->
   `file_create`, `launch` -> `process_launch`.

Aviso de un verificador que conviene tener presente: para la linea 6, poner
`CLASS_DNS` a secas **deja el dominio huerfano**, porque `event.domain` solo se
rellena desde `url` o desde `domain`/`dest_domain`/`query`, y Umbrella pone el
dominio en `dhost` -> `dest_host`. Son dos piezas: el orden de clasificacion y
alimentar `event.domain` desde `dest_host` cuando no es una IP.

Comprobacion util mientras se trabaja: cada linea de `samples/perimeter.cef` (son
11) tiene que caer en su clase. Faltan los tests que lo fijen linea a linea.

## Despues de CEF

- **QRadar** (`normalize/qradar_events.py`), 5 hallazgos altos: los bytes de
  `Large Outbound Transfer` se tiran; `Malware Detected Not Cleaned` sale como
  creacion de fichero con exito; el evento DNS fabrica una arista `resolved`
  FALSA en la que el dominio malicioso resuelve al servidor DNS interno de la
  empresa; y las categorias de la ofensa se convierten en tecnicas ATT&CK
  inventadas con ids del tipo `['MALWARE DETECTED'`.
- **Sentinel** (`normalize/sentinel_defender.py`), 3 hallazgos altos: la tabla
  `DeviceEvents` entera se clasifica como consulta DNS con severidad 1;
  `_guess_table` mira `RemoteIP` antes que `LogonType`, asi que un logon sin
  `Type` se convierte en conexion de red y pierde la cuenta; y seis tablas que
  `matches()` reclama no tienen handler.
- **Tests linea a linea** sobre las cuatro muestras.

## Lo unico que queda sin empezar

**Varios incidentes a la vez, y fusionar dos que resultan ser el mismo.**

El mapa esta hecho, y la mejor noticia es que la frontera de "un solo incidente"
es exactamente `glamdring/api/`, siete ficheros: nadie fuera de ahi importa
`STORE`, toda la capa de dominio recibe ya sus datos por parametro. El motor de
fusion tampoco hay que escribirlo -`_apply_alias` en `build.py:303`, y
`merge_events` en `build.py:384`, que esta escrita y hoy no la llama nadie-.

Lo que si es codigo nuevo: DETECTAR que dos incidentes son el mismo, la
TRAZABILIDAD del alias (hoy `_apply_alias` hace `nodes.pop()` y el nodo fundido
desaparece sin dejar constancia) y el DESHACER.

Y tres obstaculos que conviene tener delante antes de empezar, porque los tres
producen un grafo verosimil y equivocado, que es la peor clase de fallo que
puede tener esta herramienta:

1. **La deduplicacion por uid no sirve para fusionar.** `make_uid` es
   `sha256(source|json(raw))`, asi que dos exportaciones del mismo hecho dan uids
   distintos. Comprobado: el mismo evento como Splunk y como Sentinel da
   `5b84e48f...` y `8d60e61d...`. Fusionar dos casos solapados duplicaria los
   recuentos de las aristas, y ese numero es el que el analista lee como
   "400 logons".
2. **`assign_levels` y `enrich` propagan por vecindad.** Si los dos incidentes
   quedan unidos por un solo nodo compartido, la kill-chain de uno contamina las
   capas del otro y el grafo cuenta una historia que no ocurrio.
3. **`eventUids` esta truncado a 200** (`build.py:23`). Al fusionar se
   descartarian en silencio los del incidente perdedor, y con ellos la promesa de
   que todo nodo se puede contrastar con el log original.

Aparte, queda comprobar la API de ZPA (ambitos y paginacion), marcado como
pendiente en [PROXIES-SASE.md](PROXIES-SASE.md). Netskope y Zscaler ya estan: el
receptor de la fase 1 valia tal cual porque Cloud NSS admite cabeceras HTTP a
medida.

## Lo que quedo hecho

**Fase 1, completa.**

- La lectura de ficheros arbitrarios del servidor, cerrada. Leia el `.env` con
  los tokens de los SIEM.
- `limit` validado (`limit=0` llegaba a Splunk como `count=0`, que en su API
  significa SIN limite: pedias "nada" y te bajabas el indice entero).
- El `.env` ya no contamina el entorno del proceso.
- `redact()` tacha por FORMA del valor, no solo por nombre de clave.
- Contrato de conector v2: `FetchResult` con `truncated`, `total`, `cursor` y
  `warnings`; `ping()` de verdad; `close()` con el cliente reutilizado.
- Sentinel ya no congela el proceso entero hasta 120 segundos.
- Receptor `POST /api/receive/{fuente}`, con clave por fuente, comparacion en
  tiempo constante y limites de cuerpo y de ritmo.
- El aviso de grafo incompleto, en pantalla y persistente.
- El semaforo del SIEM comprueba de verdad en vez de mirar si hay un token.

**Fase 2, empezada.**

- Vocabulario cerrado de 34 actividades en `models.py`, con clase OCSF y el nodo
  que produce cada una.
- Los tres fallos del grafo: el proceso anclado al literal `'?'`, el fichero sin
  arista a su maquina y el cortafuegos como nodo suelto.
- Splunk entero: se acabo la red que mandaba a "inicio de sesion correcto"
  cualquier registro con `Account_Name`.

## Una cosa que no depende de mi

Los puertos 8000, 8001 y 8002 siguen ocupados por procesos huerfanos que no se
dejan cerrar desde una ventana normal. Desde una **como administrador**:

    taskkill /F /PID 23528 /PID 23892 /PID 17780
