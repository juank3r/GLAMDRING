# Conectores

Cómo dar de alta credenciales en cada fuente y qué consultas funcionan bien.

Todo se configura por `.env` (copia `.env.example`). **Nada de credenciales en el
código ni en el JSON del grafo.** `GET /api/health` dice qué conectores están
configurados, nunca con qué, y `GET /api/connectors/ping` los comprueba de verdad
y devuelve la latencia o el motivo del fallo.

> Sin ninguna credencial la herramienta funciona igual: ingesta ficheros exportados
> del SIEM, que es el caso más habitual porque casi ningún analista tiene acceso a
> la API.

## Hay dos vías de entrada, no una

Es la distinción que gobierna todo este documento, y no es un detalle de
implementación:

| Vía | Quién | Cómo |
|---|---|---|
| **Se consulta** | Splunk, Sentinel, QRadar, Netskope, ZPA | `POST /api/query` con un conector |
| **Empuja** | Zscaler ZIA, syslog, webhooks, HEC | `POST /api/receive/{fuente}` |

Un conector solo sabe *tirar* de datos. Hay fuentes que no se dejan: los logs web
de Zscaler ZIA **no salen por su API**, los empuja NSS. No es un capricho del
fabricante, es como funcionan también syslog y cualquier webhook. Por eso existe
el receptor, y por eso **no hay ni va a haber un conector de ZIA**.

---

## Splunk

### Credenciales

Token de servicio en **Settings → Tokens → New Token**. Basta con permiso de
búsqueda sobre los índices que vayas a consultar.

```ini
SPLUNK_URL=https://splunk.corp.local:8089    # puerto de gestión, no el 8000 de la web
SPLUNK_TOKEN=<pega-aqui-tu-token>
SPLUNK_VERIFY_TLS=1
SPLUNK_APP=search
```

`SPLUNK_VERIFY_TLS=0` solo si tu Splunk on-prem tiene certificado autofirmado **y**
sabes contra qué servidor estás hablando.

El token va con el esquema `Splunk`, no `Bearer`:
`Authorization: Splunk <token>`.

### Cómo consulta

`POST /servicesNS/-/{app}/search/jobs/export` con `output_mode=json`. La respuesta
es NDJSON, un objeto por línea; se descartan las de `preview: true` para no
duplicar resultados parciales.

Se usa modo export (equivalente a oneshot) porque para consultas acotadas de
investigación no merece la pena crear un job y sondearlo. Para búsquedas de horas
habría que pasar a `exec_mode=normal` con polling de
`/services/search/jobs/{sid}` — está anotado como límite conocido.

### Consultas que van bien

```spl
index=wineventlog EventCode IN (4624,4625,4648,4688,4720) host=WKS-0421 | head 5000

index=sysmon EventCode IN (1,3,11,22) | head 5000

index=wineventlog EventCode=4625 | stats count by Account_Name, Source_Network_Address
```

**No uses `| stats` ni `| table` si quieres grafo**: agregan y se pierden los campos
que alimentan las entidades. Deja los eventos crudos y agrega GLAMDRING.

Si tu TA de Windows usa nombres distintos (`TargetUserName` en lugar de
`Account_Name`), no pasa nada: los normalizadores prueban varios candidatos.

---

## Microsoft Sentinel / Log Analytics

### Credenciales

Service Principal con rol **Log Analytics Reader** sobre el workspace:

```powershell
az ad sp create-for-rbac --name glamdring-reader
az role assignment create --assignee <appId> --role "Log Analytics Reader" `
  --scope /subscriptions/<sub>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<ws>
```

```ini
SENTINEL_WORKSPACE_ID=00000000-0000-0000-0000-000000000000   # el Workspace ID, no el resource ID
AZURE_TENANT_ID=...
AZURE_CLIENT_ID=...
AZURE_CLIENT_SECRET=...
```

### Dos caminos

1. **SDK** (`azure-monitor-query` + `azure-identity`), si están instalados. Es la vía
   soportada y gestiona el refresco de token sola. Con `DefaultAzureCredential`
   también valen `az login` y managed identity, sin secreto en el `.env`.

   ```powershell
   pip install azure-monitor-query azure-identity
   ```

2. **REST** contra `api.loganalytics.io` pidiendo el token a Entra ID por
   client-credentials. Se usa automáticamente si los SDK no están, y necesita sí o
   sí las tres variables `AZURE_*`. Existe porque en entornos corporativos no
   siempre se pueden instalar los SDK de Azure.

Log Analytics añade una columna `Type` con el nombre de la tabla a cada fila, que es
justo lo que necesita el normalizador para saber qué está leyendo.

### Consultas que van bien

```kql
DeviceProcessEvents
| where Timestamp > ago(24h) and DeviceName == "wks-0421.corp.local"
| take 5000

DeviceNetworkEvents | where RemoteIP == "45.132.88.17" | take 2000

SecurityAlert | where TimeGenerated > ago(7d) | take 500

SigninLogs | where ResultType != 0 | summarize by UserPrincipalName, IPAddress, ResultType
```

`SecurityAlert.Entities` viene como **cadena JSON**, no como lista; el normalizador
la parsea y cuelga cada entidad de la alerta con una arista `affects`.

---

## IBM QRadar

### Credenciales

**Admin → Authorized Services → Add**, con permiso de lectura sobre Ariel.

```ini
QRADAR_URL=https://qradar.corp.local
QRADAR_TOKEN=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
QRADAR_API_VERSION=20.0
QRADAR_VERIFY_TLS=1
```

La cabecera `Version` es obligatoria y determina el esquema de respuesta, por eso se
fija por configuración en vez de dejarla al valor por defecto del servidor.

### Cómo consulta

Ariel no es síncrono. Tres pasos, todos dentro de `connectors/qradar.py`:

1. `POST /api/ariel/searches?query_expression=<AQL>` → devuelve `search_id`
2. polling de `GET /api/ariel/searches/{id}` hasta `status=COMPLETED`
3. `GET /api/ariel/searches/{id}/results` con cabecera `Range: items=0-N`

Si la AQL empieza por `offenses`, va por `/api/siem/offenses` en su lugar.

La ventana temporal solo se añade si la AQL **no** trae ya una cláusula propia:
si escribiste `LAST 2 HOURS` o un `START/STOP`, se respeta.

### Consultas que van bien

```sql
SELECT starttime, sourceip, destinationip, sourceport, destinationport,
       username, qidname(qid), categoryname(category), magnitude, payload
FROM events
LAST 24 HOURS
LIMIT 5000
```

Incluye siempre `qidname(qid)` y `categoryname(category)`: la taxonomía de QRadar es
lo más fiable para clasificar el evento, porque un mismo QID puede venir de cientos
de log sources distintos.

`magnitude` es lo que se traduce a severidad (escala 1-10 → 0-5); ya combina
credibilidad, relevancia y severidad del evento.

Para ofensas abiertas basta con `offenses`.

---

## Netskope

### Credenciales

Token de API v2 en el portal, con el ámbito acotado al tipo de evento que se vaya
a consultar (`/api/v2/events/dataexport/events/application`). **El ámbito se fija
al crear el token** y es el fallo más común: un token válido que devuelve 403
porque no cubre ese tipo.

```
NETSKOPE_URL=https://TENANT.goskope.com
NETSKOPE_TOKEN=
NETSKOPE_ITERATOR=glamdring
```

### Cómo consulta, y por qué es distinto

**Es un iterador con estado.** A Netskope no se le pide "dame lo que hay entre
estas dos fechas": se le pide "dame lo siguiente", y el servidor lleva la cuenta
por el nombre del iterador.

Eso tiene una consecuencia que hay que entender antes de tocarlo: **cada llamada
avanza el puntero.** Pedir dos veces con el mismo iterador no da los mismos
eventos, da los siguientes. No se puede reintentar como si fuera una lectura
inocua, y por eso el cursor se devuelve en `FetchResult` en vez de esconderlo.

De ahí también que el `ping` **no** use `next`: comprobar que el servicio responde
se habría llevado por delante un lote de eventos, y nadie sospecharía de la
comprobación.

Para investigar hacia atrás —que es lo normal en un SOC— hay modo por ventana
temporal, que sí es repetible, y se avisa de que no avanza el iterador.

> `NETSKOPE_ITERATOR` lleva un nombre propio y no uno genérico a propósito: dos
> herramientas con el mismo nombre **se pisan el puntero**, y cada una acaba viendo
> los eventos que la otra no vio. Si hay dos GLAMDRING contra el mismo tenant, uno
> distinto en cada uno.

### Consultas que van bien

| Consulta | Qué trae |
|---|---|
| `application` | La joya: la acción DENTRO de la aplicación cloud. Subir, descargar, compartir, con el fichero y los bytes |
| `alert` | DLP, malware, credenciales comprometidas, anomalías |
| `network` | Flujos del cliente SASE |
| `audit` | Cambios de configuración en el propio Netskope |

---

## Zscaler

Los dos productos se comportan de forma opuesta y conviene tenerlo claro:

### ZPA (aplicaciones privadas) — se consulta

```
ZPA_URL=https://config.private.zscaler.com
ZPA_CLIENT_ID=
ZPA_CLIENT_SECRET=
ZPA_CUSTOMER_ID=
```

Autenticación OAuth2 client-credentials contra `/signin`. Consultas:
`user_activity`, `user_status`, `app_connector_status`.

> **`expires_in` viene en MILISEGUNDOS**, no en segundos. Tratarlo como segundos
> da un token "válido" durante mes y medio y luego una racha de 401 que parecen un
> problema de credenciales y no lo son: el token llevaba caducado desde hacía rato
> y nadie lo renovaba. Hay test.

Los nombres de campo de la respuesta y el comportamiento de la paginación están
**pendientes de comprobar contra un ZPA real**: salen de la documentación pública.
El conector está escrito para fallar de forma legible si no cuadran —devuelve un
aviso en vez de cero eventos en silencio—, porque cero eventos y cero eventos que
no supimos leer se ven igual en pantalla.

### ZIA (salida a Internet) — empuja

No hay conector. En el portal de ZIA, *Administración > Nanolog Streaming Service
> Cloud NSS Feed*:

```
API URL:   https://TU-GLAMDRING/api/receive/zscaler
Cabecera:  X-Glamdring-Key = <la clave de la fuente>
```

y la clave se declara en `.env`:

```
GLAMDRING_RECEIVE_KEYS=zscaler:<clave>
```

> **Cloud NSS viene desactivado** en ZIA. Si no aparece la opción hay que abrir un
> caso con el soporte de Zscaler. Conviene saberlo antes de prometer fechas: no es
> un interruptor que se active solo.

NSS emite en el formato que se le configure; se aceptan su JSON y su CEF.

---

## El receptor

`POST /api/receive/{fuente}`, con la clave de esa fuente en `X-Glamdring-Key`.

```
GLAMDRING_RECEIVE_KEYS=netskope:<clave>,zscaler:<clave>
GLAMDRING_RECEIVE_MAX_BYTES=52428800
GLAMDRING_RECEIVE_PER_MINUTE=120
```

Genera cada clave con:

```powershell
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Quien empuja no es una persona con un navegador: es un proceso que reintenta solo.
Por eso los códigos importan más de lo normal:

| | |
|---|---|
| **401** | Clave o fuente incorrecta. No reintentes, arregla la clave |
| **413** | Envío demasiado grande. Trocéalo |
| **429** | Demasiados envíos. Reintenta más tarde |
| **503** | Receptor sin configurar. No reintentes |

Lo que rechaza, y por qué:

- **Una clave POR FUENTE**, no una global: se revoca la de un reenviador sin tocar
  las demás.
- **Comparación en tiempo constante.** La comparación normal de cadenas para en el
  primer byte distinto, así que tarda un poco más cuanto más acierta quien prueba.
  Sobre un endpoint alcanzable por red, eso deja sacar la clave carácter a carácter.
- **Una fuente que no existe devuelve 401, no 404**, y con el *mismo* mensaje que
  una clave mala. Distinguirlos convertiría el receptor en un listado de qué
  integraciones tiene montadas la empresa.
- **Se autoriza antes de leer el cuerpo.** Al revés, cualquiera sin clave podría
  hacernos tragar 50 MB por envío hasta tumbar el proceso.
- **Claves de menos de 24 caracteres se descartan** con aviso. Aceptar `test`
  dejaría un endpoint que *parece* protegido, que es lo peligroso.
- **Sin ninguna clave el receptor no existe.** No hay modo "sin clave" ni para
  pruebas: uno abierto en un portátil acaba copiado tal cual a un servidor.

---

## Ficheros

El conector que más se usa. Acepta:

| Formato | Detección |
|---|---|
| JSON | array, o envoltorio con `results` / `events` / `value` / `records` / `data` / `hits` / `tables` |
| NDJSON | un objeto por línea |
| CSV | separador detectado con `csv.Sniffer` (`,` `;` tab `\|`) |
| CEF | `CEF:0\|vendor\|product\|...`, con escapes y valores con espacios |
| LEEF | 1.0 y 2.0, con delimitador declarado en el cabecero |
| syslog | RFC5424 y RFC3164; si el mensaje lleva CEF/LEEF dentro, gana el interior |

Tres vías: arrastrar al lienzo, botón **Subir logs**, o `POST /api/ingest` con
`file`, `text` o `path`.

`path` está **desactivado por defecto**. Activarlo (`GLAMDRING_ALLOW_FILE_PATHS=1`)
convierte el endpoint en una lectura de ficheros arbitrarios del servidor, así que
solo tiene sentido si la herramienta corre en tu propia máquina. Los ficheros de
`samples/` se leen siempre, estén como estén esas variables.

---

## Añadir un SIEM nuevo

```python
# glamdring/connectors/miSiem.py
from .base import ConnectorError, FetchResult, Health, HttpConnector

class MiSiemConnector(HttpConnector):
    name = "misiem"
    query_language = "MiQL"
    example_query = "..."
    supports_cursor = False        # True si sabe continuar desde un cursor

    @property
    def configured(self) -> bool:
        return bool(self.config.url and self.config.token)

    def _client_kwargs(self):
        # El cliente se REUTILIZA entre consultas. Antes cada fetch abría el suyo
        # y lo cerraba: DNS, TLS entero y conexión nueva cada vez, tirando un pool
        # que existe justo para no hacer eso.
        return {"timeout": SETTINGS.query_timeout,
                "headers": {"Authorization": f"Bearer {self.config.token}"}}

    async def fetch(self, query, time_from=None, time_to=None,
                    limit=10_000, cursor=None) -> FetchResult:
        ...
        return FetchResult(records=filas[:limite],       # registros CRUDOS
                           truncated=len(filas) > limite,
                           total=cuantos_habia,          # si el SIEM lo dice
                           cursor=por_donde_seguir,      # si pagina con estado
                           warnings=[])

    async def ping(self) -> Health:
        # Lo más barato que exija autenticación. Y SIN efectos secundarios sobre
        # los datos: un semáforo no puede consumir eventos.
        ...
```

### Por qué `FetchResult` y no una lista

Devolver una lista pelada perdía tres cosas que sí importan:

- **Si faltaban datos.** «El SIEM tenía justo 10.000» y «tenía dos millones y te
  doy los primeros 10.000» llegaban idénticos. Un grafo incompleto se lee como uno
  entero, y lo que no está se interpreta como que no pasó.
- **Por dónde seguir**, para las fuentes que paginan con estado.
- **Lo raro que no llega a error**: un resultado parcial, una tabla vacía, líneas
  ilegibles.

El truco para saber si sobraban es **pedir uno más** de los que se van a entregar;
si vuelve, había más, y ese testigo se descarta. QRadar además dice el total de
verdad en `Content-Range` y se aprovecha.

Alta en `connectors/__init__.py`, y un normalizador en `normalize/` que llame a
`register(nombre, matches, normalize, priority=10)`. Nada más del sistema cambia.

El normalizador **solo puede emitir actividades del vocabulario cerrado**
([`VOCABULARIO.md`](VOCABULARIO.md)). Hay un test que lo comprueba sobre cada
muestra: si una fuente nueva inventa su propio dialecto, se acabó la
correlación entre productos, que es para lo que existe la herramienta.

Para probarlo sin el SIEM delante, `respx` mockea httpx:

```python
import respx, httpx

@respx.mock
async def test_mi_siem():
    respx.post("https://misiem/api/search").mock(
        return_value=httpx.Response(200, json={"results": [...]})
    )
    ...
```
