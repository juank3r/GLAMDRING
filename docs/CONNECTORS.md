# Conectores

Cómo dar de alta credenciales en cada SIEM y qué consultas funcionan bien.

Todo se configura por `.env` (copia `.env.example`). **Nada de credenciales en el
código ni en el JSON del grafo.** `GET /api/health` dice qué conectores están
configurados, nunca con qué.

> Sin ninguna credencial la herramienta funciona igual: ingesta ficheros exportados
> del SIEM, que es el caso más habitual porque casi ningún analista tiene acceso a
> la API.

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
from .base import Connector, ConnectorError

class MiSiemConnector(Connector):
    name = "misiem"
    query_language = "MiQL"
    example_query = "..."

    @property
    def configured(self) -> bool:
        return bool(self.config.url and self.config.token)

    async def fetch(self, query, time_from=None, time_to=None, limit=10_000):
        ...  # devolver list[dict] con los registros CRUDOS
```

Alta en `connectors/__init__.py`, y un normalizador en `normalize/` que llame a
`register(nombre, matches, normalize, priority=10)`. Nada más del sistema cambia.

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
