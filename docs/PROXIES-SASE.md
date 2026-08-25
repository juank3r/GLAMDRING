# Netskope y Zscaler: como entran sus logs

Notas de integracion para la fase 3, con las cosas comprobadas contra la
documentacion de cada fabricante marcadas como tales. Lo que no este comprobado
lo dice.

## Por que un proxy SASE, teniendo ya cuatro SIEM

Ninguna de las cuatro fuentes actuales da esto:

| Dato del proxy | Para que sirve en el grafo |
|---|---|
| Usuario detras de cada sesion | Ata la IP interna a una persona sin depender del DHCP |
| Aplicacion cloud concreta | Distingue "subio 4 GB a Internet" de "subio 4 GB a Mega" |
| Actividad dentro de la aplicacion | Subir, descargar, compartir, borrar: acciones, no solo trafico |
| Veredicto de politica | Permitido, bloqueado, avisado. Lo bloqueado tambien cuenta |
| Bytes en cada sentido | La asimetria es la firma de la exfiltracion |
| Categoria del destino | Almacenamiento, IA generativa, anonimizadores |

El caso que hoy no se ve: un equipo con el cliente SASE puesto **no pasa por el
cortafuegos de la oficina**. En el grafo actual ese trafico simplemente no
existe, y el hueco no se nota, que es lo peor que puede tener un hueco.

## Como entrega cada uno sus logs

Esta es la decision que condiciona todo lo demas.

| Plataforma | Entrega | Encaja en `fetch()` |
|---|---|---|
| **Netskope** | API REST v2, iterador sobre `/events/dataexport/events/{tipo}` | si, es *pull* |
| **Zscaler ZIA** | Los logs web **no salen por la API**: los empuja Cloud NSS | **no**, es *push* |
| **Zscaler ZPA** | API REST de logs de acceso a aplicaciones | si, es *pull* |

Por eso el receptor de la fase 1 (`POST /api/receive/{fuente}`) existe: sin el,
la mitad de Zscaler no entra. No es un capricho de un fabricante, es como
funciona syslog, los webhooks y el HEC de Splunk.

### Netskope — comprobado

- API v2, autenticacion por cabecera `Netskope-Api-Token`.
- Los eventos traen `user`, `app`, `activity` (por ejemplo `Download`),
  `alert_type` (por ejemplo `DLP`), `numbytes`, `_id`.
- El token se limita por ambito, del estilo
  `/api/v2/events/dataexport/events/audit`.
- **Es un iterador con estado**: no se le piden fechas, se le pide "lo
  siguiente". Encaja en el contrato v2 usando `cursor`, que se anadio para
  esto.

### Zscaler Cloud NSS — comprobado

- Se configura en el portal de ZIA: Administracion > Nanolog Streaming Service >
  Cloud NSS Feed.
- El campo **API URL** es la direccion a la que NSS empuja. Ahi va la URL de
  nuestro receptor.
- Admite **cabeceras HTTP a medida**, con clave y valor, y se pueden anadir
  varias. Ahi va `X-Glamdring-Key`, asi que el receptor tal como esta escrito
  vale sin tocar nada.
- **Cloud NSS viene desactivado** en ZIA. Si no aparece la opcion, hay que
  abrir un caso con el soporte de Zscaler. Conviene saberlo antes de prometer
  fechas: no es un interruptor que se active solo.
- El formato de salida se configura en el propio feed, asi que soportaremos su
  JSON y su CEF.

### Zscaler ZPA — pendiente de comprobar

La API de logs de acceso a aplicaciones es *pull* y encaja en el contrato, pero
no he verificado el detalle de los ambitos ni la paginacion. Antes de escribir
el conector hay que mirarlo.

## Entidades y relaciones nuevas

- **`app`** — la aplicacion SaaS. Hoy caerian en `service`, que las mezclaria
  con los servicios de Windows: un servicio que arranca en un equipo y Dropbox
  no son la misma clase de cosa.
- **`tunnel`** — la sesion del cliente SASE. Es lo que ata equipo, usuario y
  salida a Internet, y lo que explica por que ese trafico no aparece en el
  cortafuegos.
- Relaciones: `uploaded_to`, `downloaded_from`, `shared`, `tunneled_through`.
- Modelo: `NetRef(bytes_in, bytes_out, protocol, action, rule, category)` y
  `SessionRef(id, assigned_ip, start, end)`.

## Como se configura, cuando este

```
# Netskope (pull)
NETSKOPE_URL=https://<tenant>.goskope.com
NETSKOPE_TOKEN=

# Zscaler ZIA (push): en el portal de ZIA, Cloud NSS Feed
#   API URL:      https://glamdring.tu-red.local/api/receive/zscaler
#   Cabecera:     X-Glamdring-Key = <la clave de la fuente 'zscaler'>
GLAMDRING_RECEIVE_KEYS=zscaler:<clave>,netskope:<clave>
```

La clave se genera con:

```
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

## Fuentes

- [Netskope: API Tokens](https://docs.netskope.com/en/api-tokens-2)
- [Netskope: Application Events](https://docs.netskope.com/en/about-application-events)
- [Zscaler: Understanding Nanolog Streaming Service](https://help.zscaler.com/zia/understanding-nanolog-streaming-service)
- [Zscaler: Adding Cloud NSS Feeds for Web Logs](https://help.zscaler.com/zia/adding-cloud-nss-feeds-web-logs)
- [Zscaler: NSS Feed Output Format - Web Logs](https://help.zscaler.com/zia/nss-feed-output-format-web-logs)
