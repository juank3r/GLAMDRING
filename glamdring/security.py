"""La frontera de la API: quién puede escribir, desde dónde, y cuánto.

Hasta ahora no había ninguna. Medido en ejecución: **31 operaciones de API y
cero con autenticación**, incluidas `POST /api/reset`, `POST /api/ingest`,
`PUT /api/appearance` y `GET /api/export` — esta última entrega el corpus
completo del incidente del cliente.

Aquí hay dos cosas distintas y conviene no confundirlas:

* **De dónde viene la petición** (este módulo, siempre activo). Protege el caso
  de hoy: la herramienta en el portátil del analista, atada a loopback.
* **Quién la hace** (la clave de API, opcional). Protege el caso de mañana: la
  herramienta en una red.

EL ATAQUE QUE FUNCIONA HOY ES EL PRIMERO, y no hace falta desplegar nada para
sufrirlo. Cualquier página que el analista abra en otra pestaña puede hacer:

    fetch('http://localhost:8000/api/reset', {method: 'POST', mode: 'no-cors'})

y vaciarle la investigación en curso. Reproducido: `POST /api/reset` con
`Origin: https://evil.example` devolvía `200 {'status':'ok','events':0}`, y un
`POST /api/ingest` multipart con el mismo origen inyectaba un evento.

**Atarlo a loopback no protege de esto.** El navegador del analista *está* en
loopback: es él quien hace la petición, engañado por otra página. Y ni
`multipart/form-data` ni `text/plain` llevan comprobación previa del navegador,
así que no hay nada que lo pare por el camino.
"""

from __future__ import annotations

import hmac
import logging
from typing import Optional

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.body_limit import RequestBodyLimitResponder
from starlette.requests import Request
from starlette.responses import JSONResponse

log = logging.getLogger("glamdring.security")

# Métodos que cambian algo. Un GET no puede hacer daño desde otra pestaña porque
# el navegador no deja leer la respuesta, y aquí ninguno modifica estado.
METODOS_QUE_ESCRIBEN = {"POST", "PUT", "PATCH", "DELETE"}

# El receptor tiene su propia puerta -clave por fuente, comparación en tiempo
# constante- y lo usan procesos, no navegadores: NSS de Zscaler, reenviadores de
# syslog, webhooks. Ninguno manda `Origin`, así que la comprobación de origen no
# les aplica ni les serviría.
RUTAS_CON_PUERTA_PROPIA = ("/api/receive",)

# 50 MB de cuerpo para lo normal: un lote de eventos, una consulta, un empujon
# del receptor. Lo que no cabe es el fichero de 300 MB con el que se llenaba el
# disco temporal antes de devolver el 413.
MAX_BYTES_PETICION = 50 * 1024 * 1024

# UN TOPE GLOBAL SOLO NO VALE, y el primer intento lo demostro: puesto a 50 MB
# dejaba INALCANZABLE el limite de 200 MB de la subida de ficheros. Dos topes
# donde el de fuera es menor que el de dentro no son dos defensas, son una
# defensa y una linea de codigo que no se ejecuta nunca.
#
# Y bajar la subida a 50 MB no es la respuesta: arrastrar el fichero exportado
# del SIEM es, segun el propio README, la forma en que mas se usa esto, porque
# el analista rara vez tiene el token de la API. El tope tiene que caber ahi.
#
# Asi que el tope se elige POR RUTA. El margen que se suma al limite de cada
# ruta es para el sobre multipart -las cabeceras de cada parte-, que viaja en el
# cuerpo y cuenta para el total sin ser parte del fichero.
MARGEN_MULTIPART = 1024 * 1024

# La coincidencia es EXACTA a proposito: por prefijo, "/api/ingest" pillaria
# tambien "/api/ingest-log", que es un GET sin cuerpo pero al que no hay ninguna
# razon para regalarle 200 MB.
TOPES_EXACTOS = {
    "/api/ingest": 200 * 1024 * 1024 + MARGEN_MULTIPART,
}
TOPES_POR_PREFIJO = (
    ("/api/appearance/model/", 25 * 1024 * 1024 + MARGEN_MULTIPART),
)


def tope_de_cuerpo(ruta: str) -> int:
    """Cuanto cuerpo se admite en esta ruta."""
    if ruta in TOPES_EXACTOS:
        return TOPES_EXACTOS[ruta]
    for prefijo, tope in TOPES_POR_PREFIJO:
        if ruta.startswith(prefijo):
            return tope
    return MAX_BYTES_PETICION


class LimiteDeCuerpo:
    """Corta el cuerpo de la peticion segun la ruta.

    Se apoya en el contador de starlette -`RequestBodyLimitResponder`- y lo
    unico que anade es elegir el numero. Reescribir el conteo aqui seria
    duplicar la parte delicada: cuenta segun llega, aborta a mitad de flujo y
    sabe distinguir si la respuesta ya habia empezado.

    Lo que mas vale de todo esto no es el conteo sino el rechazo por
    `Content-Length`: si la cabecera ya declara mas de lo que cabe, se responde
    413 SIN LEER UN SOLO BYTE. Ahi es donde muere el caso medido en la auditoria,
    300 MB escritos en el temporal para acabar rechazandolos.
    """

    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        responder = RequestBodyLimitResponder(self.app, tope_de_cuerpo(scope["path"]))
        await responder(scope, receive, send)


def _es_del_mismo_sitio(request: Request) -> bool:
    """¿La petición viene de la propia página, o de otra?

    Se mira `Sec-Fetch-Site` primero porque es la respuesta directa a la
    pregunta y la mandan todos los navegadores actuales. `Origin` es el respaldo
    para los que no.

    Un cliente que no es un navegador —curl, un reenviador, un script— no manda
    ninguna de las dos, y se le deja pasar: la falsificación entre sitios es un
    problema del navegador, que es quien adjunta las credenciales de la víctima
    sin que ella lo pida. Un script que quiera atacar la API no necesita
    engañar a nadie, así que exigirle una cabecera no protege de nada.
    """
    sitio = request.headers.get("sec-fetch-site")
    if sitio:
        return sitio in ("same-origin", "same-site", "none")

    origen = request.headers.get("origin")
    if not origen:
        return True  # no es un navegador

    host = request.headers.get("host", "")
    if not host:
        return False
    # Se compara solo la parte de host:puerto: el esquema puede diferir cuando
    # hay un proxy delante terminando TLS.
    return origen.split("//")[-1].rstrip("/") == host


class OrigenMiddleware(BaseHTTPMiddleware):
    """Rechaza escrituras que vengan de otra página.

    `Sec-Fetch-Site: none` se acepta porque es lo que manda el navegador cuando
    la petición la inicia el usuario directamente (escribir la URL, un marcador).
    Eso no es una falsificación: es alguien usando la herramienta.
    """

    async def dispatch(self, request: Request, call_next):
        if request.method in METODOS_QUE_ESCRIBEN:
            ruta = request.url.path
            if not ruta.startswith(RUTAS_CON_PUERTA_PROPIA):
                if not _es_del_mismo_sitio(request):
                    log.warning("Escritura rechazada desde otro origen: %s %s (origin=%s)",
                                request.method, ruta, request.headers.get("origin"))
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Peticion rechazada: viene de otro sitio. "
                                           "Usa la interfaz de GLAMDRING."},
                    )
        return await call_next(request)


class ClaveApiMiddleware(BaseHTTPMiddleware):
    """Exige una clave en `/api/*` cuando hay una configurada.

    OPCIONAL A PROPOSITO. Sin clave, la herramienta funciona como siempre y se
    supone atada a loopback; el arranque lo avisa. Con clave, hace falta para
    todo `/api/*`.

    No se inventa un sistema de usuarios: esto lo usa un analista en su maquina,
    o un equipo pequeño detrás de un proxy que ya autentica. Un modelo de
    usuarios y permisos aquí seria dar una respuesta grande a una pregunta que
    nadie ha hecho todavia, y encima habria que mantenerla.
    """

    def __init__(self, app, clave: str) -> None:
        super().__init__(app)
        self._clave = clave

    async def dispatch(self, request: Request, call_next):
        ruta = request.url.path
        # El receptor tiene su propia clave por fuente; exigir ademas la general
        # obligaria a poner las dos en cada reenviador sin ganar nada.
        if ruta.startswith("/api") and not ruta.startswith(RUTAS_CON_PUERTA_PROPIA):
            presentada = (request.headers.get("x-glamdring-key")
                          or _clave_de_autorizacion(request))
            # compare_digest y no ==: la comparacion normal para en el primer
            # byte distinto, asi que tarda un poco mas cuanto mas acierta quien
            # prueba, y por ahi se saca la clave caracter a caracter.
            if not presentada or not hmac.compare_digest(presentada, self._clave):
                return JSONResponse(
                    status_code=401,
                    content={"detail": "Falta la clave de API o no es correcta "
                                       "(cabecera X-Glamdring-Key)."},
                )
        return await call_next(request)


def _clave_de_autorizacion(request: Request) -> Optional[str]:
    """Acepta tambien `Authorization: Bearer <clave>`, que es lo que espera
    cualquier cliente de API."""
    cabecera = request.headers.get("authorization") or ""
    if cabecera.lower().startswith("bearer "):
        return cabecera[7:].strip()
    return None


def montar_seguridad(app, clave: str = "") -> None:
    """Pone los tres middleware en el orden correcto.

    Vive aqui y no en `main` para que se pueda probar sobre una aplicacion
    recien hecha: el orden es la mitad del arreglo y montarlo del reves no da
    error, solo deja de proteger.

    El ORDEN va del mas exterior al mas interior, y se anaden al reves de como
    se ejecutan:

        1. limite de cuerpo   corta por Content-Length, sin leer nada
        2. clave de API       si hay clave, nada pasa sin ella
        3. origen             y de lo que pasa, nada escribe desde otra pagina

    El limite el PRIMERO a proposito: de nada sirve rechazar por credencial
    despues de habersele tragado el fichero entero.
    """
    app.add_middleware(OrigenMiddleware)
    if clave:
        app.add_middleware(ClaveApiMiddleware, clave=clave)
    app.add_middleware(LimiteDeCuerpo)
