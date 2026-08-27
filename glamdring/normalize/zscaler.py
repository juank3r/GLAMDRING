"""Normalizador de Zscaler: logs web y de tunel de ZIA, y acceso de ZPA.

POR QUE ENTRA POR EL RECEPTOR Y NO POR UN CONECTOR. Los logs web de ZIA **no
salen por la API**: los empuja NSS (Nanolog Streaming Service) a una URL que se
le configura. Por eso existe ``POST /api/receive/{fuente}``, y por eso el
contrato de conector no bastaba: solo sabia tirar de datos.

En el portal de ZIA, Administracion > Nanolog Streaming Service > Cloud NSS
Feed, el campo "API URL" apunta a nuestro receptor y la clave va en una cabecera
a medida. Nota operativa que conviene saber antes de prometer fechas: Cloud NSS
viene DESACTIVADO y si no aparece la opcion hay que abrir un caso con Zscaler.

NSS emite en el formato que se le configure, asi que aqui se aceptan las dos
formas habituales: su JSON y su CEF (que ya cae por el parser de texto).

Nombres de campo segun la documentacion de formato de salida de NSS para logs
web: ``action``, ``reqsize``, ``respsize``, ``urlcat``, ``appname``,
``threatname``, ``malwarecat``, ``user``, ``url``, ``ClientIP``, ``serverip``,
``requestmethod``, ``filetype``, ``dlpengine``, ``dlpdictionaries``,
``urlsupercategory``, ``appclass``, ``location``, ``department``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from ..mitre import technique
from ..models import (
    CLASS_FILE,
    CLASS_FINDING,
    CLASS_NETWORK,
    ActorRef,
    FileRef,
    HostRef,
    NetRef,
    NormalizedEvent,
    SessionRef,
    make_uid,
)
from .base import (
    basename,
    canon_domain,
    canon_host,
    first,
    is_ip,
    parse_time,
    register,
    to_int,
)

# Campos con nombre propio de NSS. 'urlcat' y 'reqsize' no aparecen en ningun
# otro producto, asi que dos de estos ya identifican la fuente sin lugar a dudas.
_MARCADORES = ("urlcat", "reqsize", "respsize", "appclass", "urlsupercategory",
               "malwarecat", "clienttranstime", "pagerisk", "dlpengine",
               "urlclass", "threatclass", "clientpublicip")

# Categorias de destino que si son una senal por si solas, no por el volumen.
_CATEGORIAS_GRAVES = ("anonymizer", "malware", "phishing", "botnet", "spyware",
                      "newly registered", "cryptomining", "proxy avoidance",
                      "peer to peer", "questionable")

# Aplicaciones por las que se sacan datos. La categoria de Zscaler las agrupa.
_CATEGORIAS_DE_SALIDA = ("file sharing", "cloud storage", "webmail",
                         "personal storage", "ai & ml applications",
                         "generative ai")


def matches(record: Dict[str, Any]) -> bool:
    if not isinstance(record, dict):
        return False
    if record.get("__format__"):
        # El CEF y el LEEF de NSS ya los recoge el parser de texto, que los
        # marca. No se les roba el registro aqui.
        return False
    minusculas = {str(k).lower() for k in record}
    presentes = sum(1 for m in _MARCADORES if m in minusculas)
    if presentes >= 2:
        return True
    proveedor = str(first(record, "vendor", "product", "sourcetype") or "").lower()
    return "zscaler" in proveedor and bool(presentes or first(record, "url", "action"))


def _aplanar(record: Dict[str, Any]) -> Dict[str, Any]:
    """Una copia con las claves en minusculas. NSS mezcla ClientIP con urlcat."""
    return {str(k).lower(): v for k, v in record.items()}


def _bajo(plano: Dict[str, Any], *nombres: str) -> Any:
    """first() sobre el registro YA aplanado.

    Antes esta funcion aplanaba el registro en cada llamada, y se la llama una
    docena de veces por evento: sobre las muestras eran 7.720 diccionarios
    construidos y tirados para normalizar 2.560 registros. Ahora se aplana una
    vez por evento y se pasa.
    """
    for nombre in nombres:
        valor = plano.get(nombre)
        if valor not in (None, "", "None"):
            return valor
    return None


def _clasificar(plano: Dict[str, Any]):
    """Devuelve (clase, actividad, severidad base)."""
    amenaza = _bajo(plano, "threatname", "malwarecat", "threatclass")
    # Que Zscaler nombre una amenaza es un hallazgo del producto, no una
    # operacion de fichero por mucho que haya un fichero de por medio.
    if amenaza and str(amenaza).strip().lower() not in ("none", "-", "n/a"):
        return CLASS_FINDING, "malware_detect", 5

    if _bajo(plano, "dlpengine", "dlpdictionaries"):
        # DLP disparado: alguien ha movido datos que no debia.
        return CLASS_FINDING, "alert", 4

    # Los logs de TUNEL de ZIA, que son los que atan la persona a su IP publica.
    if _bajo(plano, "tunneltype", "tunnelid", "vpncredentialname", "sourceip_tunnel"):
        accion = str(_bajo(plano, "action", "event") or "").lower()
        return CLASS_NETWORK, ("tunnel_close" if "disconnect" in accion or "down" in accion
                               else "tunnel_open"), 2

    metodo = str(_bajo(plano, "requestmethod", "method") or "").upper()
    subida = to_int(_bajo(plano, "reqsize", "requestsize")) or 0
    bajada = to_int(_bajo(plano, "respsize", "responsesize")) or 0
    categoria = str(_bajo(plano, "urlcat", "urlcategory", "appclass") or "").lower()

    # Una subida de verdad: metodo de escritura hacia una aplicacion por la que
    # se sacan datos. Se exige LA COMBINACION, porque un POST a cualquier web es
    # rellenar un formulario, no exfiltrar.
    if metodo in ("POST", "PUT", "PATCH") and subida > bajada and \
            any(c in categoria for c in _CATEGORIAS_DE_SALIDA):
        return CLASS_FILE, "file_upload", 3
    if _bajo(plano, "filetype") and metodo == "GET" and bajada > 0:
        return CLASS_FILE, "file_download", 2

    return CLASS_NETWORK, "network_connect", 2


def normalize(record: Dict[str, Any]) -> Optional[NormalizedEvent]:
    plano = _aplanar(record)
    clase, actividad, severidad = _clasificar(plano)

    accion = str(_bajo(plano, "action") or "").strip().lower()
    if accion in ("blocked", "block", "drop", "dropped", "deny", "denied"):
        estado = "failure"
    elif accion in ("allowed", "allow", "permit", "permitted", "connected"):
        estado = "success"
    elif accion in ("cautioned", "warned", "isolated"):
        # Un tercer desenlace: paso pero avisando. No es exito ni fallo.
        estado = "unknown"
    else:
        estado = "unknown"

    evento = NormalizedEvent(
        uid=make_uid("zscaler", record),
        time=parse_time(_bajo(plano, "datetime", "time", "timestamp", "recordid")),
        source="generic",
        origin=str(_bajo(plano, "product", "vendor") or "zscaler"),
        class_name=clase,
        activity=actividad,
        severity=severidad,
        status=estado,
        message=_mensaje(plano, actividad),
        raw=record,
    )

    usuario = _bajo(plano, "user", "login", "username")
    if usuario and str(usuario).strip() not in ("", "-", "unknown"):
        evento.actor = ActorRef(user=str(usuario),
                                domain=str(_bajo(plano, "department", "company") or "") or None)

    cliente = _bajo(plano, "clientip", "client_ip", "sourceip")
    if cliente and is_ip(str(cliente)):
        evento.src = HostRef(ip=str(cliente))
    # OJO CON 'hostname'. En un log web de NSS es el servidor de DESTINO -el
    # sitio al que se navega-, no el equipo que reporta. Meterlo como
    # dispositivo creaba un nodo 'host:cdn-update-svc' al lado del
    # 'domain:cdn-update-svc.com' que ya existia: la misma cosa partida en dos,
    # y una de las mitades disfrazada de maquina de la empresa.
    equipo = canon_host(_bajo(plano, "devicename", "devicehostname", "device"))
    if equipo and not is_ip(str(equipo)):
        evento.device = HostRef(hostname=equipo)

    servidor = _bajo(plano, "serverip", "destinationip", "dstip")
    if servidor and is_ip(str(servidor)):
        evento.dst = HostRef(ip=str(servidor))

    url = _bajo(plano, "url", "requesturl")
    if url:
        evento.url = str(url)
        evento.domain = canon_domain(str(url).split("//")[-1].split("/")[0].split(":")[0])
    if not evento.domain:
        evento.domain = canon_domain(_bajo(plano, "host", "domain", "dnsdomain"))

    # La aplicacion cloud concreta. Es lo que separa "subio 4 GB a Internet" de
    # "subio 4 GB a Mega".
    # 'General Browsing' y companyia son el valor que pone Zscaler cuando NO ha
    # reconocido una aplicacion concreta. Convertirlo en nodo llenaria el grafo
    # de servicios que no son servicios y, peor, haria que todo el trafico sin
    # clasificar apareciera colgando del mismo sitio.
    app = _bajo(plano, "appname", "app", "cloudapp")
    generico = ("general browsing", "none", "-", "unknown", "other",
                "web browsing", "general surfing")
    if app and str(app).strip().lower() not in generico:
        evento.app = str(app)

    fichero = _bajo(plano, "filename", "file_name")
    tipo = _bajo(plano, "filetype")
    if fichero or (tipo and clase == CLASS_FILE):
        nombre = str(fichero) if fichero else f"objeto.{tipo}"
        evento.file = FileRef(name=basename(nombre) or nombre, path=nombre,
                              md5=str(_bajo(plano, "md5") or "").lower() or None,
                              sha256=str(_bajo(plano, "sha256") or "").lower() or None)

    subida = to_int(_bajo(plano, "reqsize", "requestsize", "bytes_out"))
    bajada = to_int(_bajo(plano, "respsize", "responsesize", "bytes_in"))
    categoria = _bajo(plano, "urlcat", "urlcategory", "urlsupercategory", "appclass")
    regla = _bajo(plano, "reason", "policy", "rulelabel")
    if any((subida, bajada, categoria, regla)):
        evento.net = NetRef(bytes_in=bajada, bytes_out=subida,
                            protocol=str(_bajo(plano, "protocol") or "").lower() or None,
                            rule=str(regla) if regla else None,
                            category=str(categoria) if categoria else None)

    # La sesion del tunel: lo que ata la persona, el equipo y la IP publica
    # desde la que sale a Internet.
    publica = _bajo(plano, "clientpublicip", "publicip")
    sesion = _bajo(plano, "tunnelid", "sessionid", "recordid")
    if publica or actividad.startswith("tunnel"):
        evento.session = SessionRef(
            id=str(sesion) if sesion else (str(publica) if publica else None),
            assigned_ip=str(publica) if publica and is_ip(str(publica)) else None,
            client=str(_bajo(plano, "tunneltype", "useragent") or "") or None,
            location=str(_bajo(plano, "location") or "") or None,
        )

    _afinar(evento, plano, actividad, categoria)
    return evento


def _mensaje(plano: Dict[str, Any], actividad: str) -> str:
    usuario = _bajo(plano, "user") or "alguien"
    accion = _bajo(plano, "action") or actividad
    destino = _bajo(plano, "url", "host", "appname") or "un destino"
    amenaza = _bajo(plano, "threatname")
    texto = f"{usuario}: {accion} hacia {destino}"
    if amenaza and str(amenaza).lower() not in ("none", "-"):
        texto += f" [amenaza {amenaza}]"
    return texto[:400]


def _afinar(evento: NormalizedEvent, plano: Dict[str, Any],
            actividad: str, categoria: Any) -> None:
    baja = str(categoria or "").lower()

    if any(c in baja for c in _CATEGORIAS_GRAVES):
        evento.severity = max(evento.severity, 4)

    if evento.activity == "malware_detect":
        # Bloqueado significa que Zscaler lo paro. Cualquier otra cosa significa
        # que llego, y eso es lo que hay que ver desde la otra punta de la sala.
        evento.severity = 5 if evento.status != "failure" else 4
        tech = technique("T1189")
        if tech and not evento.mitre:
            evento.mitre = [tech]

    salientes = evento.net.bytes_out if evento.net else None
    if actividad == "file_upload" and salientes and salientes > 50 * 1024 * 1024:
        evento.severity = max(evento.severity, 4)
        tech = technique("T1567.002")
        if tech:
            evento.mitre = [tech]

    # El riesgo de pagina que calcula Zscaler, cuando viene.
    riesgo = to_int(_bajo(plano, "pagerisk"))
    if riesgo and riesgo >= 80:
        evento.severity = max(evento.severity, 4)


register("zscaler", matches, normalize, priority=9)
