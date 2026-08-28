"""Los seis hallazgos de clasificación de gravedad media que quedaban vivos.

Salieron de una auditoría en la que cada uno se reprodujo ejecutando código, y
aquí se fijan uno a uno. Ninguno rompe nada visiblemente: los seis dejan el grafo
en pie y con pinta de correcto, contando algo que no pasó o perdiendo algo que sí.

El séptimo de aquella lista —un IPv6 interno contando como IP pública y subiendo
la severidad— se arregló de rebote al rehacer la escala de severidad, y por eso
no está aquí.
"""

from __future__ import annotations

import pytest

from glamdring.graph.build import build_graph
from glamdring.graph.enrich import enrich
from glamdring.normalize import normalize_all
from glamdring.normalize.base import first, normalize_record


def _grafo(evento):
    return enrich(build_graph([evento]))


def _aristas(grafo):
    return {(e.source, e.type, e.target) for e in grafo.links}


# --------------------------------------------------------- campos multivalor

def test_un_campo_multivalor_de_splunk_no_produce_un_usuario_con_corchetes():
    """Splunk devuelve una LISTA cuando un campo aparece varias veces.

    Y pasa constantemente: un 4624 trae dos `Account_Name`, el de la maquina y el
    del usuario de verdad. Antes la lista llegaba entera al grafo y salia un nodo
    de usuario literalmente llamado ``['-', 'SVC_BACKUP']``. Eso no es un
    usuario: no se puede pinchar, no correlaciona con nada, y ensucia el grafo
    con una entidad que no existe en ninguna parte.
    """
    evento = normalize_record({
        "_time": "2026-08-19T09:15:41Z", "_raw": "x",
        "sourcetype": "WinEventLog:Security", "EventCode": "4624",
        "ComputerName": "srv-dc01", "Account_Name": ["-", "SVC_BACKUP"],
        "Logon_Type": "3",
    })
    assert evento is not None
    grafo = _grafo(evento)
    usuarios = [n.id for n in grafo.nodes if n.type == "user"]
    assert usuarios, "el usuario tiene que salir"
    for uid in usuarios:
        assert "[" not in uid and "'" not in uid, f"nodo con la lista dentro: {uid}"


def test_first_se_queda_con_el_primer_valor_UTIL_de_la_lista():
    """No con el primero a secas.

    El guion es el valor que Windows pone en el hueco que no aplica, asi que
    quedarse con el seria tirar el bueno y quedarse con el relleno.
    """
    assert first({"Account_Name": ["-", "SVC_BACKUP"]}, "Account_Name") == "SVC_BACKUP"
    assert first({"x": ["", None, "vale"]}, "x") == "vale"
    assert first({"x": ["-", "N/A"]}, "x") is None
    assert first({"x": "normal"}, "x") == "normal"


# ------------------------------------------------------- eventos agregados

def test_los_eventos_agregados_de_qradar_cuentan_lo_que_representan():
    """QRadar entrega catorce intentos fallidos en una sola fila.

    `Multiple Login Failures for Single Username` llega con `eventcount=14`. Ese
    campo se tiraba, asi que en el grafo la arista contaba 1 y una fuerza bruta
    parecia un despiste. Y el numero de la arista es justo lo que el analista
    lee para decidir si eso es un ataque o un dedo torpe.
    """
    evento = normalize_record({
        "starttime": 1787147782000,
        "qidname": "Multiple Login Failures for Single Username",
        "categoryname": "Authentication Failure", "logsourcename": "SRV-DC01",
        "sourceip": "10.4.2.11", "destinationip": "10.4.1.5",
        "username": "administrator", "magnitude": 7, "eventcount": 14,
    })
    assert evento.occurrences == 14

    grafo = build_graph([evento])
    autenticacion = [e for e in grafo.links if e.type == "failed_auth"]
    assert autenticacion, "hace falta la arista de fallo de autenticacion"
    assert autenticacion[0].count == 14, "la arista sigue contando uno"


def test_un_evento_normal_cuenta_uno():
    """La contraprueba: sin eventcount, nada cambia."""
    evento = normalize_record({
        "starttime": 1787147782000, "qidname": "Firewall Permit",
        "categoryname": "Firewall Session Allowed", "logsourcename": "PaloAlto",
        "sourceip": "10.4.2.11", "destinationip": "45.132.88.17", "magnitude": 4,
    })
    assert evento.occurrences == 1


# --------------------------------------------------------------- la ofensa

def test_una_ofensa_agrupada_por_usuario_no_inventa_una_maquina():
    """`offense_type` dice QUE es el `offense_source`, y no se leia.

    Se usaba solo para decidir que el registro era una ofensa, y despues el valor
    se interpretaba a ojo: si parecia una IP iba a `src` y si no, a `device`. Con
    una ofensa agrupada por usuario -de las mas comunes- eso convertia 'jlopez'
    en un HOST llamado jlopez, y el grafo enseñaba una maquina que no existe.
    """
    evento = normalize_record({
        "offense_type": "Username", "offense_source": "jlopez",
        "magnitude": 8, "description": "Ofensa por usuario",
        "start_time": 1787147782000,
    })
    assert evento.actor and evento.actor.user == "jlopez"
    assert not (evento.device and evento.device.hostname), (
        "se ha inventado una maquina a partir de un nombre de usuario")

    grafo = _grafo(evento)
    assert not [n for n in grafo.nodes if n.type == "host" and "jlopez" in n.id]


def test_una_ofensa_agrupada_por_maquina_si_produce_una_maquina():
    """La contraprueba, para que el arreglo no sea 'no crear hosts nunca'."""
    evento = normalize_record({
        "offense_type": "Hostname", "offense_source": "SRV-DC01",
        "magnitude": 8, "description": "Ofensa por equipo",
        "start_time": 1787147782000,
    })
    assert evento.device and evento.device.hostname == "srv-dc01"


# ------------------------------------------------------------- Sentinel

def test_el_dns_de_defender_saca_el_dominio_de_donde_lo_pone():
    """Defender no tiene columna para el nombre consultado.

    Lo mete en `AdditionalFields`, que es un JSON SERIALIZADO DENTRO DE UNA
    CADENA. Pasarselo tal cual a canon_domain devolvia None, asi que la unica
    tabla para la que sirve la rama de DNS se quedaba sin dominio, o sea sin el
    nodo que da sentido al evento.
    """
    evento = normalize_record({
        "Type": "DeviceEvents", "ActionType": "DnsQueryResponse",
        "TimeGenerated": "2026-08-19T09:21:20Z", "DeviceName": "WKS-0421",
        "AdditionalFields": '{"query":"cdn-update-svc.com","IsSuccess":true}',
    })
    assert evento.domain == "cdn-update-svc.com"
    assert any(n.type == "domain" for n in _grafo(evento).nodes)


def test_el_phishing_sin_columna_Type_no_se_va_al_generico():
    """matches() solo miraba _MS_MARKERS, y EmailEvents no lleva ninguno.

    Ni DeviceName, ni InitiatingProcessFileName, ni DeviceId. Asi que un correo
    exportado sin la columna Type se caia al normalizador generico y perdia
    remitente, destinatario y veredicto de entrega, que es TODO lo que tiene.

    La rama de EmailEvents de _guess_table era codigo muerto por este motivo:
    existia y nunca se llegaba a ella.
    """
    evento = normalize_record({
        "TimeGenerated": "2026-08-19T08:40:00Z",
        "SenderFromAddress": "billing@cdn-update-svc.com",
        "RecipientEmailAddress": "jlopez@corp.com",
        "Subject": "Factura pendiente", "DeliveryAction": "Delivered",
    })
    assert evento.source == "sentinel", "se lo ha quedado el generico"
    assert evento.activity == "email_deliver"
    assert evento.email and evento.email.sender == "billing@cdn-update-svc.com"
    assert evento.email.recipient == "jlopez@corp.com"


# ------------------------------------------------------------- el extractor

def test_el_usuario_no_se_queda_colgado_al_crear_un_fichero():
    """Cuando el evento trae proceso, el verbo va del proceso al fichero.

    Y el nodo de usuario se creaba sin enlazar con nada: se perdia QUIEN estaba
    detras de la escritura, que en un incidente es la mitad de la pregunta.

    Se ata al proceso y no al fichero, a proposito: el usuario ejecuto el
    proceso y el proceso toco el fichero. Decir que el usuario escribio el
    fichero teniendo un proceso de por medio seria inferir un paso que el evento
    no da.
    """
    evento = normalize_record({
        "_time": "2026-08-19T09:32:00Z", "_raw": "x",
        "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
        "EventCode": "11", "ComputerName": "wks-0421", "User": "CORP\\jlopez",
        "Image": "C:\\Windows\\System32\\certutil.exe",
        "TargetFilename": "C:\\Windows\\Temp\\upd.exe",
    })
    grafo = _grafo(evento)
    usuarios = [n for n in grafo.nodes if n.type == "user"]
    assert usuarios, "el usuario tiene que estar"
    assert usuarios[0].degree > 0, "el usuario se ha quedado sin ninguna arista"

    aristas = _aristas(grafo)
    assert any(o == usuarios[0].id and t == "executed" for o, t, _ in aristas), (
        "el usuario tiene que colgar del proceso que ejecuto")


@pytest.mark.parametrize("muestra", (
    "splunk_windows.json", "perimeter.cef", "qradar_ariel.json",
    "sentinel_defender.json", "netskope_casb.json", "zscaler_web.json"))
def test_ninguna_muestra_deja_nodos_sueltos_despues_de_todo_esto(muestra):
    """La red de seguridad de siempre: si algo se ha torcido, se ve aqui."""
    from glamdring.config import SAMPLES_DIR
    from glamdring.normalize import parse_payload

    registros, _ = parse_payload((SAMPLES_DIR / muestra).read_text(encoding="utf-8"))
    grafo = enrich(build_graph(normalize_all(registros)))
    sueltos = [n.id for n in grafo.nodes if n.degree == 0]
    assert not sueltos, f"{muestra} deja sueltos: {sueltos}"
