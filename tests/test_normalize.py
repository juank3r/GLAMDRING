"""Los normalizadores: que cada fuente acabe en el mismo modelo OCSF-lite."""

from __future__ import annotations

from datetime import timezone

import pytest

from glamdring.models import (
    CLASS_AUTHENTICATION,
    CLASS_EMAIL,
    CLASS_FINDING,
    CLASS_NETWORK,
    CLASS_PROCESS,
)
from glamdring.normalize import normalize_all, normalize_record
from glamdring.normalize.base import (
    canon_host,
    canon_user,
    is_private_ip,
    parse_severity,
    parse_time,
)
from glamdring.normalize.cef import parse_cef, parse_leef, parse_syslog


# ---------------------------------------------------------------- utilidades


@pytest.mark.parametrize("raw,expected", [
    ("CORP\\JLopez", "jlopez"),
    ("jlopez@corp.com", "jlopez"),
    ("JLOPEZ", "jlopez"),
    ("jlopez", "jlopez"),
    ("SYSTEM", None),
    ("WKS-0421$", None),          # cuenta de maquina: ruido en el grafo
    ("-", None),
    (None, None),
])
def test_canon_user(raw, expected):
    assert canon_user(raw) == expected


@pytest.mark.parametrize("raw,expected", [
    ("WKS-0421.corp.local", "wks-0421"),
    ("SRV-DC01", "srv-dc01"),
    ("10.4.2.11", "10.4.2.11"),   # las IP no se recortan por el punto
    ("-", None),
])
def test_canon_host(raw, expected):
    assert canon_host(raw) == expected


@pytest.mark.parametrize("ip,private", [
    ("10.4.2.11", True), ("192.168.1.5", True), ("172.16.0.9", True),
    ("172.32.0.9", False), ("45.132.88.17", False), ("8.8.8.8", False),
])
def test_is_private_ip(ip, private):
    assert is_private_ip(ip) is private


def test_parse_time_accepts_every_shape():
    iso = parse_time("2026-08-19T09:15:41.000Z")
    assert iso.year == 2026 and iso.tzinfo == timezone.utc

    # QRadar entrega milisegundos, no segundos.
    millis = parse_time(1787130962000)
    assert millis.year == 2026 and millis.hour == 9

    seconds = parse_time(1787130962)
    assert seconds == millis

    # Un valor vacio no puede reventar: cae a "ahora".
    assert parse_time(None) is not None


def test_parse_severity_scales():
    assert parse_severity("High") == 4
    assert parse_severity("critical") == 5
    assert parse_severity(10, scale_max=10) == 5
    assert parse_severity(5, scale_max=10) == 3   # magnitud QRadar media
    assert parse_severity(None) == 1


# -------------------------------------------------------------------- Splunk


def test_splunk_logon_success(splunk_records):
    events = normalize_all(splunk_records)
    logons = [e for e in events if e.class_name == CLASS_AUTHENTICATION and e.status == "success"]
    assert logons, "deberia haber algun 4624 correcto"

    remote = [e for e in logons if e.activity == "logon_remote"]
    assert remote, "el 4624 tipo 3 tiene que marcarse como logon remoto"
    assert remote[0].actor.user == "CORP\\jlopez"
    assert remote[0].src.ip == "10.4.2.11"
    # Un logon remoto correcto se etiqueta como movimiento lateral.
    assert any(t.id.startswith("T1021") for t in remote[0].mitre)


def test_splunk_failed_logons(splunk_records):
    """Un logon fallido es un logon con status de fallo, no otra actividad.

    Este test afirmaba activity == "logon_failed". Ese valor ya no existe, y no
    por gusto: era el MISMO dato en dos sitios, y dos sitios donde ponerlo son
    dos sitios donde pueden discrepar. Medido antes de quitarlo: colapsarlo a
    'logon' + status dejaba nodos, aristas, frase del relato e is_key_event
    IDENTICOS en los ocho eventos que lo llevaban.

    Y sobre todo rompia la correlacion entre SIEM, que es para lo que existe
    esta herramienta: si Splunk dice 'logon_failed' y QRadar dice 'logon' con
    status de fallo, el grafo no puede unir lo que cuentan los dos.
    """
    events = normalize_all(splunk_records)
    failures = [e for e in events if e.status == "failure"
                and e.class_name == CLASS_AUTHENTICATION]
    assert len(failures) >= 3
    assert all(e.activity in ("logon", "logon_remote") for e in failures)
    assert "logon_failed" not in {e.activity for e in events}, (
        "logon_failed salio del vocabulario: el desenlace va en status")


def test_splunk_process_infers_mitre(splunk_records):
    events = normalize_all(splunk_records)
    processes = [e for e in events if e.class_name == CLASS_PROCESS]
    assert processes

    encoded = [e for e in processes if e.process and e.process.cmdline
               and "-enc" in e.process.cmdline]
    assert encoded, "el powershell codificado deberia estar"
    ids = {t.id for t in encoded[0].mitre}
    assert "T1027" in ids           # ofuscacion
    assert encoded[0].severity >= 3  # y por tanto no es informativo

    certutil = [e for e in processes if e.process and e.process.name == "certutil.exe"]
    assert certutil
    assert any(t.id == "T1105" for t in certutil[0].mitre)

    dumper = [e for e in processes if e.process and e.process.cmdline
              and "sekurlsa" in e.process.cmdline]
    assert dumper
    assert any(t.id == "T1003.001" for t in dumper[0].mitre)


def test_splunk_sysmon_network_and_file(splunk_records):
    events = normalize_all(splunk_records)

    connections = [e for e in events if e.class_name == CLASS_NETWORK]
    assert any(e.dst and e.dst.ip == "45.132.88.17" for e in connections)

    # ANTES aqui se exigia que todo destino publico subiera a severidad 3, y esa
    # regla es justo la que tenia la escala del reves: casi todo el trafico de
    # una oficina va a una IP publica, asi que Windows Update pesaba lo mismo
    # que una baliza de mando y control, y mas que un salto lateral.
    #
    # Un destino publico por si solo no es una senal. Lo que si lo es: que quien
    # sale a Internet sea un binario corriendo desde una carpeta donde no
    # deberia haber ejecutables.
    externas = [e for e in connections if e.dst and e.dst.ip == "45.132.88.17"]
    desde_temp = [e for e in externas if e.process
                  and "temp" in str(e.process.path or "").lower()]
    assert desde_temp, "la muestra tiene una conexion saliente desde C:\\Windows\\Temp"
    assert all(e.severity >= 4 for e in desde_temp), (
        "un proceso en Temp saliendo a Internet si es una senal")

    files = [e for e in events if e.file and e.file.sha256]
    assert files, "los Hashes de Sysmon deberian producir sha256"
    assert all(len(e.file.sha256) == 64 for e in files)


def test_splunk_low_eventcodes_need_sysmon_sourcetype():
    """EventCode 3 en un sourcetype que no es Sysmon no puede leerse como red."""
    record = {
        "_time": "2026-08-19T09:00:00Z",
        "sourcetype": "WinEventLog:System",
        "EventCode": "3",
        "host": "WKS-0421",
        "Message": "Servicio iniciado",
    }
    event = normalize_record(record)
    assert event is not None
    assert event.class_name != CLASS_NETWORK


# ------------------------------------------------------------------ Sentinel


def test_sentinel_tables(sentinel_records):
    events = normalize_all(sentinel_records)
    origins = {e.origin for e in events}
    assert "DeviceProcessEvents" in origins
    assert "DeviceNetworkEvents" in origins
    assert "SecurityAlert" in origins
    assert all(e.source == "sentinel" for e in events)


def test_sentinel_alert_expands_entities(sentinel_records):
    events = normalize_all(sentinel_records)
    alerts = [e for e in events if e.class_name == CLASS_FINDING]
    assert alerts

    critical = [e for e in alerts if e.severity == 5]
    assert critical, "AlertSeverity=Critical debe mapear a 5"

    powershell_alert = [e for e in alerts if "PowerShell" in e.message]
    assert powershell_alert
    alert = powershell_alert[0]
    # Las entidades venian dentro de una cadena JSON en 'Entities'.
    assert alert.device and alert.device.hostname == "wks-0421"
    assert alert.actor and alert.actor.user == "jlopez"
    assert alert.dst and alert.dst.ip == "45.132.88.17"
    assert {t.id for t in alert.mitre} >= {"T1059.001", "T1027"}


def test_sentinel_signin_result_type(sentinel_records):
    events = normalize_all(sentinel_records)
    signins = [e for e in events if e.origin == "SigninLogs"]
    assert len(signins) == 2
    # ResultType 0 es exito; cualquier otro es fallo.
    assert {e.status for e in signins} == {"success", "failure"}


def test_sentinel_email(sentinel_records):
    events = normalize_all(sentinel_records)
    emails = [e for e in events if e.class_name == CLASS_EMAIL]
    assert len(emails) == 1
    assert emails[0].email.recipient == "jlopez@corp.com"
    assert emails[0].severity == 4          # ThreatTypes=Phish
    assert any(t.id == "T1566.002" for t in emails[0].mitre)


# -------------------------------------------------------------------- QRadar


def test_qradar_classification(qradar_records):
    events = normalize_all(qradar_records)
    assert events and all(e.source == "qradar" for e in events)

    auth = [e for e in events if e.class_name == CLASS_AUTHENTICATION]
    assert len(auth) == 2
    assert {e.status for e in auth} == {"success", "failure"}

    # magnitude 7 sobre 10 -> severidad 4 (alta)
    failed = [e for e in auth if e.status == "failure"][0]
    assert failed.severity == 4


def test_qradar_epoch_millis(qradar_records):
    events = normalize_all(qradar_records)
    assert all(e.time.year == 2026 for e in events)
    assert all(e.time.tzinfo == timezone.utc for e in events)


def test_qradar_egress_flagged_as_c2(qradar_records):
    """Salir a Internet no es una senal. Sacar 700 MB si.

    Este test exigia T1071.001 -mando y control- en CUALQUIER conexion de una
    IP interna a una publica. Eso es casi todo el trafico de una oficina: con
    esa regla, abrir el correo quedaba etiquetado como command-and-control y
    pesaba igual que una baliza de verdad. Y el informe exportado lo afirmaba.

    Lo que el evento SI demuestra es el volumen. Se marca la transferencia
    grande, y con T1048 y no T1041, porque el segundo afirmaria ademas que el
    canal es de mando y control y eso no consta.
    """
    events = normalize_all(qradar_records)
    salidas = [e for e in events
               if e.src and e.src.ip and e.src.ip.startswith("10.")
               and e.dst and e.dst.ip == "45.132.88.17"]
    assert salidas

    grandes = [e for e in salidas if e.net and e.net.bytes_out
               and e.net.bytes_out > 100 * 1024 * 1024]
    assert grandes, "la muestra tiene una transferencia de 734 MB salientes"
    assert grandes[0].net.bytes_out == 734003200, "los bytes ya no se tiran"
    assert any(t.id == "T1048" for t in grandes[0].mitre)
    assert grandes[0].severity >= 4

    # Y la navegacion normal al mismo destino NO se marca como nada.
    normales = [e for e in salidas if e not in grandes]
    assert normales
    assert not any(t.id == "T1071.001" for e in normales for t in e.mitre)


# ------------------------------------------------------------- CEF/LEEF/syslog


def test_parse_cef_header_and_extensions():
    line = ("CEF:0|Fortinet|FortiGate|7.4.3|13|Traffic Allowed|4|"
            "src=10.4.2.11 spt=51022 dst=45.132.88.17 dpt=443 act=accept "
            "msg=Sesion saliente permitida hacia destino externo")
    record = parse_cef(line)
    assert record["device_vendor"] == "Fortinet"
    assert record["cef_severity"] == "4"
    assert record["src_ip"] == "10.4.2.11"
    assert record["dest_port"] == "443"
    # El valor con espacios llega entero hasta la siguiente clave.
    assert record["message"] == "Sesion saliente permitida hacia destino externo"


def test_parse_leef_tab_delimited():
    line = ("LEEF:2.0|Palo Alto Networks|PAN-OS|11.1|threat|x09|"
            "devTime=Aug 19 2026 09:16:03\tsrc=10.4.2.11\tdst=45.132.88.17\tusrName=jlopez")
    record = parse_leef(line)
    assert record["device_vendor"] == "Palo Alto Networks"
    assert record["src_ip"] == "10.4.2.11"
    # Los nombres propios de LEEF se traducen a los canonicos, igual que en CEF.
    assert record["src_user"] == "jlopez"
    # Sin este alias, los eventos LEEF se quedaban sin fecha y aparecian con la
    # hora de la ingesta, estirando la cronologia del incidente hasta "ahora".
    assert record["time"] == "Aug 19 2026 09:16:03"


def test_parse_syslog_rfc3164():
    line = "<133>Aug 19 09:35:12 SRV-DC01 sshd[41207]: Failed password for invalid user administrator from 10.4.2.11 port 51882 ssh2"
    record = parse_syslog(line)
    assert record["host"] == "SRV-DC01"
    assert record["application"] == "sshd"
    assert "Failed password" in record["message"]
    assert record["syslog_severity"] == 5


def test_syslog_wrapping_cef_yields_cef():
    """Un CEF dentro de syslog tiene que parsearse como CEF, no como syslog."""
    line = "<134>CEF:0|Zscaler|NSSWeblog|6.1|200|Web Request|5|src=10.4.2.11 act=allowed"
    record = parse_syslog(line)
    assert record["__format__"] == "cef"
    assert record["device_vendor"] == "Zscaler"


def test_cef_sample_normalizes(cef_records):
    events = normalize_all(cef_records)
    assert len(events) == len(cef_records), "el generico no debe descartar nada"
    assert all(e.source == "generic" for e in events)

    # 'blocked' salio del vocabulario: un bloqueo es una conexion con status de
    # fallo. Este test exigia la actividad, que era el mismo dato en dos sitios;
    # medido antes de quitarla, colapsarla dejaba nodos, aristas y frase
    # identicos en los tres eventos que la llevaban.
    bloqueos = [e for e in events
                if e.class_name == CLASS_NETWORK and e.status == "failure"]
    assert bloqueos, "act=blocked / act=deny siguen siendo un fallo"
    assert all(e.activity == "network_connect" for e in bloqueos)
    assert "blocked" not in {e.activity for e in events}

    ssh_failures = [e for e in events
                    if e.class_name == CLASS_AUTHENTICATION and e.status == "failure"]
    assert len(ssh_failures) >= 2
    # Y con el usuario y la IP SACADOS DE LA FRASE. Antes se quedaban dentro de
    # la cadena del mensaje y el evento llegaba al grafo sin nadie y sin origen:
    # una fuerza bruta SSH no dibujaba una sola arista.
    assert all(e.actor and e.actor.user for e in ssh_failures)
    assert all(e.src and e.src.ip == "10.4.2.11" for e in ssh_failures)

    # El acceso que SI entra viene de otra maquina: es un logon remoto, y esa
    # diferencia es la que dibuja la arista de movimiento lateral.
    remotos = [e for e in events if e.activity == "logon_remote"]
    assert remotos and remotos[0].actor.user == "jlopez"


# ------------------------------------------------------------------- conjunto


def test_every_sample_record_is_normalized(all_events, splunk_records, sentinel_records,
                                           qradar_records, cef_records):
    """Ningun registro de ejemplo debe quedarse sin normalizador."""
    total = len(splunk_records) + len(sentinel_records) + len(qradar_records) + len(cef_records)
    assert len(all_events) == total


def test_raw_is_always_preserved(all_events):
    assert all(event.raw for event in all_events)


def test_uid_is_stable(splunk_records):
    first = normalize_all(splunk_records)
    second = normalize_all(splunk_records)
    assert [e.uid for e in first] == [e.uid for e in second]
    assert len({e.uid for e in first}) == len(first), "no debe haber colisiones"


@pytest.mark.parametrize("raw,expected_hour,expected_minute", [
    ("Aug 19 2026 09:16:02", 9, 16),      # CEF 'rt'
    ("19 Aug 2026 09:16:02", 9, 16),
    ("2026-08-19 09:16:02", 9, 16),
    ("08/19/2026 09:16:02", 9, 16),
])
def test_parse_time_handles_dated_text_formats(raw, expected_hour, expected_minute):
    """Un formato con fecha que no se reconoce cae a 'ahora' y falsea todo.

    Es el peor fallo posible en esta herramienta: no rompe nada visible, pero
    coloca los eventos en el momento de la ingesta y la cronologia del incidente
    deja de significar nada.
    """
    parsed = parse_time(raw)
    assert parsed.year == 2026 and parsed.month == 8 and parsed.day == 19
    assert parsed.hour == expected_hour and parsed.minute == expected_minute


def test_no_sample_event_falls_back_to_now(all_events):
    """Ningun evento de los ficheros de ejemplo puede acabar con la hora actual."""
    from datetime import datetime, timezone
    now = datetime.now(timezone.utc)
    stragglers = [e for e in all_events if abs((now - e.time).total_seconds()) < 300]
    assert not stragglers, (
        "eventos sin fecha valida: "
        + ", ".join(f"{e.source}/{e.origin}" for e in stragglers)
    )


def test_demo_incident_lasts_about_an_hour(all_events):
    times = sorted(event.time for event in all_events)
    span = times[-1] - times[0]
    assert span.total_seconds() < 3 * 3600, f"el incidente de demo dura {span}, demasiado"
