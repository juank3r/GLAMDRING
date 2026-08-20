"""Deteccion de herramientas de intrusion y de comportamiento de ransomware.

Tres capas, de mas concreta a mas general:

1. **Herramientas conocidas.** Se busca el nombre del ejecutable en el catalogo
   de la Ransomware Tool Matrix. Barato y preciso.
2. **Notas de rescate.** Un fichero llamado `RECOVER-FILES.txt` apareciendo en un
   servidor de ficheros es la senal mas tardia y mas inequivoca que existe, y
   ademas atribuye.
3. **Comportamiento.** Secuencias que delatan un despliegue de ransomware
   independientemente del grupo: borrar instantaneas, inhibir la recuperacion,
   parar el antivirus, cifrado masivo. Aqui no importa quien es, importa que
   esta a punto de pasar.

La tercera capa es la que salva el caso cuando el grupo es nuevo y no esta en
ningun catalogo, que es exactamente cuando mas falta hace.
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set

from ..models import (
    CLASS_FILE,
    CLASS_NETWORK,
    CLASS_PROCESS,
    NormalizedEvent,
)
from .catalog import Catalog, basename_of, binaries_in, catalog

# ---------------------------------------------------------------------------
# Etapas de un despliegue de ransomware
#
# El orden ES el orden. Sirve para decir "vas por aqui" y, mas util todavia,
# "lo siguiente seria esto".
# ---------------------------------------------------------------------------
STAGES: List[Dict[str, str]] = [
    {"id": "access", "label": "Acceso inicial",
     "hint": "Phishing, credencial valida o servicio expuesto."},
    {"id": "foothold", "label": "Punto de apoyo y control remoto",
     "hint": "Se instala una herramienta RMM o un implante para no depender del acceso original."},
    {"id": "discovery", "label": "Reconocimiento",
     "hint": "Se enumera el dominio, la red y los recursos compartidos."},
    {"id": "credentials", "label": "Robo de credenciales",
     "hint": "Volcado de LSASS, NTDS o gestores de contrasenas."},
    {"id": "lateral", "label": "Movimiento lateral",
     "hint": "Se salta a otros equipos, normalmente hacia servidores y controladores."},
    {"id": "exfiltration", "label": "Exfiltracion",
     "hint": "Se sacan los datos ANTES de cifrar: es la palanca de la doble extorsion."},
    {"id": "inhibit", "label": "Inhibicion de la recuperacion",
     "hint": "Se borran instantaneas y copias para que restaurar no sea una opcion."},
    {"id": "impact", "label": "Cifrado y nota de rescate",
     "hint": "El cifrado ya esta en marcha."},
]

STAGE_ORDER = {stage["id"]: index for index, stage in enumerate(STAGES)}

# Categoria de herramienta -> etapa en la que suele aparecer.
CATEGORY_STAGE = {
    "RMM Tools": "foothold",
    "Discovery": "discovery",
    "Credential Theft": "credentials",
    "OffSec": "lateral",
    "Networking": "exfiltration",
    "Exfiltration": "exfiltration",
    "Defense Evasion": "inhibit",
    "LOLBAS": "discovery",
}


# ---------------------------------------------------------------------------
# Firmas de comportamiento
#
# Cada una es una regla sobre la linea de comandos. Se comentan una a una porque
# el criterio de "que cuenta como ransomware" es justo lo discutible.
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Signature:
    id: str
    label: str
    stage: str
    severity: int          # 0-5, la que se le impone al hallazgo
    pattern: re.Pattern
    why: str               # por que esto importa, para el informe
    mitre: str = ""


SIGNATURES: List[Signature] = [
    Signature(
        "shadow_copy_delete", "Borrado de instantaneas de volumen", "inhibit", 5,
        re.compile(r"vssadmin(\.exe)?\s+.*delete\s+shadows|"
                   r"wmic(\.exe)?\s+shadowcopy\s+delete|"
                   r"win32_shadowcopy.*\.delete\(\)|"
                   r"delete-?\s*shadow", re.I),
        "Borrar las instantaneas es el paso que convierte un incidente en un "
        "desastre: sin ellas, restaurar deja de ser una opcion barata. Casi "
        "siempre ocurre minutos antes del cifrado.",
        "T1490"),
    Signature(
        "recovery_disable", "Recuperacion de Windows deshabilitada", "inhibit", 5,
        re.compile(r"bcdedit(\.exe)?\s+.*(recoveryenabled\s+no|"
                   r"bootstatuspolicy\s+ignoreallfailures)", re.I),
        "Se desactiva el arranque de recuperacion para que el equipo no pueda "
        "auto-repararse tras el cifrado.",
        "T1490"),
    Signature(
        "backup_catalog_delete", "Catalogo de copias de seguridad borrado", "inhibit", 5,
        re.compile(r"wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)|"
                   r"vssadmin(\.exe)?\s+resize\s+shadowstorage", re.I),
        "Sin catalogo de copias, la restauracion desde Windows Backup deja de "
        "funcionar aunque los datos sigan ahi.",
        "T1490"),
    Signature(
        "backup_service_stop", "Servicios de copia de seguridad detenidos", "inhibit", 4,
        re.compile(r"(net|sc)(\.exe)?\s+stop\s+.*(veeam|backup|acronis|sql|"
                   r"vss|sqlwriter|msexchange)", re.I),
        "Se para el software de copias y las bases de datos para poder cifrar "
        "ficheros que estarian bloqueados.",
        "T1489"),
    Signature(
        "defender_disable", "Proteccion antivirus desactivada", "inhibit", 5,
        re.compile(r"set-mppreference\s+.*-disable|"
                   r"add-mppreference\s+.*-exclusionpath|"
                   r"(net|sc)(\.exe)?\s+stop\s+(windefend|sense|sophos|"
                   r"symantec|mcafee|crowdstrike|sentinelone)|"
                   r"uninstall.*(sophos|sentinelone|crowdstrike)", re.I),
        "Desactivar o excluir el antivirus justo antes del cifrado es el paso "
        "que hace que el binario final no se detecte.",
        "T1562.001"),
    Signature(
        "event_log_clear", "Registro de eventos borrado", "inhibit", 4,
        re.compile(r"wevtutil(\.exe)?\s+cl\b|clear-eventlog|"
                   r"(net|sc)(\.exe)?\s+stop\s+eventlog", re.I),
        "Se borra la telemetria. Todo lo que venga despues de este momento "
        "puede estar incompleto, y eso condiciona la investigacion entera.",
        "T1070.001"),
    Signature(
        "safe_mode_boot", "Arranque forzado en modo seguro", "inhibit", 5,
        re.compile(r"bcdedit(\.exe)?\s+.*safeboot|"
                   r"bootcfg\s+.*safeboot", re.I),
        "Varias familias arrancan en modo seguro para cifrar con el antivirus "
        "descargado. Es una firma muy especifica de despliegue de ransomware.",
        "T1562.009"),
    Signature(
        "mass_deploy", "Despliegue remoto masivo", "lateral", 4,
        re.compile(r"(psexec|paexec)(\.exe)?\s+.*(@|\\\\)|"
                   r"wmic(\.exe)?\s+/node:.*process\s+call\s+create|"
                   r"invoke-command\s+.*-computername\s+.*@|"
                   r"pdqdeploy|"
                   r"gpupdate\s+/force.*\\\\", re.I),
        "Ejecutar el mismo binario contra una lista de equipos es como se "
        "reparte el ransomware por el dominio en el ultimo minuto.",
        "T1021.002"),
    Signature(
        "exfil_tooling", "Herramienta de exfiltracion en marcha", "exfiltration", 4,
        re.compile(r"rclone(\.exe)?\s+.*(copy|sync|move)\b|"
                   r"megacmd|megasync|"
                   r"winscp(\.exe|\.com)?\s+.*(put|synchronize)|"
                   r"(curl|wget)(\.exe)?\s+.*(-T|--upload-file)", re.I),
        "Los datos salen ANTES de cifrar. Si esto ha ocurrido, hay brecha de "
        "datos aunque se restaure todo sin pagar.",
        "T1567"),
    Signature(
        "archive_staging", "Datos empaquetados para sacarlos", "exfiltration", 3,
        re.compile(r"(7z|7za|rar|winrar)(\.exe)?\s+a\s+.*(-p|-hp)|"
                   r"compress-archive\s+.*-destinationpath", re.I),
        "Comprimir con contrasena antes de subir es el paso previo tipico de la "
        "exfiltracion, y ademas dificulta la inspeccion en el perimetro.",
        "T1560"),
    Signature(
        "credential_dump", "Volcado de credenciales", "credentials", 5,
        re.compile(r"sekurlsa|lsadump|"
                   r"comsvcs\.dll.*minidump|"
                   r"procdump(\.exe|64\.exe)?\s+.*lsass|"
                   r"ntdsutil.*ifm|"
                   r"reg(\.exe)?\s+save\s+hklm\\(sam|system|security)", re.I),
        "Con las credenciales del dominio, el atacante deja de necesitar "
        "exploits: se mueve como un administrador mas.",
        "T1003"),
    Signature(
        "domain_recon", "Enumeracion del dominio", "discovery", 3,
        re.compile(r"\bnltest\b.*dclist|"
                   r"net(\.exe|1\.exe)?\s+group\s+.*domain\s+admins|"
                   r"\badfind\b|\bsharphound\b|\bbloodhound\b|"
                   r"get-adcomputer|get-aduser|get-domain", re.I),
        "Enumerar administradores y controladores de dominio es lo que hace "
        "todo atacante antes de decidir por donde escalar.",
        "T1087"),
    Signature(
        "share_enum", "Barrido de recursos compartidos", "discovery", 3,
        re.compile(r"net(\.exe|1\.exe)?\s+(view|share)\b|"
                   r"\bnetscan\b|softperfect|"
                   r"\bsmbclient\b.*-L", re.I),
        "Localizar los recursos compartidos es como se decide que se cifra "
        "primero y que se roba.",
        "T1135"),
]


# ---------------------------------------------------------------------------
# Resultados
# ---------------------------------------------------------------------------

@dataclass
class ToolSighting:
    """Una herramienta conocida vista en un evento."""

    tool: str
    category: str
    category_label: str
    stage: str
    groups: List[str]
    where: str                       # 'process' | 'cmdline' | 'file'
    evidence: str
    node_hint: str                   # host o entidad donde se vio
    event_uid: str
    time: Optional[datetime]
    weight: float = 1.0


@dataclass
class NoteSighting:
    """Una nota de rescate encontrada en el sistema de ficheros."""

    filename: str
    groups: List[str]
    path: str
    node_hint: str
    event_uid: str
    time: Optional[datetime]
    known: bool = True               # False si encaja por heuristica generica


@dataclass
class BehaviourHit:
    """Una firma de comportamiento que ha disparado."""

    signature: Signature
    evidence: str
    node_hint: str
    event_uid: str
    time: Optional[datetime]


@dataclass
class Findings:
    tools: List[ToolSighting] = field(default_factory=list)
    notes: List[NoteSighting] = field(default_factory=list)
    behaviours: List[BehaviourHit] = field(default_factory=list)

    def tool_names(self) -> Set[str]:
        return {sighting.tool for sighting in self.tools}

    def stages_seen(self) -> List[str]:
        vistas = {sighting.stage for sighting in self.tools if sighting.stage}
        vistas |= {hit.signature.stage for hit in self.behaviours}
        if self.notes:
            vistas.add("impact")
        return sorted(vistas, key=lambda stage: STAGE_ORDER.get(stage, 99))


# ---------------------------------------------------------------------------
# Deteccion generica de notas de rescate
#
# Para grupos que no estan en ningun catalogo. Se exige que el fichero este en
# un sitio donde una nota tiene sentido y que el nombre encaje en formas muy
# tipicas; aun asi es la parte con mas riesgo de falso positivo, y por eso los
# hallazgos por esta via se marcan con `known=False`.
# ---------------------------------------------------------------------------
_GENERIC_NOTE = re.compile(
    r"^(!{1,3}[-_ ]?)?"
    r"(read[-_ ]?me|readme|how[-_ ]?to[-_ ]?(decrypt|restore|recover)|"
    r"recover[-_ ]?(files|your[-_ ]?files|data)|restore[-_ ]?(files|my[-_ ]?files)|"
    r"decrypt[-_ ]?(files|info|note)|your[-_ ]?files|"
    r"what[-_ ]?happened|attention|unlock[-_ ]?files)"
    r"[-_ a-z0-9]*\.(txt|hta|html|htm|README)$",
    re.I,
)

# Extensiones que una nota de rescate no tiene nunca.
_NOT_A_NOTE = {".exe", ".dll", ".sys", ".log", ".json", ".xml", ".csv"}


def _looks_like_note(filename: str) -> bool:
    base = basename_of(filename)
    if not base or any(base.endswith(ext) for ext in _NOT_A_NOTE):
        return False
    return bool(_GENERIC_NOTE.match(base))


# ---------------------------------------------------------------------------
# Motor
# ---------------------------------------------------------------------------

def _host_of(event: NormalizedEvent) -> str:
    for ref in (event.device, event.src, event.dst):
        if ref is None:
            continue
        if ref.hostname:
            return ref.hostname
        if ref.ip:
            return ref.ip
    return "desconocido"


def _scan_event(event: NormalizedEvent, kb: Catalog, findings: Findings) -> None:
    host = _host_of(event)

    # -- capa 1: herramientas conocidas ------------------------------------
    candidatos: List[tuple] = []          # (binario, donde, evidencia)

    if event.process:
        for value in (event.process.name, event.process.path):
            base = basename_of(value or "")
            if base:
                candidatos.append((base, "process", value or base))
        if event.process.cmdline:
            for binario in binaries_in(event.process.cmdline):
                candidatos.append((binario, "cmdline", event.process.cmdline[:200]))

    if event.file:
        for value in (event.file.name, event.file.path):
            base = basename_of(value or "")
            if base:
                candidatos.append((base, "file", value or base))

    vistos: Set[str] = set()
    for binario, donde, evidencia in candidatos:
        nombre = kb.tool_for_binary(binario)
        if not nombre or nombre in vistos:
            continue
        herramienta = kb.tools.get(nombre, {})
        # Las herramientas marcadas como exactOnly no valen desde la linea de
        # comandos: 'net' o 'reg' aparecen en cualquier sitio.
        if herramienta.get("exactOnly") and donde == "cmdline":
            continue
        vistos.add(nombre)
        categoria = herramienta.get("category", "")
        findings.tools.append(ToolSighting(
            tool=nombre,
            category=categoria,
            category_label=herramienta.get("categoryLabel", categoria),
            stage=CATEGORY_STAGE.get(categoria, ""),
            groups=list(herramienta.get("groups", [])),
            where=donde,
            evidence=str(evidencia)[:200],
            node_hint=host,
            event_uid=event.uid,
            time=event.time,
            weight=kb.discriminating_weight(nombre),
        ))

    # Fragmentos: solo dentro de la linea de comandos y solo los largos.
    if event.process and event.process.cmdline:
        bajo = event.process.cmdline.lower()
        for fragmento, nombre in kb.fragment_index.items():
            if nombre in vistos:
                continue
            if fragmento in bajo:
                vistos.add(nombre)
                herramienta = kb.tools.get(nombre, {})
                categoria = herramienta.get("category", "")
                findings.tools.append(ToolSighting(
                    tool=nombre, category=categoria,
                    category_label=herramienta.get("categoryLabel", categoria),
                    stage=CATEGORY_STAGE.get(categoria, ""),
                    groups=list(herramienta.get("groups", [])),
                    where="cmdline", evidence=event.process.cmdline[:200],
                    node_hint=host, event_uid=event.uid, time=event.time,
                    weight=kb.discriminating_weight(nombre),
                ))

    # -- capa 2: notas de rescate ------------------------------------------
    if event.class_name == CLASS_FILE and event.file:
        nombre_fichero = event.file.name or basename_of(event.file.path or "")
        entrada = kb.note_for_filename(basename_of(nombre_fichero))
        if entrada:
            findings.notes.append(NoteSighting(
                filename=entrada["filename"],
                groups=list(entrada.get("groups", [])),
                path=event.file.path or nombre_fichero,
                node_hint=host, event_uid=event.uid, time=event.time, known=True,
            ))
        elif _looks_like_note(nombre_fichero):
            findings.notes.append(NoteSighting(
                filename=nombre_fichero, groups=[],
                path=event.file.path or nombre_fichero,
                node_hint=host, event_uid=event.uid, time=event.time, known=False,
            ))

    # -- capa 3: comportamiento --------------------------------------------
    texto = " ".join(filter(None, [
        event.process.cmdline if event.process else None,
        event.message,
    ]))[:4000]
    if texto:
        for firma in SIGNATURES:
            if firma.pattern.search(texto):
                findings.behaviours.append(BehaviourHit(
                    signature=firma,
                    evidence=texto[:220],
                    node_hint=host,
                    event_uid=event.uid,
                    time=event.time,
                ))


def scan(events: Iterable[NormalizedEvent], kb: Optional[Catalog] = None) -> Findings:
    """Recorre los eventos y devuelve todo lo detectado."""
    kb = kb or catalog()
    findings = Findings()
    if not kb.available:
        return findings
    for event in events:
        _scan_event(event, kb, findings)
    return findings


# ---------------------------------------------------------------------------
# Sintesis
# ---------------------------------------------------------------------------

def stage_assessment(findings: Findings) -> List[Dict[str, Any]]:
    """En que etapas hay evidencia y cual seria la siguiente.

    Lo util no es tanto saber por donde va como saber que falta por pasar: si
    hay exfiltracion pero todavia no se han borrado las instantaneas, queda
    margen para actuar.
    """
    por_etapa: Dict[str, List[Dict[str, str]]] = defaultdict(list)

    for sighting in findings.tools:
        if sighting.stage:
            por_etapa[sighting.stage].append({
                "kind": "tool", "label": sighting.tool,
                "detail": sighting.category_label, "where": sighting.node_hint,
            })
    for hit in findings.behaviours:
        por_etapa[hit.signature.stage].append({
            "kind": "behaviour", "label": hit.signature.label,
            "detail": hit.signature.mitre, "where": hit.node_hint,
        })
    for note in findings.notes:
        por_etapa["impact"].append({
            "kind": "note", "label": note.filename,
            "detail": "nota de rescate", "where": note.node_hint,
        })

    salida: List[Dict[str, Any]] = []
    for etapa in STAGES:
        evidencias = por_etapa.get(etapa["id"], [])
        # Se recorta la evidencia repetida: doce apariciones de rclone son una.
        unicas: List[Dict[str, str]] = []
        etiquetas: Set[str] = set()
        for item in evidencias:
            clave = f"{item['kind']}|{item['label']}"
            if clave in etiquetas:
                continue
            etiquetas.add(clave)
            unicas.append(item)
        salida.append({
            "id": etapa["id"],
            "label": etapa["label"],
            "hint": etapa["hint"],
            "reached": bool(unicas),
            "evidence": unicas[:8],
            "count": len(evidencias),
        })
    return salida


def severity_floor(findings: Findings) -> int:
    """Severidad minima que merece lo detectado, para elevar el riesgo del grafo."""
    if findings.notes:
        return 5
    if any(hit.signature.severity >= 5 for hit in findings.behaviours):
        return 5
    if findings.behaviours:
        return max(hit.signature.severity for hit in findings.behaviours)
    if findings.tools:
        return 3
    return 0


def summarize(findings: Findings) -> Dict[str, Any]:
    """Resumen compacto para la API, el informe y la interfaz."""
    por_categoria: Dict[str, List[str]] = defaultdict(list)
    for sighting in findings.tools:
        if sighting.tool not in por_categoria[sighting.category_label]:
            por_categoria[sighting.category_label].append(sighting.tool)

    etapas = stage_assessment(findings)
    alcanzadas = [etapa for etapa in etapas if etapa["reached"]]
    siguiente = next((etapa for etapa in etapas if not etapa["reached"]
                      and STAGE_ORDER[etapa["id"]] > (
                          STAGE_ORDER[alcanzadas[-1]["id"]] if alcanzadas else -1)), None)

    return {
        "toolCount": len(findings.tool_names()),
        "toolsByCategory": dict(por_categoria),
        "behaviourCount": len({hit.signature.id for hit in findings.behaviours}),
        "behaviours": [
            {
                "id": hit.signature.id, "label": hit.signature.label,
                "stage": hit.signature.stage, "severity": hit.signature.severity,
                "mitre": hit.signature.mitre, "why": hit.signature.why,
                "where": hit.node_hint, "evidence": hit.evidence,
                "uid": hit.event_uid,
                "time": hit.time.isoformat() if hit.time else None,
            }
            for hit in _dedupe_behaviours(findings.behaviours)
        ],
        "ransomNotes": [
            {
                "filename": note.filename, "path": note.path,
                "groups": note.groups, "where": note.node_hint,
                "known": note.known, "uid": note.event_uid,
                "time": note.time.isoformat() if note.time else None,
            }
            for note in findings.notes
        ],
        "stages": etapas,
        "nextStage": siguiente,
        "severityFloor": severity_floor(findings),
    }


def _dedupe_behaviours(hits: Sequence[BehaviourHit]) -> List[BehaviourHit]:
    """Una firma por equipo: si vssadmin corre en cuarenta hosts son cuarenta,
    pero cuarenta veces en el mismo host es una."""
    vistos: Set[str] = set()
    salida: List[BehaviourHit] = []
    for hit in sorted(hits, key=lambda h: h.time or datetime.min):
        clave = f"{hit.signature.id}|{hit.node_hint}"
        if clave in vistos:
            continue
        vistos.add(clave)
        salida.append(hit)
    return salida
