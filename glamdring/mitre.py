"""Catalogo minimo de MITRE ATT&CK y heuristicas de etiquetado.

No pretende ser ATT&CK entero: solo las tecnicas que aparecen de verdad en un
incidente Windows/cloud tipico, que son las que alimentan las capas de la vista
kill-chain. Si el SIEM ya trae la tecnica (Sentinel y Defender suelen traerla),
se usa la suya y esto solo rellena nombre y tactica.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .models import Technique

# id -> (nombre, tactica)
TECHNIQUES: Dict[str, Tuple[str, str]] = {
    "T1078":     ("Valid Accounts", "initial-access"),
    "T1078.004": ("Valid Accounts: Cloud Accounts", "initial-access"),
    "T1566":     ("Phishing", "initial-access"),
    "T1566.002": ("Phishing: Spearphishing Link", "initial-access"),
    "T1189":     ("Drive-by Compromise", "initial-access"),
    "T1190":     ("Exploit Public-Facing Application", "initial-access"),
    "T1059":     ("Command and Scripting Interpreter", "execution"),
    "T1059.001": ("PowerShell", "execution"),
    "T1059.003": ("Windows Command Shell", "execution"),
    "T1059.005": ("Visual Basic", "execution"),
    "T1204":     ("User Execution", "execution"),
    "T1204.002": ("User Execution: Malicious File", "execution"),
    "T1053":     ("Scheduled Task/Job", "persistence"),
    "T1053.005": ("Scheduled Task", "persistence"),
    "T1543.003": ("Windows Service", "persistence"),
    "T1547.001": ("Registry Run Keys / Startup Folder", "persistence"),
    "T1136":     ("Create Account", "persistence"),
    "T1068":     ("Exploitation for Privilege Escalation", "privilege-escalation"),
    "T1134":     ("Access Token Manipulation", "privilege-escalation"),
    "T1548":     ("Abuse Elevation Control Mechanism", "privilege-escalation"),
    "T1027":     ("Obfuscated Files or Information", "defense-evasion"),
    "T1070":     ("Indicator Removal", "defense-evasion"),
    "T1070.001": ("Clear Windows Event Logs", "defense-evasion"),
    "T1562.001": ("Impair Defenses: Disable or Modify Tools", "defense-evasion"),
    "T1218":     ("System Binary Proxy Execution", "defense-evasion"),
    "T1003":     ("OS Credential Dumping", "credential-access"),
    "T1003.001": ("LSASS Memory", "credential-access"),
    "T1110":     ("Brute Force", "credential-access"),
    "T1110.001": ("Password Guessing", "credential-access"),
    "T1555":     ("Credentials from Password Stores", "credential-access"),
    "T1087":     ("Account Discovery", "discovery"),
    "T1018":     ("Remote System Discovery", "discovery"),
    "T1082":     ("System Information Discovery", "discovery"),
    "T1046":     ("Network Service Discovery", "discovery"),
    "T1021":     ("Remote Services", "lateral-movement"),
    "T1021.001": ("Remote Desktop Protocol", "lateral-movement"),
    "T1021.002": ("SMB/Windows Admin Shares", "lateral-movement"),
    "T1021.006": ("Windows Remote Management", "lateral-movement"),
    "T1570":     ("Lateral Tool Transfer", "lateral-movement"),
    "T1005":     ("Data from Local System", "collection"),
    "T1560":     ("Archive Collected Data", "collection"),
    "T1071":     ("Application Layer Protocol", "command-and-control"),
    "T1071.001": ("Web Protocols", "command-and-control"),
    "T1105":     ("Ingress Tool Transfer", "command-and-control"),
    "T1571":     ("Non-Standard Port", "command-and-control"),
    "T1572":     ("Protocol Tunneling", "command-and-control"),
    "T1041":     ("Exfiltration Over C2 Channel", "exfiltration"),
    "T1567":     ("Exfiltration Over Web Service", "exfiltration"),
    "T1048":     ("Exfiltration Over Alternative Protocol", "exfiltration"),
    "T1486":     ("Data Encrypted for Impact", "impact"),
    "T1490":     ("Inhibit System Recovery", "impact"),
    "T1489":     ("Service Stop", "impact"),
}

_TECHNIQUE_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")


def technique(technique_id: str) -> Optional[Technique]:
    """Construye una Technique completa a partir del id.

    Si el id es una subtecnica desconocida (T1059.999) cae a la tecnica padre,
    que es lo unico que hace falta para colocar el nodo en su capa.

    Lo que NO se acepta es cualquier cosa que no tenga forma de identificador de
    ATT&CK. Antes se devolvia ``Technique(id=<lo que fuera>, name="")``, y por
    ahi se colaban al grafo y al informe cosas como
    ``Technique(id='MALWARE DETECTED')``: las categorias de una ofensa de QRadar
    convertidas en tecnicas que no existen.

    En un informe que alguien va a firmar, una tecnica inventada es peor que
    ninguna: quien lo lea la va a buscar en el catalogo de MITRE y no la va a
    encontrar, y a partir de ahi ya no se fia de las demas.
    """
    if not technique_id:
        return None
    tid = str(technique_id).strip().upper()
    if not _TECHNIQUE_RE.fullmatch(tid):
        return None
    if tid in TECHNIQUES:
        name, tactic = TECHNIQUES[tid]
        return Technique(id=tid, name=name, tactic=tactic)
    parent = tid.split(".", 1)[0]
    if parent in TECHNIQUES:
        name, tactic = TECHNIQUES[parent]
        return Technique(id=tid, name=name, tactic=tactic)
    # Forma valida pero fuera de nuestro catalogo: se conserva el id, que es
    # comprobable, y se deja claro que no sabemos ponerle nombre ni tactica.
    return Technique(id=tid, name="", tactic="")


def techniques(ids: object) -> List[Technique]:
    """Acepta lista, cadena separada por comas o texto libre con ids dentro."""
    if not ids:
        return []
    if isinstance(ids, str):
        # SOLO lo que tenga forma de id. Antes, si el texto no traia ninguno, se
        # partia por comas y se aceptaba lo que saliera: pasarle "Malware
        # Detected, Suspicious Activity" devolvia dos tecnicas inventadas.
        raw_ids = _TECHNIQUE_RE.findall(ids.upper())
    elif isinstance(ids, (list, tuple, set)):
        raw_ids = [str(i) for i in ids]
    else:
        raw_ids = [str(ids)]

    out: List[Technique] = []
    seen = set()
    for raw in raw_ids:
        item = technique(raw)
        if item and item.id and item.id not in seen:
            seen.add(item.id)
            out.append(item)
    return out


# ---------------------------------------------------------------------------
# Heuristicas: cuando el SIEM no etiqueta, deducimos por linea de comandos
# ---------------------------------------------------------------------------

_CMDLINE_RULES: List[Tuple[re.Pattern, str]] = [
    (re.compile(r"\b(powershell|pwsh)\b.*?(-enc|-encodedcommand|-e\s+[A-Za-z0-9+/=]{20,})", re.I), "T1027"),
    (re.compile(r"\b(powershell|pwsh)\b", re.I), "T1059.001"),
    (re.compile(r"\bcmd\.exe\b|\bcmd\b\s+/c", re.I), "T1059.003"),
    (re.compile(r"\b(wscript|cscript|mshta)\b", re.I), "T1059.005"),
    (re.compile(r"\brundll32\b|\bregsvr32\b|\bmsbuild\b|\binstallutil\b", re.I), "T1218"),
    (re.compile(r"\bschtasks\b|\bat\.exe\b", re.I), "T1053.005"),
    (re.compile(r"\bsc\.exe\b\s+create|\bnew-service\b", re.I), "T1543.003"),
    (re.compile(r"\breg\b.*\\(run|runonce)\b", re.I), "T1547.001"),
    (re.compile(r"\bnet\b\s+user\b.*\/add|\bnew-localuser\b", re.I), "T1136"),
    (re.compile(r"\bprocdump\b|\bcomsvcs\.dll\b.*minidump|\bmimikatz\b|\bsekurlsa\b", re.I), "T1003.001"),
    (re.compile(r"\bnet\b\s+(user|group)\b|\bwhoami\b\s+\/all|\bnet\b\s+localgroup", re.I), "T1087"),
    (re.compile(r"\bnet\b\s+view\b|\bnltest\b|\barp\b\s+-a", re.I), "T1018"),
    (re.compile(r"\bsysteminfo\b|\bhostname\b\s*$", re.I), "T1082"),
    (re.compile(r"\bpsexec\b|\\admin\$|\\c\$|\bwmic\b.*\/node:", re.I), "T1021.002"),
    (re.compile(r"\bmstsc\b|\bxfreerdp\b", re.I), "T1021.001"),
    (re.compile(r"\bwinrs\b|\benter-pssession\b|\binvoke-command\b", re.I), "T1021.006"),
    (re.compile(r"\bcertutil\b.*-urlcache|\bbitsadmin\b.*\/transfer|\b(curl|wget)\b|invoke-webrequest|downloadstring", re.I), "T1105"),
    (re.compile(r"\bwevtutil\b\s+cl|clear-eventlog", re.I), "T1070.001"),
    (re.compile(r"\bset-mppreference\b.*disable|\bnetsh\b.*firewall.*off", re.I), "T1562.001"),
    (re.compile(r"\bvssadmin\b.*delete\s+shadows|\bwbadmin\b.*delete", re.I), "T1490"),
    (re.compile(r"\b(rar|7z|zip)\b.*-p|compress-archive", re.I), "T1560"),
]


def infer_from_cmdline(cmdline: Optional[str]) -> List[Technique]:
    """Etiqueta un proceso por su linea de comandos.

    Se para en la primera coincidencia de cada tecnica pero recorre todas las
    reglas: un ``powershell -enc ... certutil -urlcache`` merece T1027 y T1105.
    """
    if not cmdline:
        return []
    out: List[Technique] = []
    seen = set()
    for pattern, tid in _CMDLINE_RULES:
        if pattern.search(cmdline) and tid not in seen:
            seen.add(tid)
            item = technique(tid)
            if item:
                out.append(item)
    return out
