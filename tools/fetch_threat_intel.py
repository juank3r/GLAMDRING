"""Descarga y normaliza la inteligencia de amenazas a ficheros locales.

    python tools/fetch_threat_intel.py

Escribe en glamdring/threat/data/:

    tools.json        herramienta -> categoria, patrones de deteccion y grupos
    groups.json       grupo -> herramientas por categoria, alias y fuentes
    ransomnotes.json  nombre de nota de rescate -> grupos
    meta.json         de donde salio cada cosa y cuando

Se vendoriza a proposito, igual que las librerias del frontend: la herramienta
tiene que arrancar en un portatil aislado de un SOC sin depender de que GitHub o
ransomware.live respondan. Volver a ejecutar este script es la forma de
actualizar.

FUENTES Y ATRIBUCION
--------------------
* Ransomware Tool Matrix - BushidoUK - CC BY 4.0
  https://github.com/BushidoUK/Ransomware-Tool-Matrix
  Que herramientas usa cada grupo de ransomware, por categoria.

* ransomware.live - Julien Mousqueton
  https://www.ransomware.live/
  Indice de notas de rescate por grupo y metadatos de los grupos.

Los dos creditos viajan en meta.json y salen en el informe. Es un requisito de la
licencia CC BY, y ademas es de justicia: el valor de esta funcionalidad es suyo.
"""

from __future__ import annotations

import csv
import io
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Set

DATA_DIR = Path(__file__).resolve().parent.parent / "glamdring" / "threat" / "data"

RTM_RAW = "https://raw.githubusercontent.com/BushidoUK/Ransomware-Tool-Matrix/main"
RTM_API = "https://api.github.com/repos/BushidoUK/Ransomware-Tool-Matrix/contents"
LIVE_NOTES = "https://www.ransomware.live/ransomnotes"
LIVE_GROUPS = "https://api.ransomware.live/groups"

UA = {"User-Agent": "glamdring-threat-intel/1.0"}

# ---------------------------------------------------------------------------
# Alias de proceso
#
# La matriz de herramientas trae nombres COMERCIALES ("Advanced IP Scanner"),
# pero en un log de Sysmon lo que aparece es el nombre del ejecutable
# ("advanced_ip_scanner.exe"). Sin este puente la deteccion no encuentra nada.
#
# Es una tabla CURADA a mano: no sale de ninguna fuente, y por eso es la parte
# mas fragil del modulo. Cubre las herramientas que mas se ven; para el resto se
# derivan candidatos automaticamente (ver `_derive_patterns`).
# ---------------------------------------------------------------------------
ALIASES: Dict[str, List[str]] = {
    "Advanced IP Scanner": ["advanced_ip_scanner.exe", "advanced_ip_scanner_console.exe"],
    "Advanced Port Scanner": ["advanced_port_scanner.exe"],
    "Angry IP Scanner": ["ipscan.exe", "angryip.exe"],
    "AnyDesk": ["anydesk.exe"],
    "Atera": ["ateraagent.exe", "atera.exe", "syncrosetup.exe"],
    "Action1": ["action1_agent.exe", "action1.exe"],
    "BCDEdit": ["bcdedit.exe"],
    "BITSAdmin": ["bitsadmin.exe"],
    "Bloodhound": ["sharphound.exe", "azurehound.exe", "bloodhound.exe"],
    "SharpHound": ["sharphound.exe", "sharphound.ps1"],
    "Chisel": ["chisel.exe"],
    "Cloudflared": ["cloudflared.exe"],
    "Cobalt Strike": ["beacon.exe", "artifact.exe", "cobaltstrike"],
    "CrackMapExec": ["crackmapexec.exe", "cme.exe", "nxc.exe", "netexec.exe"],
    "Defender Control": ["dcontrol.exe", "defendercontrol.exe"],
    "FileZilla": ["filezilla.exe"],
    "GMER": ["gmer.exe"],
    "Impacket": ["wmiexec.py", "smbexec.py", "psexec.py", "secretsdump.py", "atexec.py"],
    "LaZagne": ["lazagne.exe"],
    "MEGA": ["megasync.exe", "megacmd.exe", "megaclient.exe"],
    "MeshAgent": ["meshagent.exe"],
    "Mimikatz": ["mimikatz.exe", "mimilib.dll", "sekurlsa"],
    "MobaXterm": ["mobaxterm.exe"],
    "Ngrok": ["ngrok.exe"],
    "NTDS Utility": ["ntdsutil.exe"],
    "OpenSSH": ["ssh.exe", "sshd.exe", "scp.exe"],
    "PAExec": ["paexec.exe"],
    "PDQ Deploy": ["pdqdeployconsole.exe", "pdqinventory.exe"],
    "PSExec": ["psexec.exe", "psexesvc.exe"],
    "PsExec": ["psexec.exe", "psexesvc.exe"],
    "Plink": ["plink.exe"],
    "Process Explorer": ["procexp.exe", "procexp64.exe"],
    "Process Hacker": ["processhacker.exe", "kprocesshacker.sys"],
    "ProcDump": ["procdump.exe", "procdump64.exe"],
    "Proxifier": ["proxifier.exe"],
    "PowerTool": ["powertool.exe", "powertool64.exe"],
    "Radmin": ["radmin.exe", "rserver3.exe"],
    "RClone": ["rclone.exe"],
    "Rclone": ["rclone.exe"],
    "RemoteUtilities": ["rutserv.exe", "rfusclient.exe"],
    "RustDesk": ["rustdesk.exe"],
    "ScreenConnect": ["screenconnect.clientservice.exe", "connectwisecontrol.client.exe"],
    "SimpleHelp": ["simplehelp.exe", "remote access.exe"],
    "SoftPerfect NetScan": ["netscan.exe", "netscan_x64.exe"],
    "Splashtop": ["splashtop.exe", "srservice.exe"],
    "Supremo": ["supremo.exe", "supremosystem.exe"],
    "TeamViewer": ["teamviewer.exe", "tv_w32.exe", "tv_x64.exe"],
    "TightVNC": ["tvnserver.exe", "tvnviewer.exe"],
    "WinSCP": ["winscp.exe", "winscp.com"],
    "ZeroTier": ["zerotier-one_x64.exe", "zerotier-cli.exe"],
    "ZohoAssist": ["zohomeeting.exe", "za_access.exe", "zaservice.exe"],
    "Masscan": ["masscan.exe"],
    "Nmap": ["nmap.exe", "ncat.exe"],
    "AdFind": ["adfind.exe"],
    "ADRecon": ["adrecon.ps1"],
    "ADExplorer": ["adexplorer.exe", "adexplorer64.exe"],
    "netscan": ["netscan.exe"],
    "Eraser": ["eraser.exe"],
    "Everything": ["everything.exe"],
    "WinRAR": ["winrar.exe", "rar.exe"],
    "7zip": ["7z.exe", "7za.exe", "7zg.exe"],
    "7-Zip": ["7z.exe", "7za.exe", "7zg.exe"],
    "Putty": ["putty.exe"],
    "PuTTY": ["putty.exe"],
    "Veeam": ["veeam.backup"],
    "Backstab": ["backstab.exe"],
    "Bedevil": ["bdvl"],
    "GrabChrome": ["grabchrome.exe"],
    "GrabFF": ["grabff.exe"],
    "Brute Ratel C4": ["bruteratel", "badger.exe"],
    "Sliver": ["sliver.exe", "sliver-client"],
    "Metasploit": ["msfconsole", "meterpreter"],
    "Evilginx2": ["evilginx.exe", "evilginx"],
    "Ligolo": ["ligolo.exe", "ligolo-ng.exe"],
    "Rubeus": ["rubeus.exe"],
    "SeatBelt": ["seatbelt.exe"],
    "Nltest": ["nltest.exe"],
    "WMIC": ["wmic.exe"],
    "Certutil": ["certutil.exe"],
    "Curl": ["curl.exe"],
    "Wget": ["wget.exe"],
    "Vssadmin": ["vssadmin.exe"],
    "Wbadmin": ["wbadmin.exe"],
    "Wevtutil": ["wevtutil.exe"],
    "Schtasks": ["schtasks.exe"],
    "Net": ["net.exe", "net1.exe"],
}

# Herramientas cuyo nombre es tan generico que buscarlo en una linea de comandos
# produciria falsos positivos constantes. Se detectan SOLO por nombre exacto de
# ejecutable, nunca por subcadena.
EXACT_ONLY: Set[str] = {
    "net", "at", "reg", "sc", "ftp", "cmd", "find", "more", "tree", "rar",
    "esentutl", "expand", "extrac32", "mshta", "print",
}


def fetch(url: str, timeout: int = 60) -> bytes:
    request = urllib.request.Request(url, headers=UA)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return response.read()


def fetch_text(url: str) -> str:
    return fetch(url).decode("utf-8-sig", errors="replace")


def fetch_json(url: str) -> Any:
    return json.loads(fetch(url))


# ---------------------------------------------------------------------------
# Ransomware Tool Matrix
# ---------------------------------------------------------------------------

CATEGORY_LABELS = {
    "Discovery": "Descubrimiento",
    "RMM Tools": "Acceso remoto (RMM)",
    "Defense Evasion": "Evasion de defensas",
    "Credential Theft": "Robo de credenciales",
    "OffSec": "Herramienta ofensiva",
    "Networking": "Tunelizacion y red",
    "LOLBAS": "Binario del sistema (LOLBAS)",
    "Exfiltration": "Exfiltracion",
}

# Tactica MITRE que sugiere cada categoria. No es una equivalencia exacta -- una
# herramienta RMM puede usarse para acceso inicial, persistencia o mando y
# control -- pero da el orden correcto en la vista kill-chain.
CATEGORY_TACTIC = {
    "Discovery": "discovery",
    "RMM Tools": "command-and-control",
    "Defense Evasion": "defense-evasion",
    "Credential Theft": "credential-access",
    "OffSec": "execution",
    "Networking": "command-and-control",
    "LOLBAS": "defense-evasion",
    "Exfiltration": "exfiltration",
}


def clean_tool(name: str) -> str:
    """Normaliza un nombre de la matriz.

    Los nombres traen defanging ('Temp[.]sh'), marcas de afiliado ('*') y
    espacios raros. Se limpian aqui para que la clave sea estable.
    """
    text = (name or "").strip()
    text = text.replace("[.]", ".").replace("[:]", ":")
    text = re.sub(r"\s*\*+\s*$", "", text)          # marca de afiliado
    text = re.sub(r"\s*\+\s*$", "", text)           # marca de estado-nacion
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _derive_patterns(tool: str) -> List[str]:
    """Candidatos de nombre de ejecutable cuando no hay alias curado.

    Heuristica deliberadamente conservadora: solo formas evidentes del nombre.
    Es mejor no detectar una herramienta que inventarse una deteccion.
    """
    base = tool.lower().strip()
    if not base:
        return []
    sin_espacios = re.sub(r"[^a-z0-9._-]", "", base)
    con_guion = re.sub(r"\s+", "-", base)
    con_barra = re.sub(r"\s+", "_", base)

    candidatos = {sin_espacios, con_guion, con_barra}
    salida: List[str] = []
    for c in candidatos:
        if len(c) < 4:      # 'net', 'at', 'sc'... demasiado corto para adivinar
            continue
        salida.append(f"{c}.exe")
    return sorted(set(salida))


def parse_all_tools() -> Dict[str, Dict[str, Any]]:
    """AllTools.csv -> {herramienta: {category, tactic, patterns}}.

    El CSV es una columna por categoria, no una fila por herramienta.
    """
    rows = list(csv.reader(io.StringIO(fetch_text(f"{RTM_RAW}/Tools/AllTools.csv"))))
    if not rows:
        return {}
    headers = [h.strip() for h in rows[0]]

    tools: Dict[str, Dict[str, Any]] = {}
    for row in rows[1:]:
        for index, cell in enumerate(row):
            if index >= len(headers):
                continue
            name = clean_tool(cell)
            if not name:
                continue
            category = headers[index]
            patterns = ALIASES.get(name) or _derive_patterns(name)
            tools[name] = {
                "name": name,
                "category": category,
                "categoryLabel": CATEGORY_LABELS.get(category, category),
                "tactic": CATEGORY_TACTIC.get(category, ""),
                "patterns": patterns,
                "exactOnly": name.lower() in EXACT_ONLY,
                "curated": name in ALIASES,
                "groups": [],
            }
    return tools


def parse_group_profile(markdown: str) -> Dict[str, List[str]]:
    """Perfil de grupo (tabla markdown de 8 columnas) -> {categoria: [tools]}.

    Cada perfil tiene DOS tablas: la de herramientas y, al final, la de informes
    publicos con las columnas 'Date Published' y 'Report'. Solo se lee la
    primera y se corta en cuanto la tabla termina; si no, los encabezados de la
    segunda acaban en el catalogo como si fueran herramientas llamadas
    'Date Published' y 'Report'.
    """
    lines = [line.strip() for line in markdown.splitlines()]
    headers: List[str] = []
    resultado: Dict[str, List[str]] = {}
    dentro = False

    for line in lines:
        if not line.startswith("|"):
            # Una linea que no es de tabla cierra la tabla de herramientas. A
            # partir de ahi no se mira nada mas.
            if dentro:
                break
            continue

        celdas = [c.strip() for c in line.strip("|").split("|")]
        if not headers:
            if any(h in CATEGORY_LABELS for h in celdas):
                headers = celdas
                dentro = True
            continue
        if all(set(c) <= set("-: ") for c in celdas if c):
            continue                                  # separador de la tabla

        for index, celda in enumerate(celdas):
            if index >= len(headers):
                continue
            # Solo se aceptan columnas que sean una categoria conocida.
            categoria = headers[index]
            if categoria not in CATEGORY_LABELS:
                continue
            nombre = clean_tool(celda)
            if not nombre or not _plausible_tool(nombre):
                continue
            resultado.setdefault(categoria, []).append(nombre)
    return resultado


# Cadenas que aparecen en las tablas y no son herramientas.
_NOT_TOOLS = {
    "date published", "report", "source", "sources", "tool", "tools",
    "n/a", "none", "unknown", "-", "tbd",
}


def _plausible_tool(name: str) -> bool:
    """Descarta lo que claramente no es el nombre de una herramienta."""
    bajo = name.lower().strip()
    if bajo in _NOT_TOOLS:
        return False
    if len(bajo) < 2 or len(bajo) > 60:
        return False
    if bajo.startswith(("http://", "https://")):
        return False
    # Una frase larga es una nota del autor, no un nombre de herramienta.
    return len(bajo.split()) <= 6


def parse_sources(markdown: str) -> List[Dict[str, str]]:
    """Tabla de informes publicos del final de cada perfil."""
    fuentes: List[Dict[str, str]] = []
    for match in re.finditer(r"\|\s*([^|]*?\d{4})\s*\|\s*(https?://[^\s|]+)\s*\|", markdown):
        fuentes.append({"date": match.group(1).strip(), "url": match.group(2).strip()})
    return fuentes


def collect_groups(tools: Dict[str, Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    perfiles = fetch_json(f"{RTM_API}/GroupProfiles")
    grupos: Dict[str, Dict[str, Any]] = {}

    for item in perfiles:
        if item["type"] != "file" or not item["name"].endswith(".md"):
            continue
        nombre = item["name"][:-3].replace("_", " ")
        markdown = fetch_text(item["download_url"])
        por_categoria = parse_group_profile(markdown)

        planas: List[str] = []
        for categoria, lista in por_categoria.items():
            for herramienta in lista:
                planas.append(herramienta)
                # La herramienta puede aparecer en el perfil de un grupo sin
                # estar en AllTools.csv; se da de alta al vuelo.
                if herramienta not in tools:
                    tools[herramienta] = {
                        "name": herramienta,
                        "category": categoria,
                        "categoryLabel": CATEGORY_LABELS.get(categoria, categoria),
                        "tactic": CATEGORY_TACTIC.get(categoria, ""),
                        "patterns": ALIASES.get(herramienta) or _derive_patterns(herramienta),
                        "exactOnly": herramienta.lower() in EXACT_ONLY,
                        "curated": herramienta in ALIASES,
                        "groups": [],
                    }
                if nombre not in tools[herramienta]["groups"]:
                    tools[herramienta]["groups"].append(nombre)

        grupos[nombre] = {
            "name": nombre,
            "toolsByCategory": por_categoria,
            "tools": sorted(set(planas)),
            "sources": parse_sources(markdown),
            "notes": [],
            "aliases": [],
            "description": "",
        }
        print(f"  grupo {nombre:<22} {len(planas):>3} herramientas")
    return grupos


# ---------------------------------------------------------------------------
# ransomware.live
# ---------------------------------------------------------------------------

def collect_ransom_notes() -> Dict[str, Dict[str, Any]]:
    """Indice de notas de rescate: nombre de fichero -> grupos que lo usan.

    Se extrae de los enlaces /ransomnote/<grupo>/<fichero> de la pagina publica.
    Un fichero llamado 'RECOVER-FILES.txt' apareciendo en un servidor de ficheros
    es de las senales mas tardias y mas inequivocas que existen.
    """
    html = fetch_text(LIVE_NOTES)
    enlaces = re.findall(r'href="(/ransomnote/[^"]+)"', html)

    notas: Dict[str, Dict[str, Any]] = {}
    for enlace in enlaces:
        partes = [urllib.parse.unquote(p) for p in enlace.strip("/").split("/")]
        if len(partes) < 3:
            continue
        grupo, fichero = partes[1], partes[-1]
        clave = fichero.lower()
        entrada = notas.setdefault(clave, {"filename": fichero, "groups": [], "url": enlace})
        if grupo not in entrada["groups"]:
            entrada["groups"].append(grupo)
    return notas


def collect_group_metadata() -> Dict[str, Dict[str, Any]]:
    """Descripcion y alias de cada grupo, para enriquecer los perfiles."""
    try:
        datos = fetch_json(LIVE_GROUPS)
    except (urllib.error.URLError, ValueError) as exc:
        print(f"  aviso: no se pudieron leer los metadatos de grupos ({exc})")
        return {}

    salida: Dict[str, Dict[str, Any]] = {}
    for grupo in datos:
        nombre = (grupo.get("name") or "").strip()
        if not nombre:
            continue
        salida[nombre.lower()] = {
            "name": nombre,
            "altname": grupo.get("altname") or "",
            "description": (grupo.get("description") or "").strip()[:600],
        }
    return salida


# ---------------------------------------------------------------------------

def main() -> int:
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    try:
        print("Ransomware Tool Matrix: catalogo de herramientas...")
        tools = parse_all_tools()
        print(f"  {len(tools)} herramientas en {len(CATEGORY_LABELS)} categorias")

        print("Ransomware Tool Matrix: perfiles de grupo...")
        groups = collect_groups(tools)

        print("ransomware.live: notas de rescate...")
        notes = collect_ransom_notes()
        print(f"  {len(notes)} nombres de nota distintos")

        print("ransomware.live: metadatos de grupos...")
        meta_grupos = collect_group_metadata()
    except urllib.error.URLError as exc:
        print(f"ERROR de red: {exc}", file=sys.stderr)
        return 1

    # Los nombres de grupo llegan de dos sitios con formas distintas: la matriz
    # de herramientas los escribe 'Akira' y la URL de ransomware.live 'akira'.
    # Se unifican a la forma canonica de la matriz para que el informe no ensene
    # el mismo grupo escrito de dos maneras y para que el cruce sea directo.
    por_grupo_lower = {nombre.lower().replace(" ", ""): nombre for nombre in groups}

    for nota in notes.values():
        canonicos: List[str] = []
        for grupo_nota in nota["groups"]:
            destino = por_grupo_lower.get(grupo_nota.lower().replace(" ", ""))
            canonicos.append(destino or grupo_nota)
            if destino and nota["filename"] not in groups[destino]["notes"]:
                groups[destino]["notes"].append(nota["filename"])
        # Se ordena y se deduplica: la misma nota puede listar el grupo dos veces
        # si el sitio tiene una entrada por alias.
        nota["groups"] = sorted(set(canonicos))

    for nombre, grupo in groups.items():
        extra = meta_grupos.get(nombre.lower())
        if extra:
            grupo["description"] = extra["description"]
            if extra["altname"]:
                grupo["aliases"] = [extra["altname"]]

    for herramienta in tools.values():
        herramienta["groups"].sort()

    meta = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "counts": {
            "tools": len(tools),
            "groups": len(groups),
            "ransomNotes": len(notes),
            "groupsWithNotes": sum(1 for g in groups.values() if g["notes"]),
        },
        "sources": [
            {
                "name": "Ransomware Tool Matrix",
                "author": "BushidoUK",
                "url": "https://github.com/BushidoUK/Ransomware-Tool-Matrix",
                "license": "CC BY 4.0",
                "provides": "que herramientas usa cada grupo de ransomware, por categoria",
            },
            {
                "name": "ransomware.live",
                "author": "Julien Mousqueton",
                "url": "https://www.ransomware.live/",
                "license": "ver el sitio",
                "provides": "indice de notas de rescate por grupo y metadatos de grupos",
            },
        ],
        "caveat": (
            "La atribucion por solape de herramientas es una HIPOTESIS, no un "
            "veredicto. Los grupos de ransomware comparten afiliados y casi todos "
            "usan las mismas utilidades. Sirve para orientar la busqueda, no para "
            "cerrar un caso."
        ),
    }

    for nombre, contenido in (
        ("tools.json", tools),
        ("groups.json", groups),
        ("ransomnotes.json", notes),
        ("meta.json", meta),
    ):
        destino = DATA_DIR / nombre
        destino.write_text(
            json.dumps(contenido, indent=1, ensure_ascii=False, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        print(f"  escrito {destino.name:<18} {destino.stat().st_size // 1024:>4} KB")

    print(f"\n{len(tools)} herramientas · {len(groups)} grupos · {len(notes)} notas de rescate")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
