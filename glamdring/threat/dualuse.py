"""Herramientas de DOBLE USO: las que también usa gente que no ataca a nadie.

EL PROBLEMA QUE RESUELVE. La atribución medía lo distintiva que es una
herramienta **solo dentro del catálogo de ransomware**: si la usan menos de diez
de los diecisiete grupos, cuenta como pista que señala a alguien.

Medido sobre el catálogo real: de 305 herramientas, **solo dos** superaban ese
umbral (PsExec y Mimikatz). Todas las demás contaban como discriminantes,
incluidas:

    AnyDesk                  8/17 grupos
    Advanced IP Scanner      8/17 grupos
    RClone                   8/17 grupos
    OpenSSH                  6/17 grupos
    WinSCP                   5/17 grupos

Y esas están instaladas en medio departamento de sistemas del mundo. El
resultado era que un incidente en el que alguien usó AnyDesk y RClone producía
candidatos con solape "discriminante", cuando lo único que demuestra es que la
empresa tiene soporte remoto y hace copias de seguridad.

SON DOS EJES DISTINTOS, y ahí estaba el error de fondo:

* **Cuántos grupos de ransomware la usan** — lo que ya se medía. Dice si
  distingue a un grupo *de otro grupo*.
* **Si la usa también gente legítima** — lo que faltaba. Dice si distingue un
  ataque *de un martes cualquiera*.

Una herramienta puede ser rara entre los grupos y aun así estar en todos los
portátiles de la empresa. El catálogo, por construcción, no puede saberlo: solo
mira ransomware.

QUÉ ENTRA EN ESTA LISTA. Software que un departamento de sistemas instala a
propósito, o que viene con el sistema operativo. NO entra lo que nadie tiene
motivo legítimo para tener: Cobalt Strike, Mimikatz, LaZagne, Bloodhound.

Que una herramienta esté aquí **no la hace inocente**. Sigue contando como
evidencia de intrusión y sigue apareciendo en la detección: lo único que deja de
hacer es señalar a un grupo concreto.
"""

from __future__ import annotations

from typing import Dict, Set

# Categorías cuyo contenido es dual por definición.
#
# Los binarios del sistema vienen con Windows: certutil, bitsadmin, wevtutil y
# compañía están en todas las máquinas del planeta, las use quien las use.
CATEGORIAS_DUALES = {"LOLBAS"}

# Soporte remoto comercial. Un departamento de sistemas despliega uno de estos a
# propósito y en toda la flota; encontrarlo no dice nada sobre quién entró.
# Encontrar DOS distintos sí es raro, pero eso es cosa de la detección, no de la
# atribución.
_REMOTO = {
    "AnyDesk", "TeamViewer", "ScreenConnect", "Atera", "Splashtop", "LogMeIn",
    "ZohoAssist", "Action1", "NetSupport", "Syncro", "Pulseway", "N-Able",
    "ManageEngineRMM", "SimpleHelp", "RemotePC", "Supremo", "TightVNC",
    "Radmin", "DWAgent", "ITarian", "Level.io", "Fleetdeck", "Domotz",
    "SuperOps", "TacticalRMM", "Xeox", "RPort", "MeshAgent", "RustDesk",
    "Chrome Remote Desktop", "Microsoft RDP", "FreeRDP", "RSAT", "MobaXterm",
    "PDQ Deploy", "Parsec", "ASG Remote Desktop", "RemoteUtilities",
    "Remote Manipulator System (RMS)", "Twingate", "ZeroTier",
}

# Transferencia de ficheros y copias de seguridad. RClone y WinSCP mueven datos
# todos los días en sitios donde no ha entrado nadie.
_FICHEROS = {
    "RClone", "Rclone", "WinSCP", "FileZilla", "7zip", "WinRAR", "PSCP",
    "FreeFileSync", "Restic", "Cyberduck", "AZCopy", "s5cmd", "MEGA",
    "Dropbox", "pCloud", "BackBlaze", "Azure Blob Storage",
    "Azure Storage Explorer", "S3 Browser", "MinIO", "ProtonMail",
}

# Redes y túneles que se usan para trabajar.
_RED = {
    "OpenSSH", "OpenVPN", "PuTTY", "Plink", "Wireguard VPN", "Tailscale",
    "Cloudflared", "TryCloudflare", "Ngrok", "Socat", "Teleport",
    "VS Code Tunnel", "Proxifier",
}

# Inventario y descubrimiento. Un escáner de red es la herramienta diaria de
# quien administra la red, y Nmap está en el portátil de todo el que la toca.
_INVENTARIO = {
    "Advanced IP Scanner", "Advanced Port Scanner", "Angry IP Scanner", "Nmap",
    "Nping", "Masscan", "Nbtscan", "SoftPerfect NetScan",
    "SoftPerfect LanSearchPro", "Lansweeper", "PDQ Inventory", "RVTools",
    "VMware PowerCLI", "Everything.exe", "ADExplorer", "AdFind", "Dsquery",
    "Get-ADUser", "PsInfo", "ServiceControl (sc.exe)", "PingCastle",
    "AWS Systems Manager Inventory", "Censys", "Shodan", "WKTools",
}

DOBLE_USO: Set[str] = _REMOTO | _FICHEROS | _RED | _INVENTARIO


def es_de_doble_uso(nombre: str, herramienta: Dict) -> bool:
    """True si esta herramienta también la usa gente legítima.

    Se mira la categoría primero porque es lo que sobrevive a una actualización
    del catálogo: si mañana aparece un LOLBAS nuevo, entra solo sin tocar nada.
    """
    if not nombre:
        return False
    if (herramienta or {}).get("category") in CATEGORIAS_DUALES:
        return True
    return nombre in DOBLE_USO
