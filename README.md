# GLAMDRING

<div align="center">

![Gandalf empuñando Glamdring, en arte ASCII](docs/glamdring.png)

</div>

**Lee Splunk, Sentinel/Defender, QRadar y CEF/LEEF/syslog, y los convierte en un grafo
3D navegable del incidente.** Entidades como nodos, acciones como aristas dirigidas y el
tiempo como eje. El SIEM sigue siendo la fuente de verdad: cada nodo y cada arista abren
el log literal que los generó. Corre en local, un proceso, sin autenticación.

---

## Arranque rápido

Probado con **Python 3.12**.

```powershell
cd GLAMDRING
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
powershell -ExecutionPolicy Bypass -File tools\run.ps1
```

- Abre <http://localhost:8000> y pulsa **Demo** (52 eventos, 38 entidades) o
  **Demo mínima** (6 eventos, 10 nodos, 16 aristas) para ver la forma del grafo sin
  nada encima.
- Sin SIEM y sin credenciales: `samples/` trae el incidente repartido entre los cuatro
  formatos de ingesta soportados.
- Frontend sin build: no hay `npm install`.
- `tools\run.ps1` (51 líneas) cierra lo que hubiera y arranca **siempre en :8000**.
  Acepta `-Port 8080` y `-Reload` (la recarga levanta un proceso más, el vigilante, por
  eso se pide a propósito y no viene puesta).
- Servidores vivos de sesiones anteriores:
  `powershell -ExecutionPolicy Bypass -File tools\stop_servers.ps1`. Busca por línea de
  comandos y no solo por puerto, para cazar también al vigilante de `--reload`. Acepta
  `-Keep 8000` y `-WhatIf`.
- Linux/macOS: `source .venv/bin/activate` y `uvicorn glamdring.main:app --port 8000`.
  `run.ps1` es solo para PowerShell.

---

## Qué hace

### Normaliza cuatro formatos a un modelo común

| Fuente | Qué entiende | Conector en vivo |
|---|---|---|
| **Splunk** | `WinEventLog:Security` (4624, 4625, 4648, 4688, 4720), Sysmon (1, 3, 11, 22), sourcetypes de firewall/proxy/DNS y campos CIM | sí, token de servicio |
| **Sentinel / Defender** | `DeviceProcessEvents`, `DeviceNetworkEvents`, `DeviceFileEvents`, `DeviceLogonEvents`, `SigninLogs`, `EmailEvents`, `SecurityAlert`, `SecurityIncident` | sí, Service Principal con *Log Analytics Reader* |
| **QRadar** | Resultados Ariel (`starttime`, `sourceip`, `magnitude`, `categoryname`…) y ofensas | sí, token en la cabecera `SEC` |
| **CEF / LEEF / syslog** | CEF 0.x, LEEF 1.0 y 2.0, syslog RFC5424 y RFC3164, y JSON arbitrario como red de seguridad | — (entra por fichero, con `files`) |

- El destino común es un subconjunto pragmático de [OCSF](https://schema.ocsf.io/), el
  esquema vendor-neutral impulsado por AWS y Splunk (`glamdring/normalize/`).

---

## De un vistazo

Seis esquemas que explican el sistema entero sin leer una línea de código.

### Dónde encaja en la red

No instala agentes, no responde a incidentes y no sustituye al SIEM: lee lo que el SIEM
ya recogió y lo pinta.

![Arquitectura de red](docs/diagrams/01-arquitectura-red.svg)

### Qué le pasa a un log desde que entra

Seis etapas, cada una con su contrato. Abajo, el mismo registro de Splunk atravesándolas
todas: crudo, normalizado, grafo, con criterio.

![Arquitectura de datos](docs/diagrams/02-arquitectura-datos.svg)

### Cómo se dibuja el grafo

Sin npm y sin compilación: módulos ES con `importmap` y three.js r168, con la revisión
fijada a la que trae `3d-force-graph`. Al pie, las tres trampas que no lanzan ningún
error y costaron caro.

![Arquitectura visual](docs/diagrams/03-arquitectura-visual.svg)

### Lo que aporta el perímetro

Un log de cortafuegos no dice qué proceso abrió la conexión, pero dice cuándo, cuánto y
hacia dónde. Cruzado con el endpoint, cierra el caso.

![Perímetro y cortafuegos](docs/diagrams/04-perimetro-firewall.svg)

### Por qué hacen falta los cuatro SIEM

Cada uno ve bien una parte y mal las demás, y cada uno llama de una manera distinta a la
misma persona. La canonización es lo que los une.

![Los cuatro SIEM y la unificación](docs/diagrams/05-siems-unificacion.svg)

### Cómo se detecta un despliegue de ransomware

Ocho etapas. Cuando se ve la octava ya es tarde, así que lo que se busca es el rastro de
las siete anteriores.

![Cadena de ransomware](docs/diagrams/06-cadena-ransomware.svg)

---

## Capacidades de cada SIEM, y qué pasa cuando hay dos

Ninguno lo ve todo. La pregunta útil no es cuál es mejor, sino **qué se pierde cuando
hay dos y nadie los cruza**.

![Capacidades comparadas de los cuatro SIEM](docs/diagrams/07-capacidades-siem.svg)

| | Endpoint | Identidad | Correo | Red y flujos | Perímetro | Cloud |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| **Splunk** | ●●● | ●○○ | ●○○ | ●●○ | ●●○ | ●○○ |
| **Sentinel / Defender** | ●●○ | ●●● | ●●● | ●○○ | ●○○ | ●●● |
| **IBM QRadar** | ●○○ | ●●○ | ●○○ | ●●● | ●●● | ●○○ |
| **CEF / LEEF / syslog** | ●○○ | ●○○ | ●○○ | ●●○ | ●●● | ●○○ |

`●●●` fuente principal · `●●○` aporta, con lagunas · `●○○` testimonial o ausente

| SIEM | Su punto fuerte | Su punto ciego |
|---|---|---|
| **Splunk** | Línea de comandos completa, árbol de procesos, Sysmon y 4688 | Identidad cloud |
| **Sentinel / Defender** | Inicios de sesión, phishing entregado, alertas del EDR ya correladas | Todo lo que no es Microsoft |
| **IBM QRadar** | Quién habló con quién y cuántos bytes; ofensas ya agrupadas | Identifica por IP, no por nombre |
| **CEF / LEEF / syslog** | El comodín: cortafuegos, proxy, antivirus, VPN, cabinas | Cada fabricante lo estira a su gusto |

Dos SIEM no son el doble de visibilidad, son **dos mitades que nadie junta**. Pasa en
dos escenarios muy corrientes:

- **Una empresa con dos SIEM.** Uno heredado y otro nuevo, o uno de TI y otro de OT. El
  ataque cruza los dos y cada analista mira solo el suyo.
- **Dos empresas que se fusionan.** Datos parecidos, herramientas distintas y una
  migración que dura años. Mientras tanto hay que investigar incidentes que atraviesan
  las dos redes.

| Solo el SIEM A (Splunk) | Solo el SIEM B (QRadar) | Cosidos por equipo y hora |
|---|---|---|
| «jlopez ejecutó `powershell.exe` con la línea ofuscada en WKS-0421» | «10.4.2.11 sacó 4,2 GB hacia 45.132.88.17 en 40 minutos» | «jlopez ejecutó `powershell.exe` en WKS-0421 y doce minutos después ese mismo equipo sacó 4,2 GB» |
| No sabes si llegó a salir de la red | No sabes qué proceso fue ni quién | El caso, entero |

Lo que lo hace posible:

- **Un solo modelo.** Los cuatro caen a OCSF-lite, así que un proceso de Splunk y un
  flujo de QRadar se comparan.
- **La identidad se unifica.** `CORP\jlopez`, `jlopez@corp.com` y `jlopez` son un nodo,
  no tres. Y `10.4.1.5` se funde en `srv-dc01`.
- **Cada arista recuerda su origen**, así que siempre se vuelve al log del SIEM que lo tiene.

---

## Los 17 grupos de ransomware reconocidos

![Los 17 grupos de ransomware, sus herramientas por categoría y su nota característica](docs/diagrams/08-grupos-ransomware.svg)

Ordenados por tamaño del repertorio. Las ocho categorías van en orden de intrusión:
**RMM** control remoto · **Desc** reconocimiento · **Cred** robo de credenciales ·
**OffS** utillaje ofensivo · **Red** túneles · **Exfi** exfiltración ·
**Evas** evasión de defensas · **LOL** binarios del sistema.

| Grupo | Total | RMM | Desc | Cred | OffS | Red | Exfi | Evas | LOL | Nota que lo distingue |
|---|--:|--:|--:|--:|--:|--:|--:|--:|--:|---|
| **ScatteredSpider** | 78 | 26 | 11 | 10 | 6 | 17 | 6 | 1 | 1 | — |
| **TheGentlemen** | 41 | 3 | 12 | 3 | 8 | 8 | 1 | 5 | 1 | `README-GENTLEMEN.txt` |
| **Warlock** | 26 | 2 | 2 | 2 | 3 | 8 | 1 | 3 | 5 | `How to decrypt my data.txt` |
| **BlackSuit** | 24 | 4 | 4 | 7 | 2 | 3 | 1 | 2 | 1 | `README.BlackSuit.txt` |
| **Akira** | 23 | 4 | 5 | 3 | 1 | 3 | 5 | 2 | — | `akira_readme.txt` |
| **BlackBasta** | 21 | 6 | 5 | 1 | 4 | — | 2 | 1 | 2 | `blackbasta1.txt` |
| **Qilin** | 18 | 1 | 2 | 1 | 3 | 1 | 1 | 6 | 3 | `DtMXQFOCos-RECOVER-README.txt` |
| **BianLian** | 16 | 6 | 5 | 1 | 1 | — | 2 | — | 1 | `Look at this instruction.txt` |
| **DragonForce** | 15 | — | 4 | 2 | 1 | — | 2 | 5 | 1 | `[rand].README.txt` |
| **Beast** | 13 | 1 | 4 | 3 | — | 2 | 2 | — | 1 | — |
| **EvilCorp** | 12 | 1 | 2 | 3 | 2 | — | 3 | — | 1 | — |
| **Interlock** | 11 | 2 | 2 | — | 1 | 1 | 2 | 2 | 1 | `!!!OPEN_ME!!!.txt` |
| **ProphetSpider** | 11 | — | 1 | 1 | 5 | — | 1 | — | 3 | — |
| **PLAY** | 10 | — | 1 | 1 | 2 | 1 | 1 | 3 | 1 | `readme2.txt` |
| **INC Ransom** | 9 | — | 2 | — | — | — | 5 | — | 2 | — |
| **Yurei** | 9 | 1 | 2 | — | 4 | — | — | — | 2 | — |
| **SafePay** | 8 | 1 | 1 | — | — | — | 3 | — | 3 | `readme_safepay.txt` |

- **El perfil pesa más que el total.** ScatteredSpider tiene 26 herramientas de control
  remoto y 17 de red: entra y se queda. INC Ransom tiene 5 de 9 en exfiltración: viene a
  llevarse datos.
- **La nota que distingue** es la única que no comparte con ningún otro grupo del
  catálogo. Los que ponen «—» solo usan nombres genéricos como `README.txt`, que no
  identifican nada: el motor los pondera con 0,1 frente al 10 de una nota propia
  (`glamdring/threat/attribution.py:88` y `:93`).
- **Los emblemas del esquema son monogramas, no logotipos.** Estos grupos no tienen una
  marca redistribuible, y ponerles una inventada sería afirmar algo falso.

> **Esto no sirve para señalar a nadie.** Comparten afiliados y casi todos usan las
> mismas utilidades, que además usan los administradores legítimos. El solape orienta la
> búsqueda —dice qué mirar a continuación—, no dice quién fue.

El cuadro se genera desde el catálogo, no se escribe a mano:

```powershell
python tools/fetch_threat_intel.py   # actualiza el catálogo desde las fuentes
python tools/make_group_table.py     # regenera docs/diagrams/08-grupos-ransomware.svg
```

---
