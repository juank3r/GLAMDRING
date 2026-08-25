# Hallazgos de clasificacion

Auditoria de los cuatro normalizadores y de la capa de grafo. Cada hallazgo se
reprodujo EJECUTANDO codigo sobre las muestras reales, y despues paso por un
verificador independiente cuyo encargo era tumbarlo. De 45, seis se cayeron
ahi y no estan en esta lista.

**45 confirmados**: 23 de gravedad alta, 17 media, 5 baja.


## Gravedad alta

### El logoff 4634 sale como 'logon_remote' con T1021 y dibuja aristas 'lateral': una jornada normal pinta todo el grafo de victima

`glamdring/normalize/splunk_windows.py:139`

**Sale hoy:** 4634 (y 4647) no estan en _HANDLERS, caen a _logon(record, True) y ademas entran en la rama de Logon_Type (linea 133-143). Como 4634 SI trae Logon_Type, un logoff de sesion de red sale con activity='logon_remote', status='success', severity=2 y mitre=['T1021.002'] (tactica 'lateral-movement'); con Logon_Type=10 sale T1021.001. extract._authentication (extract.py:237-240) traduce logon_remote a una arista de tipo 'lateral', y 'lateral-movement' esta en VICTIM_TACTICS (enrich.py:39), asi que enrich pinta los nodos como ROLE_VICTIM.

**Deberia:** 4634/4647 son cierres de sesion: deberian ser activity='logoff' en CLASS_AUTHENTICATION, o no emitirse. En ningun caso deben inventar una tecnica de movimiento lateral. La rama de Logon_Type solo tiene sentido para los EventCode que declaran un logon (4624/4625), no para cualquier registro que traiga el campo.

**Lo que se le escapa al analista:** 4634 es tipicamente el evento mas numeroso de un log de seguridad de Windows (uno por cada 4624). Veinte desconexiones rutinarias de un recurso compartido dejan 21 nodos ROLE_VICTIM con tactica 'lateral-movement' y riesgo 47 en el servidor. El analista abre el grafo y todo esta rojo por movimiento lateral que nunca ocurrio; cuando haya un salto lateral de verdad no lo distinguira del fondo, y el informe exportado afirmara T1021.002 sobre veinte usuarios inocentes.

### La regla del sourcetype 'sysmon' es una comparacion de subcadena sobre un valor que fija el cliente: sin esa palabra, Sysmon 11 pega el SHA256 del fichero soltado a certutil.exe y Sysmon 22 pierde el dominio C2

`glamdring/normalize/splunk_windows.py:315`

**Sale hoy:** Si sourcetype (o source) no contiene literalmente 'sysmon', la linea 315 borra el code y el registro cae a las redes finales. Sysmon 11 acaba en _process_create por la red de la linea 331 ('Image'), y como _process_create construye el FileRef a partir de Image con los hashes del campo Hashes (lineas 179-182), el SHA256 del fichero CREADO queda atribuido a C:\\Windows\\System32\\certutil.exe; la ruta real (TargetFilename) desaparece. Sysmon 22 sale como class='Process Activity', activity='launch', domain=None. Basta con sourcetype='XmlWinEventLog', 'wineventlog', un nombre propio del cliente, o que la busqueda no devuelva sourcetype.

**Deberia:** El despacho de los codigos bajos no puede depender de una palabra en un campo configurable. Deberia decidirse por la forma del registro (TargetFilename+Image sin CommandLine = Sysmon 11; QueryName = Sysmon 22) o por una lista de sourcetypes configurable; y si no hay certeza, no clasificar, nunca caer a un handler que reinterpreta los campos. En ningun caso _process_create debe atribuir a Image un hash que no es suyo.

**Lo que se le escapa al analista:** El mismo evento cambia de significado segun como se llame el sourcetype en ese cliente. Con un nombre 'malo', el hash del ejecutable soltado aparece colgando de certutil.exe: si el analista pivota ese hash y VirusTotal lo da como malicioso, el grafo le esta afirmando que el binario malicioso es un ejecutable firmado de Microsoft, y el fichero real (Temp\upd.exe) no existe en ningun sitio del incidente. Con Sysmon 22, el dominio de C2 -el IOC mas pivotable de todo el log- desaparece sin dejar rastro ni aviso.

### Sysmon 8 y 10 (inyeccion y volcado de LSASS) se reclaman y se devuelven a None: cero nodos y cero aristas, mimikatz y lsass no existen en el grafo

`glamdring/normalize/splunk_windows.py:331`

**Sale hoy:** matches() devuelve True y normalize() devuelve None. Los codigos 8 y 10 no estan en _HANDLERS, y ninguna de las redes finales los alcanza: usan SourceImage/TargetImage, que no estan en first(record,'process','process_name','Image') (linea 331), y su campo de usuario es 'User' con U mayuscula, que no esta en first(record,'user','Account_Name') (linea 333). El registro sale del normalizador de Splunk y lo acaba recogiendo el generico: source='generic', class='Process Activity', activity='launch', severity=2, y el grafo resultante tiene 0 nodos y 0 aristas.

**Deberia:** Sysmon 10 con GrantedAccess 0x1410 sobre lsass.exe es acceso a credenciales (T1003.001) y Sysmon 8 es inyeccion de proceso (T1055): deberian producir dos procesos (origen y destino) y una arista entre ellos, con severidad alta. Como minimo, SourceImage/TargetImage y 'User' deberian estar en las listas de candidatos de first() para no perder la atribucion a Splunk.

**Lo que se le escapa al analista:** El volcado de credenciales de LSASS es el pivote central de casi todo incidente de ransomware: es lo que explica como el atacante paso de una estacion a Domain Admin. Aqui el evento entra por la ingesta, se cuenta como evento normalizado y no produce ni un solo nodo. El analista que mire el grafo vera el proceso inicial y el salto lateral posterior sin nada que los una, y concluira que son dos incidentes distintos. Ademas la severidad 2 y el source='generic' hacen que ni siquiera se pueda filtrar por 'lo que vino de Sysmon'.

### 4648 esta cubierto pero se aplana a un logon local: se descartan la cuenta usada (Target_Account_Name) y el servidor destino (Target_Server_Name)

`glamdring/normalize/splunk_windows.py:299`

**Sale hoy:** _HANDLERS['4648'] llama a _logon(r, True). En _logon el actor se toma de first(record,'Account_Name','TargetUserName','user','Target_Account_Name') (linea 117): 'Account_Name' gana siempre, asi que el actor es el sujeto que lanza el runas, no la cuenta privilegiada que se usa. Target_Server_Name no se lee en ninguna parte del fichero, asi que dst=None. Resultado: activity='logon', status='success', severity=2, mitre=[], y la unica arista es user:jlopez -authenticated-> host:wks-0421, o sea 'jlopez entro en su propio equipo'.

**Deberia:** 4648 es 'logon con credenciales explicitas': el actor relevante es Target_Account_Name (administrador), el destino es Target_Server_Name (DC01) y merece T1078/T1550 con severidad alta. Ademas el evento se registra tanto si la autenticacion posterior tuvo exito como si no, asi que status='success' es una afirmacion que el registro no respalda; deberia ser 'unknown'.

**Lo que se le escapa al analista:** 4648 es el precursor clasico del movimiento lateral: runas, pass-the-hash, PsExec con credenciales alternativas. El grafo dice literalmente lo contrario de lo que pone el log: que jlopez se autentico en su propio equipo, severidad 2, sin tecnica MITRE. La cuenta 'administrador' y el nodo DC01 no aparecen, asi que el salto hacia el controlador de dominio -la arista que el analista esta buscando- no existe. Es peor que no cubrir el codigo, porque el evento figura como procesado correctamente.

### Sysmon 13 (persistencia en clave Run), 23 (borrado de fichero), 2 (timestomp) y 15 (ADS) salen como activity='launch' con status='success' y sin el objeto tocado

`glamdring/normalize/splunk_windows.py:331`

**Sale hoy:** Ninguno esta en _HANDLERS. Todos traen 'Image', asi que la red de la linea 331 los manda a _process_create: class='Process Activity', activity='launch', status='success', severity=2. TargetObject (la clave de registro) y TargetFilename (el fichero borrado o el ADS) no se leen en _process_create, asi que file=None y el objeto sobre el que actua el atacante no llega al grafo. Encima el nodo de proceso se funde con el del Sysmon 1 legitimo del mismo binario, inflandole el contador de eventos.

**Deberia:** 13 y 12 son cambios de registro (CLASS_FILE o un tipo 'registry', que la ontologia ya contempla en enrich.CONTEXT_TYPES) con T1547.001; 23 es borrado de fichero (T1070.004) y deberia ser activity='delete', no 'create' ni 'launch'; 2 es timestomp (T1070.006). Un evento cuyo objeto principal no se sabe leer no debe emitirse como 'lanzamiento de proceso correcto'.

**Lo que se le escapa al analista:** La persistencia y la destruccion de evidencia son dos de las tres preguntas que el analista tiene que contestar en su turno ('como vuelve el atacante' y 'que se ha llevado o borrado'). Aqui las dos se convierten en el evento mas banal que existe, un proceso que arranca bien. La clave Run que hay que limpiar en la remediacion no esta en el grafo, y el borrado masivo de documentos que precede al cifrado se ve como una rafaga de lanzamientos del mismo proceso, indistinguible de un binario que se ejecuta varias veces.

### 'stream:' y 'cisco' se comprueban antes que 'dns': la telemetria DNS de Splunk Stream y de Cisco Umbrella se clasifica como red y pierde el dominio consultado

`glamdring/normalize/splunk_windows.py:323`

**Sale hoy:** La lista de la linea 323 ('firewall','proxy','netflow','stream:','pan:','cisco') se evalua ANTES que la comprobacion de 'dns' de la linea 325. Los sourcetypes reales 'stream:dns' y 'cisco:umbrella:dns' contienen 'stream:' y 'cisco', asi que van a _network_connect. _network_connect no lee el campo 'query', solo DestinationHostname/dest_host, de modo que domain=None: el dominio consultado desaparece. El mismo registro con sourcetype 'infoblox:dns' si sale como DNS Activity con su nodo de dominio.

**Deberia:** Comprobar 'dns' antes que la lista generica de red, o cortar el sourcetype por el ultimo segmento en lugar de buscar subcadenas. Y _dns_query/_network_connect deberian aceptar 'query' como candidato de dominio, que es el nombre CIM estandar.

**Lo que se le escapa al analista:** Splunk Stream y Cisco Umbrella son dos de las fuentes DNS mas habituales en un SOC. Con ellas, la consulta al dominio de C2 se dibuja como 'el equipo hablo con su servidor DNS interno 10.4.0.53': ni nodo de dominio, ni IP resuelta, ni indicador que pivotar. El analista pierde el unico artefacto que le permite buscar el mismo C2 en el resto del parque, y no hay ninguna senal de que se haya descartado un dato: el evento figura normalizado y con clase asignada.

### La escala de severidad esta invertida: el salto lateral, el binario soltado y el DNS de C2 pesan menos que el trafico de Windows Update; con minSeverity=3 solo sobrevive el ruido

`glamdring/normalize/splunk_windows.py:232`

**Sale hoy:** Todas las severidades son literales de la funcion que las construye (2 en _logon/_process_create/_network_connect/_file_create, 1 en _dns_query, 4 en _account_created) y el unico ajuste al alza en red es 'destino no RFC1918 -> 3' (linea 232). Resultado medido: 4624 tipo 10 correcto desde una IP publica con T1021.001 = severidad 2; Sysmon 11 soltando el ejecutable en Temp = 2; Sysmon 22 consultando el dominio de C2 = 1; mientras svchost.exe hablando con Windows Update y chrome.exe con un CDN = 3. El rango completo que puede emitir el fichero es 1..4: nunca emite 5.

**Deberia:** La severidad deberia subir con la evidencia, no con el hecho de que el destino sea publico. Un logon remoto correcto con T1021, un fichero soltado en Temp por un proceso no firmado, o una consulta a un dominio de C2 tienen que quedar por encima de una conexion saliente rutinaria. Y como el evento trae MITRE, la severidad podria derivarse de la tactica, como ya hace _process_create con infer_from_cmdline (lineas 187-188).

**Lo que se le escapa al analista:** El primer gesto de un analista con prisa es subir el umbral de severidad para quitarse ruido de encima. Con minSeverity=3 desaparecen los tres eventos que forman el incidente y se quedan exactamente los dos que no importan. El filtro no es que sea poco util: es que hace lo contrario de lo que el analista cree que hace, y no hay nada en la interfaz que le avise de que acaba de esconder el ataque.

### _file_activity crea el nodo del equipo pero nunca lo enlaza: una deteccion de malware no dice en que maquina esta el malware

`glamdring/graph/extract.py:294`

**Sale hoy:** Ingiriendo el evento de Defender de samples/perimeter.cef (dvchost=SRV-DC01, filePath=C:\Windows\Temp\m.exe, act=quarantine_failed) el grafo queda: file:c:\windows\temp\m.exe grado=2, hash:b2c3... grado=1, user:jlopez grado=1 y host:srv-dc01 GRADO=0. Las unicas aristas son ('user:jlopez','wrote','file:...m.exe') y ('file:...m.exe','has_hash','hash:b2c3...'). _add_device(...) en la linea 288 crea host:srv-dc01, pero la linea 294 solo enlaza process_key OR user_key OR device_key con el fichero: como user_key existe, device_key nunca se usa, y la linea 297 solo enlaza el device si hay proceso.

**Deberia:** El equipo donde el AV encuentra el fichero es el dato central del evento. Deberia existir siempre una arista host<->fichero (o process->device y ademas device->file cuando no hay proceso), de modo que el nodo del fichero cuelgue de la maquina afectada. Ademas la relacion 'wrote' es una inferencia: el evento dice que Defender DETECTO m.exe, no que jlopez lo escribiera; el propio docstring del modulo (linea 12) dice 'Nada de inferir'.

**Lo que se le escapa al analista:** Un volcador de credenciales con cuarentena FALLIDA en el controlador de dominio, y el grafo no conecta el binario con SRV-DC01. El analista que pincha m.exe no ve la maquina que hay que aislar; si esa alerta llega sola (fuera de una ingesta combinada) el DC aparece como esfera suelta sin ninguna relacion y se lee como ruido. Encima el grafo afirma 'jlopez escribio m.exe', que el evento no dice.

### Sin campo device, todo proceso se ancla al host literal '?': procesos de maquinas distintas se funden en un unico nodo y las maquinas desaparecen del grafo

`glamdring/graph/extract.py:161`

**Sale hoy:** Con dos eventos QRadar de proceso de dos maquinas distintas (sourceip 10.4.2.11 y 10.4.1.5) cuyo logsourcename es un producto ('CrowdStrike-EDR', descartado como host por looks_like_product), el grafo entero es: process:?|c:\windows\temp\svc.exe (grado=2, eventCount=2), user:jlopez, user:administrator. Un solo nodo de proceso para dos equipos, y NINGUN nodo host/ip: las dos maquinas no aparecen. _process_activity (linea 248) ancla el proceso solo a device_key, y la linea 161 sustituye el host ausente por la cadena '?', que colisiona entre maquinas. _process_activity nunca mira event.src, que si trae la IP.

**Deberia:** Es exactamente lo que el docstring de _add_process (lineas 152-154) dice que hay que evitar: 'Sin anclar al host, powershell.exe seria un unico nodo compartido por todas las maquinas del dominio y el grafo seria inservible'. Sin host conocido hay que usar el siguiente identificador disponible (event.src) y, si no hay ninguno, un discriminante unico por evento en vez de un '?' compartido, para no unir maquinas que no tienen nada que ver.

**Lo que se le escapa al analista:** El grafo dibuja una sola ejecucion de svc.exe compartida por dos equipos: el analista concluye que es un proceso unico y no ve que el mismo binario corre en la estacion Y en el DC, que es justo la senal de propagacion. Ademas ninguna de las dos maquinas entra en el grafo, asi que no hay nada que aislar. Cualquier fuente que reporte por producto (QRadar con logsourcename de fabricante) cae aqui.

### _network_activity crea el cortafuegos como nodo y no le pone ninguna arista: en telemetria de perimetro queda un nodo suelto (sospecha confirmada)

`glamdring/graph/extract.py:274`

**Sale hoy:** Ingiriendo samples/perimeter.cef completo el grafo tiene 9 nodos y 10 aristas, y el unico nodo con grado 0 es host:fgt-perim-01 (el FortiGate), presente en 3 eventos. En la mezcla de las cuatro muestras sigue con grado 0. _add_device (linea 263) lo crea desde dvchost; la linea 264 solo usa device_key como respaldo de src_key (que aqui SI existe: es el equipo interno), la linea 269 elige origin = process_key or src_key or device_key (gana src_key) y la linea 274 solo enlaza el device si hay proceso. Resultado: en un evento de red con src y sin proceso, el equipo que reporta no recibe ninguna arista.

**Deberia:** O bien no crear nodo para el dispositivo que solo observa el trafico (el cortafuegos es la fuente del log, no un participante), o bien enlazarlo explicitamente con la conexion que reporta (p.ej. src -[traversed]-> device -[traversed]-> dst, o device -[observed]-> arista). Lo que no puede quedar es creado y desconectado.

**Lo que se le escapa al analista:** En el grafo 3D el FortiGate flota sin conexiones: ocupa sitio, se puede confundir con un equipo comprometido aislado y no aporta nada. Y al reves: se pierde el hecho de por donde salio el trafico, que es lo unico que aporta la telemetria de perimetro cuando el EDR no cubre esa maquina. Es sistematico en toda fuente perimetral (firewall, proxy, DNS de salida) donde device=aparato y src=equipo interno.

### LEEF pierde la severidad: sev=8 sale como severidad 2 y el evento de C2 desaparece de la cronologia del informe

`glamdring/normalize/cef.py:264`

**Sale hoy:** SOSPECHA (a) CONFIRMADA. La linea 8 de perimeter.cef (LEEF PAN-OS, cat=command-and-control, sev=8) parsea a un record con la clave 'sev'='8'. 'sev' NO esta en CEF_KEY_ALIASES, asi que first(record,'cef_severity','severity','priority') devuelve None; tampoco hay 'syslog_severity' (la linea LEEF no lleva prefijo <pri>), asi que cae al else de la linea 271: severity = 3 if failure else 2. Como en el blob no hay ninguna palabra de _FAIL_HINTS, failure=False y sale severity=2 y status='success'. Consecuencia medida: narrative.is_key_event(evento) devuelve False, y el evento NO aparece en la cronologia que lee el analista.

**Deberia:** parse_severity('8', scale_max=10) devuelve 4 (lo comprobe). Basta anadir 'sev': 'severity' (y 'severity' de LEEF) a CEF_KEY_ALIASES para que la severidad 8/10 de PAN-OS se traduzca a 4. Con severity=4, is_key_event pasa a True y el trafico C2 entra en la cronologia. Ademas un 'threat' con cat=command-and-control no deberia salir con status='success'.

**Lo que se le escapa al analista:** El unico evento del corpus que dice literalmente 'Trafico C2 detectado' con severidad 8/10 del fabricante entra en GLAMDRING como un evento de severidad 2 y estado 'correcto', y queda fuera del informe. El analista no ve el command-and-control en su turno.

### parse_syslog no vuelve a mirar el texto: usuario e IP se quedan dentro de la cadena y el grafo se queda sin nodos ni aristas de autenticacion

`glamdring/normalize/cef.py:211`

**Sale hoy:** SOSPECHA (b) CONFIRMADA (con una correccion: en samples/perimeter.cef la IP es 10.4.2.11, no 10.4.2.9). La rama RFC3164 (lineas 200-211) guarda time/host/application/message y devuelve el record sin volver a mirar dentro de 'message'. Para las lineas 9, 10 y 11 el record solo tiene ['__format__','_raw','application','host','message','syslog_severity','time']: no hay src_ip, ni src_user, ni user. El evento sale con actor=None y src=None, y extract() produce un solo nodo 'host:srv-dc01' y CERO aristas para las tres lineas. Ademas, como las dos lineas de fuerza bruta pierden el usuario, narrative las funde en UNA sola entrada con count=2: 'Fallo un intento de autenticacion de un usuario desconocido contra srv-dc01'.

**Deberia:** Extraer del mensaje sshd lo que el propio texto ya dice: usuario ('for [invalid user] X'), IP origen ('from A.B.C.D') y puerto ('port N'). Verificado por control: rellenando actor=ActorRef(user='administrator') y src=HostRef(ip='10.4.2.11'), extract() pasa de 1 nodo y 0 aristas a nodos ['user:administrator','host:srv-dc01','ip:10.4.2.11'] y aristas [('user:administrator','failed_auth','host:srv-dc01'), ('ip:10.4.2.11','connected','host:srv-dc01')].

**Lo que se le escapa al analista:** Se pierden las tres piezas que hacen del incidente un incidente: que atacaron las cuentas 'administrator' y 'svc_backup' (se funden en 'un usuario desconocido'), que el origen es 10.4.2.11 (la MISMA maquina de la descarga web y del C2, es decir el enlace que une el segmento de perimetro con el de SSH) y que cinco minutos despues hubo un login correcto desde esa IP. En el grafo 3D no hay ni nodo de usuario ni nodo de IP: el pivote fuerza bruta -> acceso correcto es invisible.

### 'Malware Detected' con act=quarantine_failed sale como activity 'create' y el informe lo redacta como 'jlopez creo m.exe'

`glamdring/normalize/cef.py:351`

**Sale hoy:** SOSPECHA (c, caso 2) CONFIRMADA. Linea 7 de perimeter.cef (Defender, signature_id=1001, act=quarantine_failed, msg='Herramienta de volcado de credenciales detectada y no contenida'). El blob contiene 'file','malware','quarantine' -> CLASS_FILE, y la linea 351 solo distingue 'delete' si aparece 'delet' en el blob; 'Detected' no contiene 'delet', asi que activity='create'. La frase que narrative.describe() escribe en el informe es literalmente: 'jlopez creo m.exe en C:\\Windows\\Temp\\m.exe en srv-dc01.' y el grafo dibuja la arista ('user:jlopez','wrote','file:c:\\windows\\temp\\m.exe').

**Deberia:** Una deteccion de EDR no es una escritura de fichero atribuida al usuario. Deberia ser una alerta/deteccion (CLASS_FINDING con activity 'alert', o una actividad de fichero de tipo deteccion) que conserve act=quarantine_failed en la frase. Atribuir 'wrote' a jlopez es inventar una relacion que el evento no demuestra, justo lo que extract.py dice que no hay que hacer.

**Lo que se le escapa al analista:** El evento mas grave del corpus (sev 5, herramienta de volcado de credenciales que Defender NO consiguio contener) se le presenta al analista como 'jlopez creo un fichero'. Un usuario legitimo creando un .exe en Temp se descarta en treinta segundos; una contencion fallida de un dumper de credenciales en el DC obliga a aislar la maquina. Es exactamente el caso 'clasificar mal con aplomo'.

### El trafico C2 (LEEF, cat=command-and-control) se clasifica como Process Activity/'launch' y el grafo pierde la conexion 10.4.2.11 -> 45.132.88.17

`glamdring/normalize/cef.py:250`

**Sale hoy:** SOSPECHA (c, caso 3) CONFIRMADA. El blob incluye category='command-and-control' y _PROC_HINTS contiene 'command', asi que la rama de la linea 250 gana y class_name=CLASS_PROCESS -> activity='launch' (linea 349). Como el evento no tiene process_name ni cmdline, _process_activity() no genera nada: nodos=['user:jlopez'], aristas=[]. La conexion src=10.4.2.11 -> dst=45.132.88.17:443, que SI esta en el record, desaparece del grafo.

**Deberia:** 'command-and-control' es una tactica de red, no un proceso. Con class_name=CLASS_NETWORK y activity='connect' (control ejecutado) extract() devuelve nodos ['ip:10.4.2.11','ip:45.132.88.17','user:jlopez'] y aristas [('ip:10.4.2.11','connected','ip:45.132.88.17'), ('user:jlopez','authenticated','ip:10.4.2.11')]. El hint 'command' deberia exigir palabra completa o 'command line'/'commandline', no encajar dentro de 'command-and-control'.

**Lo que se le escapa al analista:** El canal de C2 hacia 45.132.88.17 (la misma IP a la que la linea 5 saca 734 MB) no existe como arista en el grafo 3D. El analista puede girar el grafo entero y no vera la conexion del implante; y como ademas sale con severidad 2 (hallazgo 1) tampoco esta en el texto del informe. El evento entra en el sistema y no deja rastro util en ninguna de las dos vistas.

### 'DNS Request' (signature_id=500) sale como File System Activity/'create': el grafo no crea el dominio ni una sola arista

`glamdring/normalize/cef.py:252`

**Sale hoy:** SOSPECHA (c, caso 1) CONFIRMADA, aunque el mecanismo NO es el signature_id: normalize() no lee signature_id en ningun sitio (solo aparece en las lineas 118 y 150, al construir el record). La clasificacion es por palabras sobre un blob que incluye _raw. En la linea 6 el blob contiene 'malware' (por cs1=Malware y por el msg) y 'dns'; como _FILE_HINTS se evalua ANTES que _NET_HINTS, gana CLASS_FILE y activity='create'. Al no haber fichero, _file_activity() no produce nada: nodos=['user:jlopez'], aristas=[].

**Deberia:** Una peticion DNS es CLASS_DNS (activity 'query') o, como minimo, red. Control ejecutado: con CLASS_DNS y domain='cdn-update-svc.com' extract() ya devuelve el nodo 'domain:cdn-update-svc.com'. La resolucion hacia un dominio clasificado como malware tiene que existir como nodo y arista.

**Lo que se le escapa al analista:** La resolucion DNS de 10.4.2.11 hacia cdn-update-svc.com (Umbrella la marca como categoria Malware) aporta cero al grafo: ni dominio, ni arista, ni entrada en la cronologia (is_key_event=False). El paso 'la maquina resolvio el dominio malicioso' desaparece de la linea temporal entre la navegacion y la descarga del ejecutable.

### 'Large Outbound Transfer': los 700 MiB de bytessent se tiran; el evento de exfiltracion queda byte a byte identico a una navegacion normal

`glamdring/normalize/qradar_events.py:189`

**Sale hoy:** normalize() nunca lee 'bytessent'/'bytesreceived'. El registro trae bytessent=734003200 (700 MiB) y bytesreceived=8442, y sale class='Network Activity', activity='connect', sin ningun campo de bytes (NormalizedEvent no tiene ninguno: ['uid','time','source','origin','class_name','activity','severity','status','message','actor','src','dst','device','process','file','email','domain','url','app','mitre','raw']). Poniendo bytessent=0 y bytesreceived=0 el evento normalizado es IDENTICO (comparacion model_dump excluyendo raw/uid -> True). En el informe sale '10.4.1.5 se conecto a 45.132.88.17:443.' y en el grafo RelSpec(source='ip:10.4.1.5', target='ip:45.132.88.17', type='connected', props={'port': 443}) -- exactamente la misma frase y la misma arista que 'Firewall Permit' (1 evento de navegacion normal), y hasta la misma tecnica MITRE (T1071.001 en los dos).

**Deberia:** Cuando el registro trae bytessent/bytesreceived debe conservarlos (campo propio en NormalizedEvent o al menos props de la arista, que ya admite extras: la arista lleva 'port'), marcar la asimetria (734003200 salientes contra 8442 entrantes, ratio 87.000:1) y etiquetar T1048/T1041 (exfiltracion) en vez de T1071.001, que es lo mismo que le pone a cualquier conexion. Sin el volumen no hay forma de distinguir una sesion HTTPS de 700 MB de una peticion web.

**Lo que se le escapa al analista:** El unico evento del incidente que prueba la exfiltracion (700 MiB saliendo de 10.4.1.5 hacia la misma IP externa del C2) llega al analista indistinguible de una peticion web cualquiera: misma clase, misma actividad, misma frase de informe, misma arista y misma tecnica ATT&CK. El dato que convierte 'conexion sospechosa' en 'fuga de datos confirmada' solo sobrevive dentro de raw, que nadie mira en el grafo 3D.

### 'Malware Detected Not Cleaned' (magnitude 9, AV) sale como creacion de fichero CON EXITO y el informe se lo atribuye al usuario

`glamdring/normalize/qradar_events.py:211`

**Sale hoy:** _classify() ve 'virus' en categoryname='Virus Detected' (_FILE_WORDS, linea 85) y devuelve CLASS_FILE antes de mirar nada mas; la rama de linea 210-218 fija activity='create'. Ademas _is_failure() (linea 128) busca ('fail','denied','deny','block','reject','invalid','unauthorized') y 'Malware Detected Not Cleaned' no contiene ninguna, asi que status='success'. Resultado: class='File System Activity' / activity='create' / status='success' / mitre=[]. narrative.describe() produce: 'jlopez creo m.exe en C:\Windows\Temp\m.exe en 10.4.1.5.' y el grafo genera RelSpec(source='user:jlopez', target='file:c:\windows\temp\m.exe', type='wrote').

**Deberia:** Una deteccion de antivirus es un hallazgo, no una operacion de fichero del usuario. Con categoryname='Virus Detected' y logsourcename='TrendMicro-AV' deberia salir class_name=CLASS_FINDING / activity='alert' (o al menos CLASS_FILE con activity='malware_detected'), status='failure' o 'unknown' (el AV NO limpio: 'Not Cleaned'), y MITRE T1204/T1105 segun proceda. La arista debe ser 'detected'/'affects' entre la alerta y el fichero, nunca user:jlopez --wrote--> file, porque el AV no dice que jlopez lo escribiera.

**Lo que se le escapa al analista:** Confirmado: es exactamente el caso que el dominio no perdona. El evento de mayor magnitude del incidente (9/10), un malware que el antivirus NO consiguio limpiar en C:\Windows\Temp\m.exe, llega al analista como 'jlopez creo m.exe' con status 'exito' y sin ninguna tecnica ATT&CK. Cualquier filtro por alertas, por status=failure o por clase 'Detection Finding' lo deja fuera, y encima el grafo imputa la escritura al usuario, que es la victima. El binario sigue en disco y el informe lo cuenta como actividad rutinaria.

### El evento DNS de QRadar fabrica una arista 'resolved' FALSA: el dominio malicioso aparece resolviendo al servidor DNS interno de la empresa

`glamdring/normalize/qradar_events.py:191`

**Sale hoy:** 'DNS Query' se clasifica CLASS_NETWORK (linea 84: 'dns' esta en _NET_WORDS) y la rama de red pone activity='connect' y domain='cdn-update-svc.com' (linea 191-193), dejando dst=10.4.0.10, que es el RESOLUTOR InfoBlox, no la IP resuelta. Como el class_name es 'Network Activity', extract() lo enruta a _network_activity(), que en su ultimo bloque asume que event.dst.ip es la IP del dominio y emite: RelSpec(source='domain:cdn-update-svc.com', target='ip:10.4.0.10', type='resolved'). Ademas la primera arista dice ip:10.4.2.11 --connected--> domain:cdn-update-svc.com, cuando el host no se conecto al dominio: pregunto por el. En el mismo grafo, el evento 'Proxy Allowed' emite la arista correcta domain:cdn-update-svc.com --resolved--> ip:45.132.88.17, asi que conviven dos aristas 'resolved' contradictorias para el mismo dominio.

**Deberia:** Un evento con categoryname='DNS Session'/'DNS Query' y domainname debe salir class_name=CLASS_DNS y activity='query' (existe: models.py CLASS_DNS='DNS Activity', class_uid 4003, y extract.py tiene _dns_activity). Y la IP resuelta debe venir del campo de respuesta, no de destinationip: el destinationip de un log de DNS es SIEMPRE el resolutor. Si no hay campo de respuesta, no debe emitirse ninguna arista 'resolved'.

**Lo que se le escapa al analista:** El grafo inventa un IOC. El analista que pivota sobre el dominio de C2 para sacar la IP a bloquear ve dos respuestas contradictorias y una de ellas es el resolutor DNS corporativo (10.4.0.10). En el mejor caso pierde el turno persiguiendo su propia infraestructura; en el peor mete 10.4.0.10 en una lista de bloqueo y tumba la resolucion DNS de toda la red. Un dato inventado con aplomo es peor que un hueco.

### La misma resolucion DNS del mismo dominio se clasifica de tres formas incompatibles segun la fuente, y en CEF hasta pierde el dominio

`glamdring/normalize/qradar_events.py:84`

**Sale hoy:** Alcance medido sobre las tres muestras reales, todas resolviendo cdn-update-svc.com:
- qradar_ariel.json ('DNS Query', InfoBlox): class='Network Activity', activity='connect', sev=2, domain='cdn-update-svc.com' -> extract() lo manda a _network_activity() -> informe: '10.4.2.11 se conecto a cdn-update-svc.com.'
- splunk_windows.json (Sysmon EventID 22): class='DNS Activity', activity='query', sev=1, domain='cdn-update-svc.com' -> _dns_activity() -> informe: 'wks-0421 resolvio el dominio cdn-update-svc.com.'
- perimeter.cef (Cisco Umbrella 'DNS Request'): class='File System Activity', activity='create', sev=3, domain=None -> _file_activity() -> informe: 'jlopez creo un fichero en cdn-update-svc.'
Son tres class_name, tres activity, tres funciones distintas de extract.py y tres frases distintas de narrative.describe(). qradar_events.py no importa CLASS_DNS en ningun sitio: por diseno no puede emitir la clase que ya existe en models.py. En CEF ademas el dominio se pierde entero (domain=None) y acaba convertido en un nombre de fichero.

**Deberia:** Un unico contrato de ontologia: toda resolucion DNS, venga de donde venga, debe ser class_name=CLASS_DNS + activity='query' con el dominio en event.domain. Eso ya esta implementado y probado en splunk_windows.py (_dns_query, linea 259-263) y en sentinel_defender.py (_dns, linea 331). qradar_events.py debe detectar categoryname 'DNS Session'/'DNS Query'/domainname ANTES de caer en _NET_WORDS y devolver CLASS_DNS; cef.py debe dejar de mandar 'DNS Request' a la rama de fichero.

**Lo que se le escapa al analista:** Es el problema central de la fase, y es peor que un nombre inconsistente: la clase decide la RUTA de extraccion, asi que el mismo hecho produce tres subgrafos distintos y tres frases distintas en el mismo informe. El analista que filtre por 'DNS Activity' ve solo la mitad Splunk/Sentinel y se pierde la consulta de QRadar y la de Umbrella; el que cuente 'cuantas veces se resolvio el dominio del C2' obtiene 1 en vez de 3. Y en CEF el dominio malicioso desaparece del modelo y reaparece como fichero, o sea que ni siquiera hay nodo de dominio que pivotar.

### Las categorias de la ofensa se convierten en tecnicas ATT&CK inventadas con ids como "['MALWARE DETECTED'", que llegan al grafo y al informe

`glamdring/normalize/qradar_events.py:246`

**Sale hoy:** La linea 246 hace techniques(str(categories)). 'categories' en la API de ofensas de QRadar es una LISTA de nombres de la taxonomia propia de QRadar, no ids de ATT&CK. El str() convierte la lista en "['Malware Detected', 'Authentication Failure']"; techniques() no encuentra ningun patron Tnnnn, cae al split por comas y pasa cada trozo a technique(), que NUNCA devuelve None para una cadena no vacia (mitre.py linea 91: return Technique(id=tid, name="", tactic="")). Resultado: mitre=["['MALWARE DETECTED'", "'AUTHENTICATION FAILURE']"] -- con corchete y comilla incluidos. Esas cadenas salen como props del nodo de alerta (extract.py linea 346: techniques=[t.id for t in event.mitre]) y en la cronologia del informe: {"techniques": ["['MALWARE DETECTED'", "'AUTHENTICATION FAILURE']"], "tactics": []}.

**Deberia:** No pasar la taxonomia de QRadar por techniques(). O se mapea explicitamente categoria QRadar -> tecnica ATT&CK con una tabla, o se deja event.mitre vacio y las categorias se guardan como texto descriptivo. Y como minimo techniques() no debe recibir str(lista): ya acepta listas nativamente (mitre.py linea 101), y technique() deberia rechazar lo que no case con el patron Tnnnn en vez de fabricar una Technique con cualquier cadena.

**Lo que se le escapa al analista:** El informe que el analista entrega lleva un campo 'techniques' con basura sintactica que ninguna matriz ATT&CK reconoce, y sin ninguna tactica (tactics vacio) porque los ids no existen. Peor: como narrative.is_key_event() devuelve True en cuanto hay event.mitre, estas tecnicas falsas fuerzan la entrada de eventos en la cronologia. Un mapeo ATT&CK inventado en un informe de incidente es un problema de credibilidad ante el cliente y ante el que audita el caso.

### La tabla DeviceEvents entera se clasifica como consulta DNS con severidad 1, y eso la saca de la cronologia del informe

`glamdring/normalize/sentinel_defender.py:348`

**Sale hoy:** Cualquier fila con Type='DeviceEvents' cae en _dns() sin mirar ActionType. ActionType='SecurityLogCleared' -> class='DNS Activity', activity='query', sev=1; lo mismo AntivirusDetection y RegistryValueSet. narrative.is_key_event() devuelve False para los tres, asi que no aparecen en la cronologia del informe. La frase generada es 'srv-dc01 resolvio el dominio desconocido.'

**Deberia:** DeviceEvents es la tabla cajon de sastre de Defender: lleva mas de cien ActionType distintos (SecurityLogCleared, AntivirusDetection, RegistryValueSet, ScheduledTaskCreated, ProcessPrimaryTokenModified, ShellLinkCreateFileEvent...). Solo DnsQueryResponse/DnsConnectionInspected son DNS. Hay que despachar por ActionType dentro de DeviceEvents y mandar cada grupo a su clase (borrado de log de auditoria -> finding de severidad alta, registro -> actividad de registro, deteccion AV -> finding), no colapsarlo todo a CLASS_DNS/sev 1.

**Lo que se le escapa al analista:** Es exactamente el caso del 1102 que describe el enunciado, pero en Defender: el borrado del log de seguridad sale como una consulta DNS informativa, con severidad 1 y sin linea en la cronologia. El analista no lo ve nunca. Igual con la deteccion del antivirus y con la clave Run de persistencia.

### _guess_table mira RemoteIP antes que LogonType: un logon de Defender sin 'Type' se convierte en conexion de red y pierde la cuenta

`glamdring/normalize/sentinel_defender.py:68`

**Sale hoy:** Con la fila real samples/sentinel_defender.json[8] (DeviceLogonEvents contra srv-dc01) y sin la clave 'Type', _guess_table devuelve 'DeviceNetworkEvents' porque la rama de RemoteIP (linea 68) va antes que la de LogonType (linea 76). El evento pasa de Authentication/logon_remote/actor=jlopez a Network Activity/connect/actor=None.

**Deberia:** DeviceLogonEvents lleva RemoteIP en casi todas sus filas, asi que la rama de red se la come siempre. La huella de LogonType (o de ActionType empezando por 'Logon') es discriminante y tiene que evaluarse antes que RemoteIP/RemoteUrl. El docstring del modulo dice que esta ruta es la que se usa cuando el conector no inyecta 'Type', o sea que no es un camino teorico.

**Lo que se le escapa al analista:** El movimiento lateral desaparece del grafo: no hay arista de autenticacion, no hay nodo de usuario colgando del DC, y se pierde el T1021.002. Un LogonFailed repetido desde una IP externa (fuerza bruta RDP) sale como 'conexion de red fallida' en vez de como intento de autenticacion, asi que ninguna regla de fuerza bruta lo cuenta.

### Seis tablas de Defender que matches() reclama no tienen handler: acaban en el generico como 'alerta con status=success', sin mensaje y sin equipo

`glamdring/normalize/sentinel_defender.py:338`

**Sale hoy:** DeviceRegistryEvents, IdentityLogonEvents, IdentityDirectoryEvents, CloudAppEvents, DeviceImageLoadEvents, AlertEvidence y EmailUrlInfo no estan en _TABLES. matches() devuelve True (los reclama), normalize() devuelve None, y base.normalize_record sigue hasta el generico, que produce: source='generic', class='Detection Finding', activity='alert', status='success', sev=2, device=None, message=''. La frase del informe es 'Se disparo la alerta «» sobre un equipo sin identificar.' y is_key_event() da True, asi que esas lineas vacias SI entran en la cronologia.

**Deberia:** Son las tablas que mas pesan en un turno de SOC: DeviceRegistryEvents es la persistencia (Run keys, servicios), IdentityLogonEvents es el logon on-prem de AD (Kerberos/NTLM, fuerza bruta y pass-the-hash), CloudAppEvents es la actividad en O365 (MailItemsAccessed, reglas de buzon, exfiltracion) y DeviceImageLoadEvents es el side-loading de DLL. Cada una necesita su handler con su class_name; mientras no lo tengan, matches() no deberia reclamarlas, para que al menos el generico no las etiquete como alerta correcta.

**Lo que se le escapa al analista:** Un LogonFailed de IdentityLogonEvents (fuerza bruta contra el DC) sale con status='success'. Ademas se pierde DeviceName aunque venia en el registro, asi que el nodo no se funde con srv-dc01 y queda flotando fuera del incidente. La cronologia se llena de lineas 'Se disparo la alerta «» sobre un equipo sin identificar', que es ruido con aplomo justo en el sitio donde el analista busca la persistencia y el acceso al buzon.


## Gravedad media

### Cualquier IPv6 valido cuenta como 'IP publica' y sube la severidad a 3: el SMB interno por IPv6 y hasta ::1 se marcan como posible C2

`glamdring/normalize/splunk_windows.py:232`

**Sale hoy:** La linea 232 sube la severidad cuando el destino no es privado, pero is_private_ip (base.py) empieza por 'not _IPV4.match(value): return False', asi que para cualquier IPv6 devuelve False. Como is_ip() si acepta IPv6, dst.ip se rellena y la severidad sube. Medido: fe80::a1b2:c3d4 (link-local, misma LAN) -> 3; fd00:1234::10 (ULA interno) -> 3; ::1 (loopback) -> 3; mientras 10.4.2.50 y 192.168.1.10 -> 2. En el grafo, una sola conexion SMB interna por IPv6 deja el proceso, el host y el usuario en rol 'suspicious'.

**Deberia:** is_private_ip debe entender IPv6: fc00::/7 (ULA), fe80::/10 (link-local) y ::1 son internos, igual que RFC1918. Mientras no lo entienda, la linea 232 no deberia subir la severidad para destinos IPv6, porque afirma lo contrario de lo que ocurre.

**Lo que se le escapa al analista:** En un dominio Windows moderno IPv6 esta activo por defecto y buena parte del trafico SMB y LDAP entre equipos va por link-local. Con esto, el trafico interno mas rutinario entra en el grafo con la misma severidad que una conexion a infraestructura del atacante, y arrastra al proceso, al host y al usuario a rol 'suspicious'. Es ruido que compite en color y en tamano con el incidente real, y ademas envenena el umbral de severidad del hallazgo anterior por el otro extremo.

### Los campos multivalor de Splunk (4624 trae dos Account_Name) se convierten en un nodo de usuario literal "['-', 'SVC_BACKUP']"

`glamdring/normalize/splunk_windows.py:117`

**Sale hoy:** first() (base.py) devuelve el valor tal cual, y _logon hace str(user) en la linea 119. Cuando la busqueda devuelve Account_Name como lista -que es lo que pasa en un 4624/4625 de WinEventLog:Security, donde el registro lleva el Account_Name del Subject y el del New Logon, y el export JSON los entrega como array- el actor queda como la cadena "['-', 'SVC_BACKUP']". canon_user no lo arregla porque no es ni DOMINIO\\usuario ni un UPN, y el nodo del grafo acaba con id "user:['-', 'svc_backup']". Lo mismo con Account_Domain.

**Deberia:** first() (o los normalizadores) deberian resolver las listas: quedarse con el ultimo valor no vacio y descartar los '-'. En 4624 el valor util es el segundo, el de New Logon. Un valor de campo que no es una cadena no puede llegar a str() sin mirar.

**Lo que se le escapa al analista:** La identidad canonica del usuario es la columna vertebral del grafo: es lo que permite fundir 'CORP\\jlopez', 'JLOPEZ' y 'jlopez@corp.com' en un solo nodo. Cuando el TA devuelve multivalor, el mismo usuario aparece como un nodo con nombre de lista de Python que no se funde con su propio nodo procedente de Sysmon o de Defender, y las busquedas por nombre de cuenta no lo encuentran. Ademas ese texto sale tal cual en el informe que el analista entrega, lo que destruye la credibilidad del documento.

### La misma maquina sale como dos nodos (hostname huerfano + IP con todas las aristas) cuando la fuente pone el nombre en device y la IP en dst

`glamdring/graph/build.py:291`

**Sale hoy:** Ingiriendo solo samples/qradar_ariel.json: host:srv-dc01 grado=0 con props.ip=None, mientras ip:10.4.1.5 tiene grado=5 y concentra failed_auth de administrator, authenticated de jlopez, la salida bloqueada a 185.220.101.44 y la conexion a 45.132.88.17. Son la MISMA maquina (QRadar pone logsourcename=SRV-DC01 y destinationip=10.4.1.5 en el mismo registro; en la mezcla de las cuatro muestras host:srv-dc01 acaba con props.ip='10.4.1.5'). _merge_ip_into_hosts solo funde una ip en un host que declare esa ip en props, y qradar_events.py:174 construye siempre HostRef(hostname=...) sin ip, igual que cef.py:307, asi que la fusion nunca puede dispararse con esas fuentes.

**Deberia:** Cuando un mismo registro trae hostname en device e IP en dst/src, esa correspondencia deberia usarse para atribuir la IP al host (o al menos para no dejar el nodo hostname huerfano). Hoy la union depende de que otra fuente distinta (aqui el CEF de Fortinet, con shost=SRV-DC01 y src=10.4.1.5 juntos) aporte por casualidad el par nombre+IP en el mismo endpoint.

**Lo que se le escapa al analista:** El analista que solo tiene el export de QRadar (el caso normal: se exporta la busqueda de un SIEM, no de cuatro) ve el DC partido en dos: un 'srv-dc01' suelto que parece irrelevante y un '10.4.1.5' que es donde esta todo el ataque. Buscar por nombre de maquina no lleva a las aristas. Nota: la canonicalizacion de usuarios y hosts SI funciona (canon_user devuelve 'jlopez' para 'CORP\\jlopez', 'JLOPEZ' y 'jlopez@corp.com'; canon_host devuelve 'wks-0421' para 'WKS-0421.corp.local'), y en la mezcla de las cuatro muestras user:jlopez y host:wks-0421 salen como un unico nodo con sources=['generic','qradar','sentinel','splunk']. El problema es solo nombre-vs-IP.

### _process_activity calcula file_key y nunca lo enlaza: cada creacion de proceso deja un nodo 'file' huerfano que duplica al 'process' del mismo binario

`glamdring/graph/extract.py:250`

**Sale hoy:** Con el evento Sysmon EventID 1 (process create powershell.exe) de samples/splunk_windows.json el grafo incluye a la vez process:wks-0421|c:\windows\system32\windowspowershell\v1.0\powershell.exe (grado=4) y file:c:\windows\system32\windowspowershell\v1.0\powershell.exe con GRADO=0. La linea 250 asigna file_key y esa variable no se usa en ninguna de las lineas 252-259 (solo se usa hash_key). En la mezcla de las cuatro muestras ese nodo file sigue con grado 0 y sources=['sentinel','splunk'].

**Deberia:** O no crear el nodo file para la imagen del proceso (el proceso ya lo representa), o enlazarlo (process -[image]-> file). Un nodo creado y nunca enlazado es basura garantizada; la propia cabecera del modulo dice que solo se crea un nodo si aporta identidad estable.

**Lo que se le escapa al analista:** El mismo binario aparece dos veces con la misma etiqueta ('powershell.exe'), uno conectado y otro flotando. El analista no sabe si son dos cosas distintas (una copia del binario en otro sitio?) o un duplicado, y eso hace dudar del resto del grafo. Escala: uno por cada ruta de imagen distinta vista en eventos de creacion de proceso.

### _file_activity deja al usuario sin ninguna arista cuando el evento trae proceso: se pierde quien escribio el fichero

`glamdring/graph/extract.py:294`

**Sale hoy:** Con los dos Sysmon EventID 11 (File created) de samples/splunk_windows.json (certutil.exe crea upd.exe en WKS-0421, svchost.exe crea m.exe en SRV-DC01) el nodo user:jlopez queda con GRADO=0. La linea 294 enlaza process_key OR user_key OR device_key con el fichero: si hay proceso, el usuario que _add_user creo en la linea 289 no se enlaza con nada, y a diferencia de _process_activity (linea 253) aqui no existe ninguna arista user->process 'executed'.

**Deberia:** Igual que en _process_activity, deberia emitirse collector.link(user_key, process_key, 'executed') tambien en la actividad de fichero, para que la cuenta que escribio el fichero quede unida a la cadena.

**Lo que se le escapa al analista:** En una ingesta de auditoria de ficheros (un servidor de ficheros, un export de DeviceFileEvents) TODAS las cuentas quedan como nodos sueltos y el grafo no responde a la pregunta basica 'que usuario dejo caer el fichero'. En la mezcla completa se disimula porque jlopez recibe aristas de otros eventos, pero la atribucion de ese fichero concreto a esa cuenta no existe.

### _process_activity ignora event.src y event.dst: un evento de C2 con origen y destino no produce ninguna arista (solo 54,5% de perimeter.cef genera aristas)

`glamdring/graph/extract.py:245`

**Sale hoy:** Cobertura de aristas medida por muestra: splunk_windows.json 21/21 = 100,0%; qradar_ariel.json 8/8 = 100,0%; sentinel_defender.json 12/12 = 100,0%; perimeter.cef 6/11 = 54,5%. De los 5 eventos de perimeter.cef sin arista: (a) el LEEF de PAN-OS 'Trafico C2 detectado hacia cdn-update-svc.com' se clasifica como Process Activity y _process_activity no mira src (10.4.2.11) ni dst (45.132.88.17:443): entidades=['user:jlopez'], relaciones=[]; (b) el DNS de Umbrella cae en File System Activity y _file_activity tampoco mira src/dst: entidades=['user:jlopez'], relaciones=[]; (c) las tres lineas syslog de SSH (2 'Failed password for invalid user administrator/svc_backup from 10.4.2.11' y 1 'Accepted password for jlopez from 10.4.2.11') llegan con actor=None y src=None porque el normalizador generico de cef.py:309 solo busca el usuario en campos clave-valor y no parsea el texto del mensaje, asi que _authentication crea host:srv-dc01 y no enlaza nada.

**Deberia:** Las reglas _process_activity y _file_activity deberian caer al par src/dst cuando el evento los trae, igual que hace _network_activity: un evento con IP de origen y de destino siempre demuestra una conexion, la clase que le haya tocado no cambia ese hecho. Con eso, los casos (a) y (b) dejarian de ser nodos sueltos aunque el normalizador se equivoque de clase.

**Lo que se le escapa al analista:** Casi la mitad de la telemetria de perimetro no aporta ni una relacion al grafo. Se pierde una deteccion explicita de C2 con su destino, y se pierde entera una secuencia de fuerza bruta SSH contra el DC (dos intentos fallidos contra 'administrator' y 'svc_backup' seguidos de un acceso CORRECTO de jlopez desde la misma 10.4.2.11): en el grafo no existe ni el intento ni el exito ni el origen. Es la firma de movimiento lateral que la herramienta dice buscar.

### El dominio consultado por DNS pierde el TLD y nunca llega a event.domain: 'host:cdn-update-svc' no se une nunca con 'domain:cdn-update-svc.com'

`glamdring/normalize/cef.py:318`

**Sale hoy:** En la linea 6, dhost='cdn-update-svc.com' se aliasa a dest_host y en la linea 301 se pasa por canon_host(), que corta en el primer punto: 'cdn-update-svc'. La rama de dominio de la linea 318 solo mira 'domain','dest_domain','query' -> event.domain queda en None. Incluso forzando la clase correcta a red, el destino sale como nodo de HOST interno: nodos ['ip:10.4.2.11','host:cdn-update-svc','user:jlopez'].

**Deberia:** Si dest_host tiene forma de FQDN externo (canon_domain lo valida) hay que poblar event.domain con 'cdn-update-svc.com' y no modelarlo como host recortado. La linea 2 del mismo fichero SI crea 'domain:cdn-update-svc.com' (via request=). Hoy conviven dos nodos distintos para la misma cosa.

**Lo que se le escapa al analista:** El IOC se parte en dos nodos que el analista no puede pivotar: el dominio de la descarga ('domain:cdn-update-svc.com', linea 2) y el de la resolucion DNS ('host:cdn-update-svc', linea 6) no se tocan, y el segundo ademas parece un host interno. Bloquear el dominio a partir del grafo requiere darse cuenta a mano de que son el mismo.

### El normalizador generico nunca emite 'logon_remote': el login SSH correcto no genera la arista 'lateral' ni entra en la cronologia

`glamdring/normalize/cef.py:343`

**Sale hoy:** La linea 343 solo produce 'logon' o 'logon_failed'. La linea 11 (Accepted password for jlopez from 10.4.2.11) sale como activity='logon' e is_key_event()=False, asi que NO aparece en la cronologia del informe. extract.py (linea 237) y narrative.py (lineas 125 y 199) tratan 'logon_remote' de forma especial ('exactamente la firma del movimiento lateral'), pero ningun camino de cef.py lo emite: solo lo producen splunk_windows.py y sentinel_defender.py.

**Deberia:** Un 'Accepted password ... from <IP> ssh2' es un inicio de sesion remoto. Control ejecutado: con activity='logon_remote', actor=jlopez y src=10.4.2.11 la frase del informe pasa a 'jlopez inicio sesion remota en srv-dc01 desde 10.4.2.11, que es la firma del movimiento lateral', is_key_event=True y aparece la arista ('ip:10.4.2.11','lateral','host:srv-dc01').

**Lo que se le escapa al analista:** El acceso SSH correcto a SRV-DC01 desde la misma IP que acababa de fallar dos veces con 'administrator' y 'svc_backup' no sale en el informe y no dibuja la arista de movimiento lateral que el grafo tiene expresamente prevista. Es el evento que convierte 'ruido de fuerza bruta' en 'intrusion con exito'.

### La severidad 'sev' de LEEF no esta mapeada: una deteccion de command-and-control con sev=8/10 entra en el grafo como severidad 2/5

`glamdring/normalize/cef.py:264`

**Sale hoy:** El registro LEEF de PAN-OS de samples/perimeter.cef se parsea conservando la clave cruda 'sev': '8' (CEF_KEY_ALIASES no la traduce). En la linea 264 first(record, 'cef_severity', 'severity', 'priority') no la encuentra, no hay 'syslog_severity' en ese registro (la linea no lleva prioridad syslog) y se cae al ultimo respaldo: severity = 3 si failure else 2. Como 'command-and-control' no contiene ninguna palabra de _FAIL_HINTS, failure=False y el evento queda con severidad 2. Salida: severidad normalizada: 2.

**Deberia:** Anadir 'sev' (y 'severity' en su grafia LEEF) a CEF_KEY_ALIASES o a la lista de first() de la linea 264, de modo que parse_severity(8, scale_max=10) devuelva 4. La escala de riesgo debe errar por exceso, como ya hace _round_half_up en base.py.

**Lo que se le escapa al analista:** build.py alimenta _risk con max_severity y ordena los nodos por riesgo descendente, asi que el trafico de mando y control se hunde en la lista y se pinta como si fuera trafico rutinario. El cortafuegos lo marco como grave y la herramienta lo rebaja con aplomo. Afecta a toda fuente LEEF (QRadar consume LEEF a diario).

### Todo trafico interno->externo recibe T1071.001 y suelo de severidad 3: la navegacion normal entra en la cronologia del informe y anula la magnitude de QRadar

`glamdring/normalize/qradar_events.py:199`

**Sale hoy:** Respuesta a la pregunta 4: el mapeo de magnitude en si es monotono y defensible -- parse_severity(m, scale_max=10) da 1->1, 2->1, 3->2, 4->2, 5->3, 6->3, 7->4, 8->4, 9->5, 10->5, redondeando hacia arriba (magnitude 9 -> 5 critica). El problema es que se pisa a continuacion. Las lineas 194-199 aplican event.severity = max(event.severity, 3) y event.mitre = techniques('T1071.001') a CUALQUIER conexion de IP privada a IP publica, sin mirar puerto, dominio, reputacion ni bytes. Un 'Firewall Permit' de navegacion a 142.250.185.78:443 con magnitude 1 (lo mas benigno que emite QRadar) sale con severity=3 y mitre=['T1071.001'], y como narrative.is_key_event() devuelve True si hay mitre, entra en la cronologia del informe. En la muestra: 3 de 8 eventos llevan T1071.001 ('Firewall Permit', 'Proxy Allowed' y 'Large Outbound Transfer' -- la misma etiqueta para la navegacion benigna y para la exfiltracion de 700 MB). Eventos clave en la cronologia hoy: 6 de 8; solo con la magnitude de QRadar serian 4.

**Deberia:** La magnitude ya combina credibilidad, relevancia y severidad y es el juicio que el operador de QRadar ha afinado; el normalizador no deberia subirla por una heuristica de 'la IP destino es publica', que se cumple en el 99% del trafico corporativo. T1071.001 debe reservarse para lo que tenga indicio real (puerto no estandar, dominio con reputacion, periodicidad de beacon, volumen) y la exfiltracion debe llevar T1048/T1041, no la misma etiqueta que abrir una web.

**Lo que se le escapa al analista:** En una captura real (miles de conexiones salientes por turno) esto convierte toda la navegacion corporativa en eventos de severidad media etiquetados como Command and Control, y todos entran en la cronologia del informe. La etiqueta T1071.001 deja de significar nada: si la lleva todo, el analista aprende a ignorarla, y con ella ignora el unico evento donde importaba. Ademas se anula el criterio del ingeniero de QRadar, que es quien conoce esa red.

### En una ofensa, el offense_source de tipo Username se convierte en un HOST inventado; offense_type se lee para la rama pero nunca para interpretar el valor

`glamdring/normalize/qradar_events.py:243`

**Sale hoy:** _offense() (linea 237-243) solo comprueba is_ip(offense_source): si no es IP, lo mete como HostRef(hostname=...). QRadar tiene ~15 tipos de ofensa y offense_type dice cual es (0=Source IP, 3=Username, 7=Hostname, 6=Log Source, 2=Event Name...), pero el codigo lo usa solo para decidir la rama en la linea 135 y despues lo ignora. Con una ofensa real de la API /siem/offenses con offense_type=3 y offense_source='administrator' sale device=HostRef(hostname='administrator') y actor=None, y extract() genera el nodo ('host', 'administrator') con la arista alert --affects--> host:administrator. En el grafo combinado con los eventos de la misma muestra conviven dos nodos: 'user | administrator' (de 'Multiple Login Failures') y 'host | administrator' (de la ofensa). Ademas event_count=1842 de la ofensa no se traslada a ningun sitio y status='OPEN' se descarta (queda 'unknown').

**Deberia:** Interpretar offense_source segun offense_type: tipo 3 (Username) -> event.actor = ActorRef(user=...) para que la ofensa se cuelgue del nodo user que ya existe; tipo 0/1 -> src/dst; tipo 7 -> device. Es exactamente la misma cautela que el propio fichero aplica en las lineas 164-172 con logsourcename ('convertir un nombre de producto en un host llena el grafo de maquinas que no existen'), pero aqui no se aplica.

**Lo que se le escapa al analista:** La ofensa es la conclusion correlada de QRadar, la pieza que deberia atar todo el incidente, y aterriza colgada de una maquina que no existe. El grafo muestra un equipo llamado 'administrator' junto al usuario 'administrator', y la alerta queda desconectada del subgrafo del usuario real: el analista que pincha en el nodo user:administrator no ve la ofensa que le afecta. Encima se pierde que detras hay 1842 eventos y que la ofensa esta ABIERTA.

### Se descarta 'eventcount': 14 fallos de autenticacion agregados por QRadar se cuentan como 1 en la cronologia

`glamdring/normalize/qradar_events.py:143`

**Sale hoy:** normalize() no lee 'eventcount' en ningun punto. QRadar agrega, y en la muestra 'Multiple Login Failures for Single Username' trae eventcount=14, 'DNS Query' trae 6 y 'Firewall Deny' trae 3. Al normalizar, cada registro produce UN NormalizedEvent sin ningun campo de recuento (el modelo no lo tiene) y narrative.summarize_events() reporta count=1. La cronologia entera de la muestra sale con count=1 en las seis entradas, aunque los registros suman 28 eventos reales.

**Deberia:** El propio comentario de narrative.summarize_events dice 'Catorce fallos de login identicos son un hecho, no catorce hechos' -- pero para poder decir 'catorce' hay que conservar el numero. eventcount debe llegar al evento normalizado (campo de recuento en NormalizedEvent, o al menos alimentar el count de la cronologia y el eventCount del nodo del grafo, que ya existe en models.py linea 180).

**Lo que se le escapa al analista:** Un fallo de autenticacion aislado es ruido de fondo; catorce contra 'administrator' en el mismo minuto son una fuerza bruta. El informe presenta 'Fallo un intento de autenticacion de administrator contra srv-dc01' en singular y sin numero, asi que el analista no tiene motivo para escalarlo. Lo mismo con los 3 bloqueos hacia 185.220.101.44:9001 (nodo Tor) y las 6 consultas al dominio de C2: la repeticion, que es la senal, se aplana a uno.

### _dns tampoco saca el dominio de la unica tabla para la que sirve: DnsQueryResponse deja domain=None

`glamdring/normalize/sentinel_defender.py:333`

**Sale hoy:** canon_domain(first(record,'RemoteUrl','AdditionalFields')). Las filas DnsQueryResponse de DeviceEvents no traen RemoteUrl; el dominio consultado viaja dentro de AdditionalFields, que es una cadena JSON ('{"DnsQueryString":"cdn-update-svc.com",...}'). canon_domain no la sabe interpretar y devuelve None. La frase del informe queda 'wks-0421 resolvio el dominio desconocido.'

**Deberia:** Parsear AdditionalFields con json.loads y leer DnsQueryString (o el campo equivalente segun ActionType) antes de pasarlo a canon_domain, para que domain='cdn-update-svc.com' y el nodo de dominio se funda con el que ya crean DeviceNetworkEvents y la URL de la alerta.

**Lo que se le escapa al analista:** El pivote clasico 'que equipos han resuelto este dominio de C2' no devuelve nada. La resolucion DNS es muchas veces la unica huella cuando la conexion la bloqueo el proxy, y aqui se pierde el IOC entero: queda un nodo DNS sin dominio, que no enlaza con nada.

### _guess_table mira FolderPath antes que SHA256+FileName: un DeviceFileEvents sin 'Type' se convierte en lanzamiento de proceso

`glamdring/normalize/sentinel_defender.py:66`

**Sale hoy:** Con la fila real samples/sentinel_defender.json[2] (FileCreated de factura_2026-0819.iso) y sin la clave 'Type', _guess_table devuelve 'DeviceProcessEvents' porque la rama 'ProcessCommandLine' or 'FolderPath' (linea 66) va antes que la de DeviceFileEvents (linea 74). class pasa de 'File System Activity'/create a 'Process Activity'/launch.

**Deberia:** DeviceFileEvents trae FolderPath en todas sus filas, luego la rama de proceso se la come siempre. La condicion de proceso tiene que exigir ProcessCommandLine (o ProcessId), no FolderPath a secas, y la de fichero (SHA256+FileName o ActionType File*) evaluarse antes.

**Lo que se le escapa al analista:** La descarga del .iso malicioso aparece en el grafo como si el .iso se hubiera ejecutado. Es una afirmacion mas fuerte que la que dice el log: el analista concluye ejecucion donde solo hubo escritura en disco, y ademas se pierde la arista de creacion de fichero que ataba chrome.exe con el fichero soltado.

### EmailEvents y SigninLogs salen siempre con message vacio: _base lee cuatro campos que esas dos tablas no tienen

`glamdring/normalize/sentinel_defender.py:92`

**Sale hoy:** _base construye message con first(record,'AlertName','Description','ActionType','Title'). EmailEvents no tiene ninguno de los cuatro (su texto esta en Subject) y SigninLogs tampoco (el suyo esta en ResultDescription y AppDisplayName). Sobre el sample salen 3 de 12 eventos con message='': idx 0 (EmailEvents), idx 6 y 7 (SigninLogs). Los otros 9 se salvan solo porque las tablas Device* si traen ActionType.

**Deberia:** Cada handler debe componer su propio mensaje con los campos de su tabla: para EmailEvents el Subject (mas DeliveryAction/ThreatTypes), para SigninLogs ResultDescription y AppDisplayName. Ampliar la lista de _base con 'Subject','ResultDescription','AppDisplayName' ya cerraria los tres casos del sample.

**Lo que se le escapa al analista:** Son justo los tres eventos que cuentan la entrada y el robo de la cuenta: el correo de phishing con el asunto 'Factura pendiente 2026-0819 - accion requerida', el login correcto de jlopez desde 45.132.88.17 y el fallido de mgarcia desde la misma IP. En el inspector del grafo el nodo no dice nada, y el motivo del fallo ('Invalid username or password') se pierde aunque venia en el registro. La busqueda libre de query.py prueba event.message primero y solo lo encuentra si acaba serializando el raw entero.

### EmailEvents siempre sale con activity 'deliver', aunque Defender bloqueara el correo

`glamdring/normalize/sentinel_defender.py:248`

**Sale hoy:** _email fija activity='deliver' en la llamada a _base y no la vuelve a tocar. Con DeliveryAction='Blocked' y ThreatTypes='Phish' el status si pasa a 'failure', pero activity sigue siendo 'deliver' y la severidad se sube a 4 igual que si hubiera llegado. Junked y Replaced ni siquiera cambian el status: salen 'deliver'/'success'/sev 4. La frase del informe es identica en los cuatro casos: 'a@b.c envio un correo a jlopez@corp.com con el asunto ...'.

**Deberia:** activity tiene que salir de DeliveryAction: Delivered -> 'deliver', Blocked -> 'blocked', Junked -> 'quarantine', Replaced -> 'quarantine'. Y la severidad debe bajar cuando el correo no llego al buzon: un phishing bloqueado no es el mismo hecho que uno entregado, que es justo lo que dice el comentario de las lineas 249-250.

**Lo que se le escapa al analista:** El evento 'deliver' del sample (idx 0) esta bien porque DeliveryAction='Delivered', pero la etiqueta no distingue el caso entregado del bloqueado. En una bandeja real la mayoria de los phishing salen Blocked o Junked, y todos apareceran en el grafo como correos entregados con severidad 4: el analista abre un incidente de phishing entregado por cada correo que el filtro ya paro.

### matches() rechaza las filas de EmailEvents sin 'Type', asi que la rama de EmailEvents de _guess_table es codigo muerto y el phishing se va al generico

`glamdring/normalize/sentinel_defender.py:59`

**Sale hoy:** matches() exige que el registro traiga al menos 2 de _MS_MARKERS (TimeGenerated, DeviceName, AlertName, UserPrincipalName, InitiatingProcessFileName, ReportId, DeviceId). Una fila de EmailEvents solo trae TimeGenerated: 1 marcador. Con la fila real del sample sin 'Type', matches()=False aunque _guess_table(r) devuelve 'EmailEvents' y sd.normalize(r) sabria producir 'Email Activity'. El pipeline real acaba en el generico: source='generic', class='Detection Finding', activity='alert'.

**Deberia:** Los marcadores tienen que incluir campos propios de las tablas de correo (NetworkMessageId, SenderFromAddress, RecipientEmailAddress, InternetMessageId) o bien matches() debe aceptar el registro cuando _guess_table sepa clasificarlo. Hoy matches() y _guess_table se contradicen: uno reclama menos de lo que el otro sabe traducir.

**Lo que se le escapa al analista:** Un export de Advanced Hunting de EmailEvents (la consulta mas comun cuando se investiga una campana de phishing) no lleva DeviceName ni DeviceId. Si el conector no inyecta 'Type', ningun correo se normaliza como correo: no hay nodo de remitente, ni de buzon, ni de dominio de la URL, y el paso 1 de la cadena de ataque desaparece del grafo.


## Gravedad baja

### event.message se queda con el 'name' del CEF y tira el 'msg', que es donde esta la informacion util

`glamdring/normalize/cef.py:283`

**Sale hoy:** first(record,'name','message','_raw') coge siempre el campo name del cabecero CEF. Linea 7: event.message='Malware Detected' mientras msg='Herramienta de volcado de credenciales detectada y no contenida'. Igual en toda la muestra: linea 5 guarda 'Traffic Allowed' y descarta 'Transferencia saliente inusualmente grande'; linea 2 guarda 'Web Request Allowed' y descarta 'Descarga de ejecutable desde dominio recien registrado'.

**Deberia:** Conservar los dos, p.ej. name + ': ' + msg, o preferir msg cuando existe y difiere de name. El texto del fabricante es lo que el analista lee en el inspector del nodo y es la unica pista de 'no contenida' o 'inusualmente grande'.

**Lo que se le escapa al analista:** El detalle que distingue una deteccion contenida de una NO contenida se queda solo en raw. En el inspector del nodo el analista lee la etiqueta generica del fabricante en lugar del hecho concreto.

### SecurityIncident se etiqueta con origin 'SecurityAlert': en el grafo un incidente y una alerta son indistinguibles

`glamdring/normalize/sentinel_defender.py:280`

**Sale hoy:** _alert llama a _base con la cadena literal 'SecurityAlert' como tabla, ignorando el Type real del registro. La fila 11 del sample entra con Type='SecurityIncident' y sale con event.origin='SecurityAlert'. extract._finding pasa ese origin al nodo de alerta (origin=event.origin, linea 348 de extract.py), asi que la etiqueta llega tal cual al grafo.

**Deberia:** _base(record, table, ...) debe recibir el Type real del registro, igual que hacen _device_process y los demas handlers con su propia tabla. Basta pasar el valor que ya calculo normalize().

**Lo que se le escapa al analista:** En Sentinel un incidente es el contenedor correlado de varias alertas y es lo que se asigna a un analista; una alerta suelta es una deteccion mas. Al mostrarse los dos como 'SecurityAlert', el analista ve tres nodos de alerta al mismo nivel y no distingue cual es el incidente que agrupa a los otros dos, ni puede filtrar por procedencia para separar detecciones de casos abiertos.

### LogonType 'CachedRemoteInteractive' (RDP con credenciales en cache) no cuenta como logon remoto y se queda sin T1021.001

`glamdring/normalize/sentinel_defender.py:222`

**Sale hoy:** La condicion es logon_type in ('network','remoteinteractive'). Con LogonType='CachedRemoteInteractive' el evento sale activity='logon', mitre=[] y is_key_event()=False, mientras que con 'RemoteInteractive' sale activity='logon_remote' con T1021.001 y entra en la cronologia.

**Deberia:** CachedRemoteInteractive es el tipo 12 de Windows: una sesion RDP autenticada con credenciales cacheadas. Es tan remota como RemoteInteractive y merece la misma activity y la misma tecnica. Igual pasa con CachedInteractive respecto de Interactive. La comprobacion deberia normalizar el prefijo 'Cached' antes de comparar.

**Lo que se le escapa al analista:** Un salto RDP hecho con credenciales cacheadas (lo normal cuando el atacante ya volco LSASS y el DC no esta accesible para revalidar) se ve igual que alguien sentado en la consola del servidor. No genera la frase de movimiento lateral, no lleva T1021.001 y no sale en la cronologia del informe.

### ActionType 'LogonAttempted' se cuenta como logon fallido con severidad 3

`glamdring/normalize/sentinel_defender.py:209`

**Sale hoy:** success = 'success' in action or action == 'logonsuccess'. 'LogonAttempted' no cumple ninguna de las dos, asi que cae en la rama de fallo: activity='logon_failed', status='failure', sev=3, igual que un LogonFailed real.

**Deberia:** LogonAttempted es uno de los tres ActionType de DeviceLogonEvents y significa intento cuyo resultado Defender no resolvio: es desconocido, no fallido. Deberia salir con status='unknown' y activity='logon', o mantenerse aparte, sin la severidad 3 ni el peso de un fallo.

**Lo que se le escapa al analista:** Infla la cuenta de autenticaciones fallidas con eventos que no lo son. narrative.is_key_event() mete todo lo que tiene status='failure' en la cronologia, asi que el informe se llena de 'Fallo un intento de autenticacion' y el analista persigue una fuerza bruta que no ocurrio, o al reves: se acostumbra al ruido y descarta los fallos de verdad.

### INVENTARIO PEDIDO (no es un hallazgo nuevo): recorrido linea a linea de samples/perimeter.cef, 11 lineas

`samples/perimeter.cef:1`

**Sale hoy:** L1 Fortinet 13 'Traffic Allowed' (act=accept) -> connect / Network, sev 3. || L2 Zscaler 200 'Web Request Allowed' (request=https://cdn-update-svc.com/upd.exe) -> connect / Network, sev 3, con domain y url correctos. || L3 Zscaler 201 'Web Request Blocked' -> blocked / Network, sev 4. || L4 Fortinet 13 'Traffic Denied' (act=deny) -> blocked / Network, sev 3. || L5 Fortinet 13 'Traffic Allowed' (734 MB salientes) -> connect / Network, sev 4. || L6 Umbrella 500 'DNS Request' -> create / File System Activity, sev 3, 0 aristas. || L7 Defender 1001 'Malware Detected' (quarantine_failed) -> create / File System Activity, sev 5, arista jlopez 'wrote' m.exe. || L8 LEEF PAN-OS 'threat' (cat=command-and-control, sev=8) -> launch / Process Activity, sev 2, status success, 0 aristas. || L9 syslog sshd 'Failed password for invalid user administrator' -> logon_failed / Authentication, sev 3, sin usuario ni IP. || L10 igual con svc_backup -> logon_failed, sin usuario ni IP. || L11 syslog sshd 'Accepted password for jlopez' -> logon / Authentication, sev 2, sin usuario ni IP, fuera de la cronologia.

**Deberia:** L1 connect (CORRECTA). L2 connect (CORRECTA; lo unico perdido es el matiz de descarga de ejecutable). L3 blocked (CORRECTA). L4 blocked (CORRECTA). L5 connect (CORRECTA; se pierde el volumen cn1=734003200, que es lo que la hace sospechosa). L6 deberia ser consulta DNS (CLASS_DNS/'query') con domain=cdn-update-svc.com, NO 'create'. L7 deberia ser deteccion/alerta con contencion fallida, NO 'create' atribuido a jlopez. L8 deberia ser red ('connect', o alerta de C2) con severidad 4, NO 'launch'. L9 y L10: 'logon_failed' es CORRECTA, pero deben llevar actor=administrator/svc_backup y src=10.4.2.11. L11 deberia ser 'logon_remote' con actor=jlopez y src=10.4.2.11. Resumen: 5 de 11 con activity correcta y completa, 3 con activity directamente equivocada (L6, L7, L8) y 3 con activity razonable pero sin las entidades (L9, L10, L11).

**Lo que se le escapa al analista:** La cronologia completa que hoy produce el informe con este fichero son 5 lineas: dos bloqueos hacia Tor, un 'fallo de autenticacion de un usuario desconocido' (que en realidad son dos cuentas distintas fundidas en count=2), la conexion saliente de srv-dc01 y 'jlopez creo m.exe'. No aparecen ni el C2, ni la resolucion DNS del dominio malicioso, ni el login SSH correcto. Las tres sospechas del repaso anterior se sostienen: ninguna se cae.
