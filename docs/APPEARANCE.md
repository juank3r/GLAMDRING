# Panel de administrador

Todo lo que se toca en el panel vive en **`config/appearance.json`**, en el
servidor. Un único perfil para todo el equipo: el sysadmin fija el estándar y
todos ven lo mismo, de modo que una captura en un informe significa lo mismo
para quien la envía y para quien la recibe.

Los controles **no están escritos a mano**. Se generan a partir del `spec` que
manda el servidor (`GET /api/appearance`), con el tipo y el rango real de cada
campo. Añadir un ajuste es tocar
[`glamdring/appearance.py`](../glamdring/appearance.py) y aparece solo en el
panel, con sus límites correctos y sin que el rango del slider pueda
desincronizarse del validador.

```
┌──────────────┐   GET /api/appearance    ┌────────────────┐
│ admin.js     │◀─────────────────────────│ appearance.py  │
│ (genera UI)  │   PUT /api/appearance    │ (valida+guarda)│
└──────────────┘─────────────────────────▶└────────────────┘
                                                   │
                                          config/appearance.json
```

Todo lo que entra se sanea clave a clave: lo desconocido se descarta, lo fuera de
rango se recorta y lo que no es del tipo esperado se ignora. La respuesta incluye
`rejected` con lo que no pasó el filtro, así que si mandas diez ajustes y uno está
mal, se aplican nueve y se te dice cuál falló en lugar de perder los diez.

---

## Mapa: control → accesor de la librería

Esta es la tabla que hay que mirar cuando algo no hace lo que se espera.

### Tema

Estos valores se vuelcan a variables CSS y afectan a **toda** la interfaz, no
solo al grafo.

| Control | Variable CSS |
|---|---|
| `background` | `--bg` (y el color de la niebla del grafo) |
| `panel` / `panelAlt` | `--bg-panel` / `--bg-panel-alt` |
| `border` | `--border` |
| `text` / `textDim` | `--text` / `--text-dim` |
| `accent` | `--accent` |
| `fontScale` | `--font-scale` |
| `preset` | reescribe la paleta entera de golpe |

Preajustes: **SOC oscuro** (por defecto), **Matrix**, **Alto contraste** y
**Claro (informes)**, este último pensado para capturas que van a acabar en papel.

### Render

| Control | Qué llama |
|---|---|
| `modelQuality` | elige entre figura completa / geometría simple / icono sprite |
| `nodeResolution` · `linkResolution` | `.nodeResolution()` · `.linkResolution()` |
| `nodeOpacity` · `linkOpacity` | `.nodeOpacity()` · `.linkOpacity()` |
| `bloom*` | `postProcessingComposer().addPass(new UnrealBloomPass())` |
| `fog` · `fogDensity` | `scene().fog = new THREE.FogExp2(...)` |
| `grid` | `scene().add(new THREE.GridHelper(...))` |
| `enablePointerInteraction` | `.enablePointerInteraction()` — apagarlo acelera mucho |
| `linkHoverPrecision` | `.linkHoverPrecision()` |
| `showNavInfo` | `.showNavInfo()` |
| `heavyThreshold` | por encima de ese número de nodos se degrada la calidad sola |

### Física

| Control | Qué llama |
|---|---|
| `forceEngine` | `.forceEngine('d3' \| 'ngraph')` |
| `numDimensions` | `.numDimensions(1\|2\|3)` — a 2 el grafo se aplana |
| `chargeStrength` | `d3Force('charge').strength()` |
| `linkDistance` | `d3Force('link').distance()`, modulado por el peso de cada relación |
| `collide` · `collideRadius` | `d3Force('collide', forceCollide(...))`, implementación propia |
| `d3AlphaDecay` · `d3VelocityDecay` | homónimos |
| `warmupTicks` · `cooldownTicks` | homónimos |
| `dagMode` · `dagLevelDistance` | `.dagMode()` · `.dagLevelDistance()` |
| `layerSpacing` | separación de capas cuando la kill-chain va por `fx` fijado |

> **`forceCollide` es propio**, no el de d3. El bundle UMD no expone
> `d3-force-3d`, y vendorizar la librería entera por una función no compensa.
> Está en [`web/js/render/forces.js`](../web/js/render/forces.js), con rejilla
> espacial para no hacer O(n²) por fotograma.

> **Dos caminos para la kill-chain.** Por defecto se fija `node.fx` a la capa
> MITRE: nunca falla. Poniendo `dagMode` se deja conducir a la librería, que es
> más vistoso pero exige un grafo acíclico; `onDagError(() => false)` silencia el
> error cuando hay ciclos, que en un incidente real es lo normal.

### Etiquetas

| Control | Efecto |
|---|---|
| `nodeMode` | `never` · `hover` · `selection` · `smart` · `always` |
| `nodeRiskThreshold` | en modo `smart`, a partir de qué riesgo se rotula |
| `linkMode` | `never` · `hover` · `selection` · `busy` · `always` |
| `linkBusyThreshold` | en modo `busy`, a partir de cuántos eventos |
| `renderer` | `sprite` (SpriteText) o `css2d` (CSS2DRenderer, HTML real) |

**Ojo con `renderer`**: `extraRenderers` es una opción *de construcción*.
Cambiarla obliga a levantar una instancia nueva del grafo; se hace solo,
conservando datos, cámara y selección, pero se nota un parpadeo.

Modo `smart`: si hay selección, rotula la selección; si hay menos de 60 nodos,
rotula todo; si no, solo lo que supere el umbral de riesgo. Es el único modo que
no se vuelve ilegible al crecer el grafo.

### Aristas

| Control | Qué llama |
|---|---|
| `particles` · `particleDensity` | `.linkDirectionalParticles()`, proporcional al `log10` del volumen |
| `particleSpeed` · `particleWidth` | homónimos |
| `arrows` · `arrowLength` | `.linkDirectionalArrowLength()` |
| `gradient` | línea con `vertexColors`: hereda el color de los dos extremos |
| `dashed` | trazo discontinuo en las relaciones marcadas como inferidas |
| `curvature` | abanico para separar multiaristas entre el mismo par |
| `widthScale` | multiplica el grosor, que es logarítmico sobre el volumen |

### Cámara

| Control | Qué llama |
|---|---|
| `controlType` | `trackball` · `orbit` · `fly` — **opción de construcción** |
| `autoOrbit` · `orbitSpeed` | `cameraPosition()` con seno/coseno en un intervalo |
| `focusDistance` | distancia al enfocar un nodo |
| `transitionMs` | duración de la animación de cámara |

### Interacción

`dimOnSelect`, `dimOpacity`, `hoverHighlight`, `fixOnDrag` y
`expandOnDoubleClick`. Todos hacen lo que dicen.

### Ontología

Por entidad: **color**, **figura 3D**, **escala** y **visible**.
Por relación: **color**, **trazo discontinuo** y **visible**.

Estas sustituciones se aplican **encima** de la ontología del servidor, así que
si mañana se añade un tipo nuevo en `graph/ontology.py`, aparece sin tocar el
perfil.

### Reglas

Los pesos de la puntuación de riesgo. Importan más de lo que parece: el riesgo
decide el orden de la tabla del informe, el tamaño de cada figura en el grafo y
qué nodos sobreviven al recorte cuando hay demasiados. La fórmula está en
[`glamdring/graph/enrich.py`](../glamdring/graph/enrich.py) y se documenta en
[ARCHITECTURE.md](ARCHITECTURE.md).

Se aplican al recargar el grafo, no al instante.

### Perfil

Exportar e importar el JSON, restablecer de fábrica y subir modelos `.glb`.

**Restablecer borra el fichero** en lugar de escribir los valores por defecto: así,
si una versión futura cambia esos valores, el equipo se beneficia sin tener que
volver a pulsar el botón.

---

## Modelos 3D propios

Cualquier figura procedural se puede sustituir por un `.glb`:

```
POST   /api/appearance/model/{figura}    (multipart, campo 'file')
DELETE /api/appearance/model/{figura}
```

Figuras sustituibles: `workstation`, `server`, `router`, `firewall`, `person`,
`attacker`, `gear`, `document`, `alert`, `globe`, `envelope`, `cloud`, `key`,
`hashcube`, `endpoint`.

Se comprueba la **cabecera** del fichero (`glTF`) y no solo la extensión: lo que
se sube acaba sirviéndose como estático y lo carga el navegador de todo el
equipo. Máximo 25 MB.

El modelo se escala solo a la caja de una figura procedural. Sin esa
normalización, cualquier `.glb` descargado sale a una escala arbitraria y
descuadra el grafo entero. Se cargan de forma diferida: mientras llega el
fichero se ve la figura procedural, y al terminar se refresca.

---

## Modos de color

Ortogonales al perfil, se cambian desde la barra superior o con `c`. El grafo es
el mismo; lo que cambia es qué dimensión se lleva el color, porque "¿qué tipo de
cosa es esto?" y "¿quién es el atacante?" son preguntas distintas.

| Modo | Qué colorea |
|---|---|
| Tipo de entidad | usuario, host, proceso… (por defecto) |
| Papel en el incidente | hostil, víctima, sospechosa, activo sano, contexto |
| Severidad | la escala 0-5 |
| Riesgo | rampa continua verde → rojo |
| Origen del dato | qué SIEM lo vio |
| Táctica MITRE | posición en la cadena de ataque |
| Comunidad | clústeres detectados por propagación de etiquetas |

La severidad sigue leyéndose siempre a través de las pantallas, los pilotos y los
halos de las figuras, se esté en el modo que se esté.

---

## Ejemplos

**Un despliegue con equipos modestos** (portátiles sin GPU decente):

```json
{
  "render": { "bloom": false, "fog": false, "modelQuality": "medium",
              "nodeResolution": 8, "heavyThreshold": 150 },
  "links":  { "particles": false },
  "physics": { "collide": false, "cooldownTicks": 120 }
}
```

**Modo escaparate** para una pantalla del SOC:

```json
{
  "camera": { "autoOrbit": true, "orbitSpeed": 0.6 },
  "labels": { "nodeMode": "smart", "nodeRiskThreshold": 70 },
  "render": { "bloom": true, "bloomStrength": 1.4, "showNavInfo": false }
}
```

**Capturas para informes impresos:**

```json
{
  "theme":  { "preset": "paper" },
  "render": { "bloom": false, "fog": false, "grid": false },
  "labels": { "nodeMode": "always", "renderer": "css2d" }
}
```
