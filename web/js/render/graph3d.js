/* GLAMDRING :: graph3d.js — el lienzo.
 *
 * Una sola instancia de ForceGraph3D sirve las tres disposiciones. No se
 * reconstruye el grafo al cambiar de vista: solo cambia cómo se fijan las
 * posiciones.
 *
 *   explore     simulación libre; los clústeres emergen solos
 *   killchain   fx = capa MITRE, de acceso inicial a impacto
 *   timeline3d  fx = instante del primer avistamiento
 *
 * Hay DOS caminos para la kill-chain y ambos están disponibles desde el panel:
 * fijar `fx` (por defecto, nunca falla) o el `dagMode` de la librería, que es
 * más vistoso pero exige un grafo acíclico. `onDagError(() => false)` silencia
 * el error cuando hay ciclos, que en un incidente real es lo normal.
 *
 * Sobre reconstruir: `controlType`, `extraRenderers` y `rendererConfig` son
 * opciones DE CONSTRUCCIÓN, no setters. Cambiarlas desde el panel obliga a
 * destruir la instancia y levantar otra conservando datos, cámara y selección;
 * de ahí que todo el estado viva fuera del objeto de la librería.
 */

import * as THREE from 'three';
import SpriteText from '../vendor/three-spritetext.mjs';
import { CSS2DObject, CSS2DRenderer } from 'three/addons/renderers/CSS2DRenderer.js';
import { UnrealBloomPass } from 'three/addons/postprocessing/UnrealBloomPass.js';
import { GLTFLoader } from 'three/addons/loaders/GLTFLoader.js';

import * as ont from '../ontology.js';
import { accentColor, hexToRgba, isAlarmed, nodeColor } from './colors.js';
import { forceCollide } from './forces.js';
import * as links from './links.js';
import { buildModel, disposeCaches } from './models.js';
import * as orient from './orient.js';

const TIME_SPAN = 900;

/* Estado que sobrevive a una reconstrucción de la instancia. */
let container = null;
let handlers = {};
let profile = null;
let graph = null;

let data = { nodes: [], links: [], meta: {} };
let adjacency = {};
let view = 'explore';
let colorMode = 'type';
let timeCursor = null;
let heavy = false;

const selection = { node: null, link: null, multi: new Set() };
const highlight = { nodes: new Set(), links: new Set(), hoverNode: null, hoverLink: null };

let sceneExtras = [];
let bloomPass = null;
let orbitTimer = null;
let orbitAngle = 0;
const glbCache = new Map();
const loader = new GLTFLoader();

/* Figuras con frente, segun la ontologia del servidor. Se refresca en cada
   decorate() porque la ontologia llega por HTTP despues de construir el grafo:
   leerla una sola vez al cargar el modulo daria siempre el juego de reserva. */
let facing = new Set();

/* ------------------------------------------------------------------ ayudas */

const idOf = (endpoint) => (endpoint && typeof endpoint === 'object' ? endpoint.id : endpoint);

const msOf = (value) => {
  if (!value) return null;
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? null : parsed;
};

const opt = (section, key, fallback) => {
  const bucket = profile && profile[section];
  const value = bucket ? bucket[key] : undefined;
  return value === undefined ? fallback : value;
};

function visibleAt(item) {
  if (timeCursor === null) return true;
  return item.__gdFirst === null || item.__gdFirst <= timeCursor;
}

function isDimmedNode(node) {
  if (!opt('interaction', 'dimOnSelect', true)) return false;
  if (!highlight.nodes.size) return false;
  return !highlight.nodes.has(node);
}

function isDimmedLink(link) {
  if (!opt('interaction', 'dimOnSelect', true)) return false;
  if (!highlight.nodes.size) return false;
  return !highlight.links.has(link);
}

function radiusOf(node) {
  const meta = ont.entity(node.type);
  const base = (meta.size || 5) * (meta.scale || 1);
  // Raíz cuadrada y no lineal: un nodo de riesgo 100 en escala lineal sería una
  // bola que taparía media escena.
  const risk = Math.max(0, Math.min(100, node.risk || 0));
  return base * (0.75 + Math.sqrt(risk / 100) * 0.85);
}

function labelText(node) {
  return node.label || node.id;
}

function shouldLabelNode(node) {
  const mode = opt('labels', 'nodeMode', 'smart');
  switch (mode) {
    case 'never': return false;
    case 'always': return true;
    case 'hover': return highlight.hoverNode === node;
    case 'selection': return highlight.nodes.has(node);
    case 'smart':
    default:
      if (highlight.nodes.size) return highlight.nodes.has(node);
      if (data.nodes.length < 60) return true;
      return (node.risk || 0) >= opt('labels', 'nodeRiskThreshold', 45);
  }
}

/* ------------------------------------------------------------- figuras 3D */

function modelUrlFor(node) {
  const models = (profile && profile.models) || {};
  const modelName = (node.props && node.props.model) || ont.entity(node.type).model;
  return models[node.type] || models[modelName] || null;
}

/* Carga diferida de un .glb subido por el sysadmin. Mientras llega se muestra la
   figura procedural, y cuando el modelo está listo se refresca: así el grafo no
   se queda en blanco esperando a la red. */
function loadGlb(url, onReady) {
  if (glbCache.has(url)) {
    const cached = glbCache.get(url);
    return cached === 'pending' ? null : cached;
  }
  glbCache.set(url, 'pending');
  loader.load(
    url,
    (gltf) => {
      const model = gltf.scene;
      // Se normaliza al tamaño de una figura procedural; si no, cualquier modelo
      // descargado sale a una escala arbitraria y descuadra todo el grafo.
      const box = new THREE.Box3().setFromObject(model);
      const size = new THREE.Vector3();
      box.getSize(size);
      const largest = Math.max(size.x, size.y, size.z) || 1;
      model.scale.setScalar(2 / largest);
      const center = new THREE.Vector3();
      box.getCenter(center);
      model.position.sub(center.multiplyScalar(2 / largest));
      glbCache.set(url, model);
      if (onReady) onReady();
    },
    undefined,
    () => {
      glbCache.set(url, null);   // que falle un modelo no puede romper el grafo
    },
  );
  return null;
}

function qualityFor() {
  const configured = opt('render', 'modelQuality', 'auto');
  if (configured !== 'auto') return configured;
  if (data.nodes.length > opt('render', 'heavyThreshold', 350)) return 'low';
  if (data.nodes.length > 140) return 'medium';
  return 'high';
}

/* Atenua o restaura un nodo YA construido, sin tocar su geometria.
   Es lo que permite que resaltar al pasar el raton cueste microsegundos en vez
   de reconstruir la escena entera. */
function applyNodeDim(group, dimmed) {
  const list = group.userData.gdMaterials;
  if (!list) return;
  const dim = Math.max(0.04, opt('interaction', 'dimOpacity', 0.07));
  for (let i = 0; i < list.length; i += 1) {
    const entry = list[i];
    if (dimmed) {
      entry.material.transparent = true;
      entry.material.opacity = dim;
    } else {
      entry.material.transparent = entry.transparent;
      entry.material.opacity = entry.opacity;
    }
  }
}

/* Pone la etiqueta al dia sin reconstruir el nodo.

   Las tres modalidades utiles ('hover', 'selection' y la de por defecto,
   'smart') dependen de que este resaltado en ese momento, asi que mover el
   raton cambia que nodos llevan rotulo. Crearla la primera vez que hace falta y
   a partir de ahi solo esconderla evita tener que rehacer el objeto entero, y
   evita tambien fabricar mil texturas de texto que nadie va a mirar. */
function applyNodeLabel(group, node) {
  const wants = shouldLabelNode(node);
  let label = group.userData.gdLabel;
  if (wants && !label) {
    label = buildLabel(node, radiusOf(node));
    group.userData.gdLabel = label;
    group.add(label);
  }
  if (label) label.visible = wants;
}

/* Recalcula atenuado y etiquetas de TODOS los nodos a partir del resaltado
   actual. Sustituye a refresh() en hover y seleccion. */
export function applyHighlight() {
  const nodes = data.nodes || [];
  for (let i = 0; i < nodes.length; i += 1) {
    const node = nodes[i];
    const group = node.__threeObj;
    if (!group) continue;
    applyNodeDim(group, isDimmedNode(node));
    applyNodeLabel(group, node);
  }
  links.applyHighlight(data.links || [], isDimmedLink, linkOptions());
}

function buildNodeObject(node) {
  const group = new THREE.Group();
  const radius = radiusOf(node);
  const url = modelUrlFor(node);
  const model = (node.props && node.props.model) || ont.entity(node.type).model;

  let figure = null;
  if (url) {
    const glb = loadGlb(url, () => refresh());
    if (glb) {
      figure = glb.clone(true);
      figure.scale.multiplyScalar(radius / 1.15);
    }
  }
  if (!figure) {
    figure = buildModel({
      model,
      shape: ont.entity(node.type).shape,
      glyph: ont.entity(node.type).glyph,
      radius,
      color: nodeColor(node, colorMode),
      severityColor: accentColor(node),
      alarm: isAlarmed(node),
      quality: qualityFor(),
      scale: ont.entity(node.type).scale || 1,
    });
  }
  group.add(figure);

  // Los materiales vienen compartidos desde models.js (hay una cache por color
  // y emisivo), asi que tocarlos directamente atenuaria de golpe a todos los
  // nodos que usen ese mismo color. Se clonan UNA vez aqui, al construir, y se
  // guardan para poder cambiarles la opacidad sin reconstruir nada.
  //
  // Antes esto se hacia al reves: el atenuado se cocinaba dentro de la figura y
  // cambiar el resaltado obligaba a llamar a refresh(), que tira TODOS los
  // objetos 3D y los vuelve a construir. Con 228 nodos eso bloqueaba el hilo
  // 138 ms; con los 1500 del tope, casi un segundo. Y pasaba cada vez que el
  // raton rozaba un nodo.
  const materials = [];
  group.traverse((child) => {
    if (!child.material) return;
    const clone = child.material.clone();
    child.material = clone;
    materials.push({ material: clone, opacity: clone.opacity, transparent: clone.transparent });
  });
  group.userData.gdMaterials = materials;
  applyNodeDim(group, isDimmedNode(node));

  if (shouldLabelNode(node)) {
    const label = buildLabel(node, radius);
    group.userData.gdLabel = label;
    group.add(label);
  }
  group.userData.nodeId = node.id;
  // orient.js gira SOLO la figura, nunca el grupo: la etiqueta cuelga del grupo
  // y en modo billboard saldria orbitando alrededor del nodo.
  group.userData.gdFigure = figure;
  // Un .glb subido por el sysadmin puede venir orientado de cualquier manera, y
  // girarlo hacia la camara empeoraria las cosas en vez de arreglarlas. Solo se
  // giran las figuras procedurales, que sabemos como estan construidas.
  group.userData.gdFaces = !url && facing.has(model);
  return group;
}

function buildLabel(node, radius) {
  const size = opt('labels', 'nodeSize', 1);
  if (opt('labels', 'renderer', 'sprite') === 'css2d') {
    // CSS2D da texto nítido a cualquier distancia y permite estilarlo con la
    // misma hoja de estilos que el resto de la interfaz.
    const element = document.createElement('div');
    element.className = 'node-label';
    element.textContent = labelText(node);
    element.style.color = nodeColor(node, colorMode);
    const object = new CSS2DObject(element);
    object.position.set(0, radius * 1.9, 0);
    return object;
  }
  const sprite = new SpriteText(labelText(node));
  sprite.color = '#dce4f0';
  sprite.textHeight = Math.max(2.4, radius * 0.55) * size;
  sprite.backgroundColor = 'rgba(7,10,16,0.6)';
  sprite.padding = 0.6;
  sprite.borderRadius = 1;
  sprite.material.depthWrite = false;
  sprite.position.set(0, radius * 1.9, 0);
  return sprite;
}

/* --------------------------------------------------------------- aristas */

function linkContext() {
  return {
    selectedLink: selection.link,
    hoveredLink: highlight.hoverLink,
    highlightedLinks: highlight.links,
    busyThreshold: opt('labels', 'linkBusyThreshold', 5),
    dimOpacity: opt('interaction', 'dimOpacity', 0.07),
    isDimmed: isDimmedLink,
    heavy,
  };
}

function linkOptions() {
  return (profile && profile.links) || {};
}

function buildLinkObject(link) {
  const context = linkContext();
  const mode = opt('labels', 'linkMode', 'hover');
  const wantsText = links.shouldLabel(link, mode, context);
  const wantsDash = linkOptions().dashed && ont.relation(link.type).dashed;

  // linkThreeObject sustituye a la línea salvo con linkThreeObjectExtend(true).
  // Se devuelve un grupo para poder combinar trazo propio y texto sin pelearse.
  const group = new THREE.Group();
  if (wantsDash) {
    const dashed = links.dashedLine(link);
    dashed.userData.role = 'dash';
    group.add(dashed);
  }
  if (wantsText) {
    const label = links.linkLabel(link, { size: opt('labels', 'linkSize', 1) });
    label.userData.role = 'label';
    group.add(label);
  }
  group.userData.hasDash = wantsDash;
  // Referencia propia para poder atenuar la arista sin reconstruirla. La
  // libreria guarda su linea en `__lineObj`, pero lo que devuelve
  // linkThreeObject no queda accesible con un nombre estable.
  link.__gdObj = group;
  return group;
}

function positionLinkObject(object, coords) {
  if (!object || !object.children) return;
  object.children.forEach((child) => {
    if (child.userData.role === 'dash') links.positionDashed(child, coords);
    else links.positionLabel(child, coords);
  });
}

/* ------------------------------------------------------------- escenario */

function clearExtras() {
  if (graph) sceneExtras.forEach((item) => graph.scene().remove(item));
  sceneExtras = [];
}

function addLayerLabels() {
  if (view !== 'killchain') return;
  const spacing = opt('physics', 'layerSpacing', 130);
  const byLevel = new Map();
  let maxLevel = 0;

  data.nodes.forEach((node) => {
    const level = node.__gdLevel;
    maxLevel = Math.max(maxLevel, level);
    if (!byLevel.has(level)) byLevel.set(level, new Map());
    (node.tactics || []).forEach((tactic) => {
      const counts = byLevel.get(level);
      counts.set(tactic, (counts.get(tactic) || 0) + 1);
    });
  });

  const offset = (maxLevel * spacing) / 2;
  for (let level = 0; level <= maxLevel; level++) {
    const counts = byLevel.get(level) || new Map();
    const best = [...counts.entries()].sort((a, b) => b[1] - a[1])[0];
    const text = best ? ont.tacticLabel(best[0]) : `capa ${level + 1}`;
    const label = new SpriteText(text.toUpperCase());
    label.color = '#5b6880';
    label.textHeight = 6;
    label.material.depthWrite = false;
    label.position.set(level * spacing - offset, 150, 0);
    graph.scene().add(label);
    sceneExtras.push(label);
  }
}

/* Rejilla de suelo: sin una referencia fija, en 3D se pierde la noción de dónde
   se está, sobre todo en la kill-chain donde el eje X significa algo. */
function addGrid() {
  if (!opt('render', 'grid', true)) return;
  const size = view === 'killchain' ? 1400 : 900;
  const grid = new THREE.GridHelper(size, view === 'killchain' ? 28 : 18,
                                    0x223046, 0x151d2b);
  grid.position.y = -220;
  grid.material.transparent = true;
  grid.material.opacity = 0.35;
  graph.scene().add(grid);
  sceneExtras.push(grid);
}

function applyFog() {
  const scene = graph.scene();
  if (opt('render', 'fog', true)) {
    scene.fog = new THREE.FogExp2(
      new THREE.Color(opt('theme', 'background', '#070a10')).getHex(),
      opt('render', 'fogDensity', 0.0016),
    );
  } else {
    scene.fog = null;
  }
}

function applyBloom() {
  const composer = graph.postProcessingComposer();
  if (!composer) return;

  if (bloomPass) {
    composer.removePass(bloomPass);
    bloomPass.dispose?.();
    bloomPass = null;
  }
  if (!opt('render', 'bloom', true)) return;

  // Mismo patrón que el ejemplo `bloom-effect` del repositorio oficial. Funciona
  // porque nuestra copia de three y la que empaqueta la librería son la MISMA
  // revisión (r168); con versiones distintas esto revienta con errores de shader.
  bloomPass = new UnrealBloomPass();
  bloomPass.strength = opt('render', 'bloomStrength', 0.9);
  bloomPass.radius = opt('render', 'bloomRadius', 0.55);
  bloomPass.threshold = opt('render', 'bloomThreshold', 0.62);
  composer.addPass(bloomPass);
}

/* -------------------------------------------------------------- posiciones */

function applyLayout() {
  clearExtras();
  addGrid();

  const dagMode = opt('physics', 'dagMode', '');
  if (dagMode && view === 'killchain') {
    // Camino alternativo: se deja conducir a la librería y se sueltan las
    // posiciones fijas para que no peleen entre sí.
    data.nodes.forEach((node) => { node.fx = undefined; });
    graph.dagMode(dagMode).dagLevelDistance(opt('physics', 'dagLevelDistance', 130));
  } else {
    graph.dagMode(null);
    if (view === 'explore') {
      data.nodes.forEach((node) => { node.fx = undefined; });
    } else if (view === 'killchain') {
      const spacing = opt('physics', 'layerSpacing', 130);
      const maxLevel = data.nodes.reduce((max, node) => Math.max(max, node.__gdLevel), 0);
      const offset = (maxLevel * spacing) / 2;
      data.nodes.forEach((node) => { node.fx = node.__gdLevel * spacing - offset; });
      addLayerLabels();
    } else if (view === 'timeline3d') {
      const span = (data.__gdTmax - data.__gdTmin) || 1;
      data.nodes.forEach((node) => {
        const ratio = node.__gdFirst === null ? 0 : (node.__gdFirst - data.__gdTmin) / span;
        node.fx = ratio * TIME_SPAN - TIME_SPAN / 2;
      });
    }
  }
  graph.d3ReheatSimulation();
}

/* -------------------------------------------------------------- accesores */

function wireAccessors() {
  const linkOpts = linkOptions();

  graph
    .nodeId('id')
    .nodeLabel(nodeTooltip)
    .nodeThreeObject(buildNodeObject)
    .nodeVisibility(visibleAt)
    .linkSource('source')
    .linkTarget('target')
    .linkVisibility(visibleAt)
    .linkColor((link) => links.colorOf(link, linkOpts, linkContext()))
    .linkWidth((link) => links.widthOf(link, linkOpts, linkContext()))
    .linkOpacity(opt('render', 'linkOpacity', 0.55))
    .linkCurvature((link) => link.__gdCurve || 0)
    .linkCurveRotation((link) => link.__gdCurveRot || 0)
    .linkThreeObject(buildLinkObject)
    .linkThreeObjectExtend(true)     // se conserva la línea bajo nuestro objeto
    .linkPositionUpdate(positionLinkObject)
    .linkDirectionalArrowLength((link) =>
      (linkOpts.arrows === false || isDimmedLink(link)) ? 0 : (linkOpts.arrowLength ?? 3.4))
    .linkDirectionalArrowRelPos(0.92)
    .linkDirectionalArrowColor((link) => ont.relation(link.type).color)
    .linkDirectionalParticles((link) => links.particlesOf(link, linkOpts, linkContext()))
    .linkDirectionalParticleWidth(linkOpts.particleWidth ?? 1.1)
    .linkDirectionalParticleSpeed((link) => links.particleSpeedOf(link, linkOpts))
    .linkDirectionalParticleColor((link) => ont.relation(link.type).color)
    .linkLabel(linkTooltip)
    .linkHoverPrecision(opt('render', 'linkHoverPrecision', 4))
    .enablePointerInteraction(opt('render', 'enablePointerInteraction', true))
    .showNavInfo(opt('render', 'showNavInfo', false))
    .onDagError(() => false)         // un ciclo no puede tumbar la vista
    .onNodeHover(onNodeHover)
    .onLinkHover(onLinkHover)
    .onNodeClick((node, event) => handlers.onNodeClick?.(node, event))
    .onNodeRightClick((node, event) => handlers.onNodeRightClick?.(node, event))
    .onLinkClick((link, event) => handlers.onLinkClick?.(link, event))
    .onBackgroundClick(() => handlers.onBackgroundClick?.())
    .onNodeDragEnd((node) => {
      if (opt('interaction', 'fixOnDrag', true)) {
        node.fx = node.x; node.fy = node.y; node.fz = node.z;
      }
    });
}

function applyPhysics() {
  graph
    .numDimensions(opt('physics', 'numDimensions', 3))
    .forceEngine(opt('physics', 'forceEngine', 'd3'))
    .d3AlphaDecay(opt('physics', 'd3AlphaDecay', 0.0228))
    .d3VelocityDecay(opt('physics', 'd3VelocityDecay', 0.32))
    .warmupTicks(opt('physics', 'warmupTicks', 40))
    .cooldownTicks(opt('physics', 'cooldownTicks', 320));

  const charge = graph.d3Force('charge');
  if (charge) charge.strength(opt('physics', 'chargeStrength', -170));

  const link = graph.d3Force('link');
  if (link) {
    const base = opt('physics', 'linkDistance', 42);
    link.distance((item) => base + (ont.relation(item.type).weight || 1) * 4);
  }

  if (opt('physics', 'collide', true)) {
    const factor = opt('physics', 'collideRadius', 1.15);
    graph.d3Force('collide', forceCollide((node) => radiusOf(node) * factor));
  } else {
    graph.d3Force('collide', null);
  }
}

function applyRenderSettings() {
  graph
    .backgroundColor('rgba(0,0,0,0)')
    .nodeResolution(heavy ? 6 : opt('render', 'nodeResolution', 12))
    .linkResolution(heavy ? 3 : opt('render', 'linkResolution', 6));
  applyFog();
  applyBloom();
}

/* ------------------------------------------------------------- tooltips */

function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function nodeTooltip(node) {
  const meta = ont.entity(node.type);
  const role = ont.role(node.props && node.props.role);
  const tactics = (node.tactics || []).map((t) => ont.tacticLabel(t)).join(', ');
  return `<div class="gd-tip">
    <div class="gd-tip-head" style="color:${meta.color}">${escapeHtml(meta.label)}</div>
    <div class="gd-tip-name">${escapeHtml(node.label)}</div>
    <div class="gd-tip-row"><span style="color:${role.color}">${escapeHtml(role.label)}</span>
      · riesgo <b>${node.risk || 0}</b> · ${node.eventCount || 0} eventos</div>
    ${tactics ? `<div class="gd-tip-row">${escapeHtml(tactics)}</div>` : ''}
  </div>`;
}

function linkTooltip(link) {
  const meta = ont.relation(link.type);
  return `<div class="gd-tip">
    <div class="gd-tip-head" style="color:${meta.color}">${escapeHtml(meta.label)}</div>
    <div class="gd-tip-row">${link.count || 1} evento(s)</div>
  </div>`;
}

/* ------------------------------------------------------------ resaltado */

function onNodeHover(node) {
  if (!opt('interaction', 'hoverHighlight', true)) return;
  if (highlight.hoverNode === node) return;
  highlight.hoverNode = node;
  highlight.hoverLink = null;

  if (!selection.node && !selection.link) {
    setHighlightFromNode(node);
    // applyHighlight() y no refresh(): refresh() tira TODOS los objetos 3D y
    // los reconstruye, que con 228 nodos son 138 ms de hilo bloqueado. Pasar el
    // raton por encima de un grafo denso era una sucesion de tirones.
    applyHighlight();
  }
  handlers.onNodeHover?.(node);
}

function onLinkHover(link) {
  if (!opt('interaction', 'hoverHighlight', true)) return;
  if (highlight.hoverLink === link) return;
  highlight.hoverLink = link;

  if (!selection.node && !selection.link) {
    highlight.nodes.clear();
    highlight.links.clear();
    if (link) {
      highlight.links.add(link);
      const from = data.nodes.find((n) => n.id === idOf(link.source));
      const to = data.nodes.find((n) => n.id === idOf(link.target));
      if (from) highlight.nodes.add(from);
      if (to) highlight.nodes.add(to);
    }
    applyHighlight();
  }
}

function setHighlightFromNode(node) {
  highlight.nodes.clear();
  highlight.links.clear();
  if (!node) return;
  highlight.nodes.add(node);
  (adjacency[node.id] || []).forEach(({ node: neighbor, link }) => {
    highlight.nodes.add(neighbor);
    highlight.links.add(link);
  });
}

/* ------------------------------------------------------------ preparación */

function decorate(doc) {
  facing = ont.facingModels();
  const nodes = doc.nodes || [];
  const linkList = doc.links || [];

  // Marcas de tiempo a número una sola vez: hacer Date.parse en cada accesor y
  // en cada fotograma es carísimo.
  nodes.forEach((node) => {
    node.__gdFirst = msOf(node.firstSeen);
    node.__gdLast = msOf(node.lastSeen);
    node.__gdLevel = (node.props && node.props.level) || 0;
  });
  linkList.forEach((link) => {
    link.__gdFirst = msOf(link.firstSeen);
    link.__gdLast = msOf(link.lastSeen);
  });

  links.assignCurvature(linkList, opt('links', 'curvature', 0.22));

  adjacency = {};
  const byId = new Map(nodes.map((node) => [node.id, node]));
  nodes.forEach((node) => { adjacency[node.id] = []; });
  linkList.forEach((link) => {
    const a = byId.get(idOf(link.source));
    const b = byId.get(idOf(link.target));
    if (a && b) {
      adjacency[a.id].push({ node: b, link });
      adjacency[b.id].push({ node: a, link });
    }
  });

  const stamps = nodes.map((node) => node.__gdFirst).filter((value) => value !== null);
  const result = { nodes, links: linkList, meta: doc.meta || {} };
  result.__gdTmin = stamps.length ? Math.min(...stamps) : 0;
  result.__gdTmax = stamps.length ? Math.max(...stamps) : 1;
  if (result.__gdTmax === result.__gdTmin) result.__gdTmax = result.__gdTmin + 1;
  return result;
}

/* --------------------------------------------------- construir / destruir */

function constructionOptions() {
  const options = {
    controlType: opt('camera', 'controlType', 'trackball'),
    // Sin preserveDrawingBuffer, toDataURL() devuelve un lienzo en blanco y el
    // informe se queda sin la captura del grafo.
    rendererConfig: { antialias: true, alpha: true, preserveDrawingBuffer: true },
  };
  if (opt('labels', 'renderer', 'sprite') === 'css2d') {
    options.extraRenderers = [new CSS2DRenderer()];
  }
  return options;
}

function signatureOf(options) {
  return `${options.controlType}|${options.extraRenderers ? 'css2d' : 'sprite'}`;
}

let currentSignature = '';

function construct() {
  const options = constructionOptions();
  currentSignature = signatureOf(options);

  // Forma kapsule: ForceGraph3D(config)(elemento). La documentación del repo
  // enseña `new ForceGraph3D(elemento, config)`, que es de una versión
  // posterior a la 1.73.4 que tenemos vendorizada: con este bundle esa forma
  // no crea el lienzo Y NO LANZA NINGÚN ERROR, así que la página se queda en
  // negro sin una sola pista en la consola. Si algún día se sube de versión,
  // hay que revisar esta línea.
  graph = ForceGraph3D(options)(container);
  wireAccessors();
  applyPhysics();
  applyRenderSettings();

  // Luz frontal fija: sin ella las figuras quedan planas al girar la cámara.
  const headlight = new THREE.DirectionalLight(0xffffff, 0.6);
  headlight.position.set(1, 1, 1);
  graph.scene().add(headlight);

  // La cámara se recrea con la instancia, así que el bucle pregunta por ella
  // cada fotograma en vez de quedarse con una referencia que caducaría.
  orient.start({
    getCamera: () => (graph ? graph.camera() : null),
    getNodes: () => data.nodes || [],
    getMode: () => opt('camera', 'figureFacing', 'yaw'),
  });

  resize();
  // Red de seguridad: entre construir y recibir los primeros datos hay
  // fotogramas que pueden matar el bucle. Se comprueba un par de veces.
  setTimeout(reviveAnimation, 300);
  setTimeout(reviveAnimation, 1500);
}

function destroy() {
  if (!graph) return;
  clearExtras();
  stopOrbit();
  orient.stop();
  graph._destructor?.();
  container.innerHTML = '';
  graph = null;
}

/* --------------------------------------------------------------- órbita */

function startOrbit() {
  stopOrbit();
  if (!opt('camera', 'autoOrbit', false)) return;
  const speed = opt('camera', 'orbitSpeed', 1);
  const distance = Math.max(200, opt('camera', 'focusDistance', 130) * 3);
  orbitTimer = setInterval(() => {
    orbitAngle += (Math.PI / 600) * speed;
    graph.cameraPosition({
      x: distance * Math.sin(orbitAngle),
      z: distance * Math.cos(orbitAngle),
    });
  }, 16);
}

function stopOrbit() {
  if (orbitTimer) {
    clearInterval(orbitTimer);
    orbitTimer = null;
  }
}

/* ------------------------------------------------------------------- API */

export function init(element, callbacks, initialProfile) {
  container = element;
  handlers = callbacks || {};
  profile = initialProfile;
  construct();
  window.addEventListener('resize', resize);
  return api;
}

export function resize() {
  if (!graph || !container) return;
  graph.width(container.clientWidth).height(container.clientHeight);
}

export function refresh() {
  if (graph) graph.refresh();
}

/**
 * Revive el bucle de animación de la librería si se ha muerto.
 *
 * EL FALLO, que es del bundle y no nuestro: `three-forcegraph` guarda la
 * simulación en `state.layout`, y solo la asigna AL FINAL de una actualización
 * de `graphData`. Si un fotograma cae dentro de esa ventana, su `tickFrame()`
 * hace `layout.tick()` sobre un `undefined` y lanza.
 *
 * Lo grave es dónde lanza. El ciclo es, todo en la misma expresión:
 *
 *     forceGraph.tickFrame(), renderObjs.tick(), requestAnimationFrame(...)
 *
 * Si la primera revienta, no se llega a reprogramar el fotograma siguiente y el
 * bucle NO VUELVE. Se queda muerto para el resto de la sesión, y con él:
 *
 *   - la simulación de fuerzas, que deja de asentarse (se queda con los
 *     warmupTicks iniciales y nunca corre los cooldownTicks)
 *   - las transiciones de cámara, porque el tween se avanza en renderObjs.tick()
 *   - las partículas de las aristas
 *
 * La escena se sigue dibujando —eso lo hace otro bucle distinto— así que desde
 * fuera no se nota que algo se ha parado: simplemente nada se mueve nunca.
 *
 * No basta con `resumeAnimation()`: comprueba si el identificador del fotograma
 * pendiente es nulo, y como la excepción salta ANTES de la línea que lo
 * reasigna, se queda con el del fotograma que ya se consumió. La librería cree
 * que sigue corriendo y no hace nada. Hay que pararlo explícitamente primero,
 * que es lo que pone el identificador a nulo, y entonces sí arranca.
 *
 * Sobre un bucle sano esto es inofensivo: cancela el fotograma pendiente y pide
 * otro. Para cuando corre, `layout` ya existe y no vuelve a lanzar.
 */
function reviveAnimation() {
  if (!graph || typeof graph.resumeAnimation !== 'function') return;
  graph.pauseAnimation();
  graph.resumeAnimation();
}

export function setData(doc) {
  data = decorate(doc);
  heavy = data.nodes.length > opt('render', 'heavyThreshold', 350);
  selection.node = null;
  selection.link = null;
  selection.multi.clear();
  highlight.nodes.clear();
  highlight.links.clear();

  applyRenderSettings();
  graph.graphData(data);
  applyPhysics();
  applyLayout();
  // Cambiar los datos y la fisica es justo lo que abre la ventana en la que el
  // bucle de la libreria se mata solo. Se comprueba despues, no antes.
  setTimeout(reviveAnimation, 0);
  return data;
}

export function applyProfile(next) {
  profile = next;
  const signature = signatureOf(constructionOptions());

  if (signature !== currentSignature) {
    // Cambió una opción de construcción: hay que levantar otra instancia y
    // devolverle los datos, la vista y la selección.
    const camera = graph ? graph.cameraPosition() : null;
    const previousNode = selection.node;
    destroy();
    construct();
    graph.graphData(data);
    applyLayout();
    if (camera) graph.cameraPosition(camera, undefined, 0);
    if (previousNode) selectNode(previousNode.id, false);
  } else {
    wireAccessors();
    applyPhysics();
    applyRenderSettings();
    applyLayout();
  }
  // Al apagar el giro hay que deshacerlo: si no, cada figura se queda clavada
  // con el ultimo rumbo que le toco y el desorden parece deliberado.
  if (opt('camera', 'figureFacing', 'yaw') === 'fixed') orient.reset(data.nodes);
  startOrbit();
  refresh();
  setTimeout(reviveAnimation, 0);
}

export function setView(name) {
  view = name;
  applyLayout();
}

export const getView = () => view;

export function setColorMode(mode) {
  colorMode = mode;
  refresh();
}

export const getColorMode = () => colorMode;

/* Ensena u oculta nodos y aristas segun el cursor temporal, tocando el `visible`
   de los objetos que ya existen.

   Los accesores nodeVisibility/linkVisibility de la libreria calculan lo mismo,
   pero solo se reevaluan en su ciclo de actualizacion, y forzarlo significaba
   llamar a refresh(). La reproduccion mueve el cursor en cada fotograma, asi
   que eso era reconstruir la escena entera sesenta veces por segundo.

   No se desincronizan: cuando la libreria vuelva a evaluar sus accesores por
   cualquier otro motivo, saldra de visibleAt() y dara exactamente este mismo
   resultado. */
function applyTimeVisibility() {
  const nodes = data.nodes || [];
  for (let i = 0; i < nodes.length; i += 1) {
    const object = nodes[i].__threeObj;
    if (object) object.visible = visibleAt(nodes[i]);
  }
  const linkList = data.links || [];
  for (let i = 0; i < linkList.length; i += 1) {
    const link = linkList[i];
    const shown = visibleAt(link);
    if (link.__lineObj) link.__lineObj.visible = shown;
    if (link.__arrowObj) link.__arrowObj.visible = shown;
    if (link.__gdObj) link.__gdObj.visible = shown;
  }
}

export function setTimeCursor(cursor) {
  timeCursor = cursor;
  applyTimeVisibility();
}

export const getTimeRange = () => ({ from: data.__gdTmin || 0, to: data.__gdTmax || 0 });

export function selectNode(nodeId, focusCamera = true) {
  const node = data.nodes.find((item) => item.id === nodeId);
  selection.node = node || null;
  selection.link = null;
  setHighlightFromNode(node);
  applyHighlight();

  if (focusCamera && node && node.x !== undefined) {
    // Matemática del ejemplo `click-to-focus`: se apunta al nodo desde fuera.
    const distance = opt('camera', 'focusDistance', 130);
    const hypot = Math.hypot(node.x, node.y, node.z || 0) || 1;
    const ratio = 1 + distance / hypot;
    const position = (node.x || node.y || node.z)
      ? { x: node.x * ratio, y: node.y * ratio, z: (node.z || 0) * ratio }
      : { x: 0, y: 0, z: distance };
    graph.cameraPosition(position, node, opt('camera', 'transitionMs', 900));
  }
  return node;
}

export function toggleMultiSelect(node) {
  if (selection.multi.has(node)) selection.multi.delete(node);
  else selection.multi.add(node);
  highlight.nodes.clear();
  highlight.links.clear();
  selection.multi.forEach((item) => {
    highlight.nodes.add(item);
    (adjacency[item.id] || []).forEach(({ link }) => highlight.links.add(link));
  });
  applyHighlight();
  return [...selection.multi];
}

export const multiSelection = () => [...selection.multi];

export function selectLink(linkId) {
  const link = data.links.find((item) => item.id === linkId);
  selection.link = link || null;
  selection.node = null;
  highlight.nodes.clear();
  highlight.links.clear();
  if (link) {
    highlight.links.add(link);
    const from = data.nodes.find((n) => n.id === idOf(link.source));
    const to = data.nodes.find((n) => n.id === idOf(link.target));
    if (from) highlight.nodes.add(from);
    if (to) highlight.nodes.add(to);
  }
  applyHighlight();
  return link;
}

export function clearSelection() {
  selection.node = null;
  selection.link = null;
  selection.multi.clear();
  highlight.nodes.clear();
  highlight.links.clear();
  highlight.hoverNode = null;
  highlight.hoverLink = null;
  applyHighlight();
}

export const getSelection = () => selection;
export const nodeById = (id) => data.nodes.find((node) => node.id === id) || null;
export const linkById = (id) => data.links.find((link) => link.id === id) || null;
export const neighborsOf = (id) =>
  [...(adjacency[id] || [])].sort((a, b) => (b.node.risk || 0) - (a.node.risk || 0));
export const currentData = () => data;
export { idOf };

export function releaseFixed() {
  data.nodes.forEach((node) => { node.fx = undefined; node.fy = undefined; node.fz = undefined; });
  graph.d3ReheatSimulation();
}

export function zoomToFit(ms = 700, padding = 90) {
  if (graph) graph.zoomToFit(ms, padding);
}

/**
 * Lleva la cámara a encuadrar UNA relación, con sus dos extremos a la vista.
 *
 * No sirve la matemática de `selectNode()`, que proyecta desde el origen de la
 * escena hacia el nodo: eso centra bien una entidad suelta, pero al mirar una
 * arista deja la cámara en línea con ella y los dos extremos se tapan entre sí.
 * El recorrido necesita justo lo contrario: ver a la vez quién hizo qué y a
 * quién, porque de eso trata el paso.
 *
 * Así que se apunta al punto medio y se retrocede en una dirección
 * PERPENDICULAR a la arista, a una distancia proporcional a lo larga que sea.
 *
 * Devuelve el punto al que se mira, para poder resaltarlo.
 */
export function focusOnLink(link, ms = 900) {
  if (!graph || !link) return null;
  const from = data.nodes.find((n) => n.id === idOf(link.source));
  const to = data.nodes.find((n) => n.id === idOf(link.target));
  if (!from || !to || !Number.isFinite(from.x) || !Number.isFinite(to.x)) return null;

  const mid = {
    x: (from.x + to.x) / 2,
    y: (from.y + to.y) / 2,
    z: ((from.z || 0) + (to.z || 0)) / 2,
  };

  // Vector de la arista y su longitud.
  const ax = to.x - from.x;
  const ay = to.y - from.y;
  const az = (to.z || 0) - (from.z || 0);
  const largo = Math.hypot(ax, ay, az) || 1;

  // Perpendicular: producto vectorial de la arista con la vertical del mundo.
  // Si la arista es casi vertical el resultado sería casi cero y la cámara se
  // quedaría encima del punto medio, así que en ese caso se usa otro eje.
  let px = ay * 0 - az * 1;
  let py = az * 0 - ax * 0;
  let pz = ax * 1 - ay * 0;
  if (Math.hypot(px, py, pz) < largo * 0.15) {
    px = 1; py = 0; pz = 0;
  }
  const norma = Math.hypot(px, py, pz) || 1;

  // Lo bastante lejos para que quepan los dos extremos, con un suelo para que
  // dos entidades pegadas no dejen la cámara dentro de una figura.
  const distancia = Math.max(opt('camera', 'focusDistance', 130) * 0.75, largo * 1.35);

  graph.cameraPosition({
    x: mid.x + (px / norma) * distancia,
    y: mid.y + (py / norma) * distancia + largo * 0.25,
    z: mid.z + (pz / norma) * distancia,
  }, mid, ms);
  return mid;
}

/** Coloca el resaltado en una entidad y una arista concretas, sin mover cámara. */
export function highlightPair(nodeId, link) {
  highlight.nodes.clear();
  highlight.links.clear();
  const node = data.nodes.find((n) => n.id === nodeId);
  if (node) highlight.nodes.add(node);
  if (link) {
    highlight.links.add(link);
    const from = data.nodes.find((n) => n.id === idOf(link.source));
    const to = data.nodes.find((n) => n.id === idOf(link.target));
    if (from) highlight.nodes.add(from);
    if (to) highlight.nodes.add(to);
  }
  applyHighlight();
}

/** Posición y objetivo actuales de la cámara, para poder volver luego. */
export function cameraState() {
  return graph ? graph.cameraPosition() : null;
}

export function restoreCamera(state, ms = 700) {
  if (graph && state) graph.cameraPosition(state, undefined, ms);
}

/** Destello puntual sobre una arista: el evento "ocurre" a la vista. */
export function pulse(link) {
  try {
    graph.emitParticle(link);
  } catch (error) {
    /* la arista ya no está visible: nada que hacer */
  }
}

/** Captura del lienzo para incrustarla en el informe. */
export function snapshot() {
  if (!graph) return null;
  const renderer = graph.renderer();
  if (!renderer) return null;
  // Se fuerza un render inmediato: con preserveDrawingBuffer el búfer conserva
  // el ÚLTIMO fotograma dibujado, y sin esto se captura uno viejo.
  renderer.render(graph.scene(), graph.camera());
  try {
    return renderer.domElement.toDataURL('image/png');
  } catch (error) {
    return null;
  }
}

export function stats() {
  return { nodes: data.nodes.length, links: data.links.length, meta: data.meta || {}, heavy };
}

/* Acceso directo a la escena y a la camara de three. Se expone para poder
   inspeccionarlas desde fuera (diagnostico, capturas, extensiones) sin tener que
   volver a envolver media librería. */
export const scene = () => (graph ? graph.scene() : null);
export const camera = () => (graph ? graph.camera() : null);

export function disposeAll() {
  destroy();
  disposeCaches();
  glbCache.clear();
}

const api = {
  init, resize, refresh, setData, applyProfile, setView, getView,
  setColorMode, getColorMode, setTimeCursor, getTimeRange,
  selectNode, selectLink, clearSelection, getSelection, toggleMultiSelect,
  multiSelection, nodeById, linkById, neighborsOf, currentData, idOf,
  releaseFixed, zoomToFit, pulse, snapshot, stats, disposeAll, scene, camera,
  applyHighlight, focusOnLink, highlightPair, cameraState, restoreCamera,
};

export default api;
