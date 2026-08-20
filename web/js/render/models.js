/* GLAMDRING :: models.js — figuras 3D reconocibles.
 *
 * Un servidor parece un servidor y un atacante parece un atacante. Suena a
 * capricho estético y no lo es: en un grafo de doscientos nodos, la silueta se
 * lee desde el otro extremo de la escena y el texto no.
 *
 * Todo se construye con primitivas de three (cajas, cápsulas, conos,
 * extrusiones). Cero ficheros de assets: la herramienta arranca en un portátil
 * aislado sin red y las figuras se recolorean solas según severidad y papel en
 * el incidente. El sysadmin puede sustituir cualquiera por un .glb desde el
 * panel; eso lo resuelve graph3d.js, aquí solo está el respaldo procedural.
 *
 * Convención: cada constructor modela dentro de una caja de ~2 unidades de alto
 * centrada en el origen, y quien lo llama escala al radio que toque. Así los
 * tamaños son comparables entre figuras sin ajustar cada una a mano.
 */

import * as THREE from 'three';
import { iconSprite } from './sprites.js';

/* Las geometrías y materiales se comparten entre nodos. Sin esto, un grafo de
   400 nodos crearía 400 geometrías idénticas y otras tantas subidas a GPU. */
const geometryCache = new Map();
const materialCache = new Map();

const clock = new THREE.Clock();

/* -------------------------------------------------------------- utilidades */

function geo(key, factory) {
  let cached = geometryCache.get(key);
  if (!cached) {
    cached = factory();
    geometryCache.set(key, cached);
  }
  return cached;
}

function mat(color, emissiveIntensity = 0.2, opacity = 1, options = {}) {
  const key = `${color}|${emissiveIntensity}|${opacity}|${options.flat ? 1 : 0}`;
  let cached = materialCache.get(key);
  if (!cached) {
    cached = new THREE.MeshLambertMaterial({
      color: new THREE.Color(color),
      emissive: new THREE.Color(color),
      emissiveIntensity,
      transparent: opacity < 1,
      opacity,
    });
    materialCache.set(key, cached);
  }
  return cached;
}

/* Material puramente emisivo: pantallas, LEDs y aros. No depende de las luces,
   así que se ve igual desde cualquier ángulo, que es lo que se quiere en un
   piloto de alarma. */
function glow(color, opacity = 1) {
  const key = `glow|${color}|${opacity}`;
  let cached = materialCache.get(key);
  if (!cached) {
    cached = new THREE.MeshBasicMaterial({
      color: new THREE.Color(color),
      transparent: opacity < 1,
      opacity,
    });
    materialCache.set(key, cached);
  }
  return cached;
}

function mesh(geometry, material, x = 0, y = 0, z = 0) {
  const item = new THREE.Mesh(geometry, material);
  item.position.set(x, y, z);
  return item;
}

/* Oscurece un color para las partes en sombra de una figura (la carcasa frente
   a la pantalla, por ejemplo). Sin variación tonal todo parece plano. */
function shade(hex, factor = 0.55) {
  const color = new THREE.Color(hex);
  color.multiplyScalar(factor);
  return `#${color.getHexString()}`;
}

/* Late suavemente. Se engancha a onBeforeRender, que el renderer llama en cada
   fotograma, en vez de montar un bucle propio de animación. */
function pulse(object, speed = 2.4, min = 0.55, max = 1) {
  object.onBeforeRender = () => {
    const t = clock.getElapsedTime() * speed;
    const value = min + (max - min) * (0.5 + 0.5 * Math.sin(t));
    if (object.material) object.material.opacity = value;
    object.visible = true;
  };
  if (object.material) object.material.transparent = true;
}

function spin(object, speed = 0.8, axis = 'y') {
  let last = 0;
  object.onBeforeRender = () => {
    const now = clock.getElapsedTime();
    const delta = last ? now - last : 0;
    last = now;
    object.rotation[axis] += delta * speed;
  };
}

/* ------------------------------------------------------------------ figuras */

/* Puesto de trabajo: monitor, peana y teclado. La pantalla es emisiva y toma el
   color de la severidad, así que un equipo comprometido se ve "encendido en
   rojo" desde lejos sin leer una sola etiqueta. */
function workstation(ctx) {
  const group = new THREE.Group();
  const shell = mat(shade(ctx.color, 0.5), 0.08);

  group.add(mesh(geo('ws.frame', () => new THREE.BoxGeometry(1.7, 1.15, 0.14)), shell, 0, 0.42, 0));
  const screen = mesh(geo('ws.screen', () => new THREE.PlaneGeometry(1.5, 0.95)),
                      glow(ctx.screenColor, 0.92), 0, 0.42, 0.08);
  group.add(screen);
  group.add(mesh(geo('ws.neck', () => new THREE.CylinderGeometry(0.08, 0.08, 0.35, 8)), shell, 0, -0.32, 0));
  group.add(mesh(geo('ws.base', () => new THREE.BoxGeometry(0.75, 0.07, 0.45)), shell, 0, -0.52, 0));
  group.add(mesh(geo('ws.keys', () => new THREE.BoxGeometry(1.2, 0.06, 0.42)), shell, 0, -0.6, 0.55));

  if (ctx.alarm) pulse(screen, 3.2, 0.35, 1);
  return group;
}

/* Rack: chasis alto con bandejas y una columna de pilotos. Se distingue del
   puesto por la proporción vertical, que es lo que se percibe primero. */
function server(ctx) {
  const group = new THREE.Group();
  const shell = mat(shade(ctx.color, 0.45), 0.08);
  group.add(mesh(geo('srv.body', () => new THREE.BoxGeometry(1.05, 2, 0.9)), shell));

  const slot = geo('srv.slot', () => new THREE.BoxGeometry(0.92, 0.1, 0.04));
  const led = geo('srv.led', () => new THREE.SphereGeometry(0.055, 6, 5));
  const slotMat = mat(shade(ctx.color, 0.8), 0.12);

  for (let i = 0; i < 5; i++) {
    const y = 0.72 - i * 0.36;
    group.add(mesh(slot, slotMat, 0, y, 0.47));
    const lamp = mesh(led, glow(i === 0 && ctx.alarm ? ctx.severityColor : ctx.color), 0.38, y, 0.5);
    if (i === 0 && ctx.alarm) pulse(lamp, 4, 0.2, 1);
    group.add(lamp);
  }
  return group;
}

/* Router: caja plana y antenas. La silueta horizontal con "cuernos" es
   inconfundible incluso en miniatura. */
function router(ctx) {
  const group = new THREE.Group();
  const shell = mat(shade(ctx.color, 0.5), 0.1);
  group.add(mesh(geo('rt.body', () => new THREE.BoxGeometry(1.7, 0.34, 1.1)), shell, 0, -0.3, 0));

  const antenna = geo('rt.ant', () => new THREE.CylinderGeometry(0.05, 0.06, 1.05, 6));
  [-0.6, 0, 0.6].forEach((x, index) => {
    const rod = mesh(antenna, shell, x, 0.25, -0.3);
    rod.rotation.z = (index - 1) * 0.22;
    group.add(rod);
  });

  const led = geo('rt.led', () => new THREE.SphereGeometry(0.06, 6, 5));
  [-0.45, -0.15, 0.15, 0.45].forEach((x) => {
    group.add(mesh(led, glow(ctx.screenColor), x, -0.24, 0.56));
  });
  return group;
}

/* Cortafuegos: un muro de ladrillos. La metáfora es obvia a propósito, porque
   es la única figura que tiene que entenderse sin explicación previa. */
function firewall(ctx) {
  const group = new THREE.Group();
  const brick = geo('fw.brick', () => new THREE.BoxGeometry(0.52, 0.24, 0.3));
  const brickMat = mat(ctx.color, 0.14);

  for (let row = 0; row < 6; row++) {
    const offset = row % 2 === 0 ? 0 : 0.28;
    for (let col = -1; col <= 1; col++) {
      group.add(mesh(brick, brickMat, col * 0.56 + offset - 0.14, -0.75 + row * 0.28, 0));
    }
  }
  const edge = mesh(geo('fw.edge', () => new THREE.BoxGeometry(1.75, 0.06, 0.34)),
                    glow(ctx.screenColor), 0, 0.86, 0);
  if (ctx.alarm) pulse(edge, 3, 0.3, 1);
  group.add(edge);
  return group;
}

/* Persona: cápsula y cabeza, con un aro azul flotando encima cuando la entidad
   es legítima. El aro es lo que crea el contraste inmediato con la figura
   encapuchada del atacante. */
function person(ctx) {
  const group = new THREE.Group();
  const body = mat(ctx.color, 0.2);
  group.add(mesh(geo('pr.body', () => new THREE.CapsuleGeometry(0.42, 0.7, 5, 12)), body, 0, -0.3, 0));
  group.add(mesh(geo('pr.head', () => new THREE.SphereGeometry(0.34, 14, 12)), body, 0, 0.62, 0));

  if (!ctx.alarm) {
    const halo = mesh(geo('pr.halo', () => new THREE.TorusGeometry(0.33, 0.045, 8, 20)),
                      glow(ctx.color, 0.9), 0, 1.1, 0);
    halo.rotation.x = Math.PI / 2;
    group.add(halo);
  } else {
    const warn = mesh(geo('pr.warn', () => new THREE.TorusGeometry(0.36, 0.05, 8, 20)),
                      glow(ctx.severityColor, 0.95), 0, 1.12, 0);
    warn.rotation.x = Math.PI / 2;
    pulse(warn, 3.4, 0.25, 1);
    group.add(warn);
  }
  return group;
}

/* Atacante: la misma silueta humana pero encapuchada y sin aro. Se reconoce por
   la forma, no por el color, que es lo que hace que siga funcionando para quien
   no distingue el rojo del verde. */
function attacker(ctx) {
  const group = new THREE.Group();
  const cloth = mat(shade(ctx.color, 0.62), 0.28);

  group.add(mesh(geo('at.body', () => new THREE.ConeGeometry(0.62, 1.25, 12)), cloth, 0, -0.35, 0));
  group.add(mesh(geo('at.head', () => new THREE.SphereGeometry(0.3, 12, 10)),
                 mat('#12161f', 0.02), 0, 0.5, 0));

  const hood = mesh(geo('at.hood', () => new THREE.ConeGeometry(0.44, 0.62, 12, 1, true)), cloth, 0, 0.62, -0.03);
  hood.rotation.x = -0.18;
  group.add(hood);

  // Dos puntos de luz donde estarían los ojos: a esta escala es lo único que
  // se distingue dentro de la capucha y lo que le da carácter.
  const eye = geo('at.eye', () => new THREE.SphereGeometry(0.06, 6, 5));
  const eyeMat = glow(ctx.severityColor);
  group.add(mesh(eye, eyeMat, -0.12, 0.48, 0.25));
  group.add(mesh(eye, eyeMat, 0.12, 0.48, 0.25));
  return group;
}

/* Engranaje: un Shape con dientes, extruido. Un proceso es "algo que corre". */
function gear(ctx) {
  const group = new THREE.Group();
  const geometry = geo('gr.body', () => {
    const shape = new THREE.Shape();
    const teeth = 10;
    const outer = 0.85;
    const inner = 0.66;
    for (let i = 0; i < teeth * 2; i++) {
      const angle = (i / (teeth * 2)) * Math.PI * 2;
      const radius = i % 2 === 0 ? outer : inner;
      const x = Math.cos(angle) * radius;
      const y = Math.sin(angle) * radius;
      if (i === 0) shape.moveTo(x, y);
      else shape.lineTo(x, y);
    }
    shape.closePath();
    const hole = new THREE.Path();
    hole.absarc(0, 0, 0.28, 0, Math.PI * 2, true);
    shape.holes.push(hole);
    return new THREE.ExtrudeGeometry(shape, { depth: 0.26, bevelEnabled: false });
  });

  const cog = mesh(geometry, mat(ctx.color, 0.22), 0, 0, -0.13);
  group.add(cog);
  if (ctx.alarm) spin(group, 1.1);
  return group;
}

/* Documento: hoja con la esquina doblada y renglones. */
function document(ctx) {
  const group = new THREE.Group();
  const paper = mat(ctx.color, 0.16);
  group.add(mesh(geo('doc.page', () => new THREE.BoxGeometry(1.15, 1.5, 0.06)), paper));

  const fold = mesh(geo('doc.fold', () => new THREE.ConeGeometry(0.26, 0.26, 3)),
                    mat(shade(ctx.color, 0.6), 0.1), 0.44, 0.62, 0.05);
  fold.rotation.set(Math.PI / 2, 0, Math.PI / 4);
  group.add(fold);

  const line = geo('doc.line', () => new THREE.BoxGeometry(0.72, 0.05, 0.02));
  const ink = mat(shade(ctx.color, 0.35), 0.02);
  [-0.3, -0.05, 0.2].forEach((y) => group.add(mesh(line, ink, -0.1, y, 0.04)));
  return group;
}

/* Alerta: octaedro con un aro que gira. El movimiento es la señal; un nodo que
   se mueve atrae la mirada aunque esté al fondo de la escena. */
function alert(ctx) {
  const group = new THREE.Group();
  group.add(mesh(geo('al.core', () => new THREE.OctahedronGeometry(0.78)), mat(ctx.color, 0.6)));

  const ring = mesh(geo('al.ring', () => new THREE.TorusGeometry(1.05, 0.07, 8, 26)),
                    glow(ctx.severityColor, 0.85));
  ring.rotation.x = Math.PI / 2.6;
  spin(ring, 1.4, 'z');
  group.add(ring);
  return group;
}

/* Globo terráqueo: dominios y URLs. Esfera translúcida con meridiano y
   paralelo, que es la iconografía universal de "esto está en Internet". */
function globe(ctx) {
  const group = new THREE.Group();
  group.add(mesh(geo('gl.core', () => new THREE.SphereGeometry(0.78, 16, 12)),
                 mat(ctx.color, 0.3, 0.55)));

  const ring = geo('gl.ring', () => new THREE.TorusGeometry(0.8, 0.035, 8, 28));
  const ringMat = glow(ctx.color, 0.9);
  group.add(mesh(ring, ringMat));
  const meridian = mesh(ring, ringMat);
  meridian.rotation.y = Math.PI / 2;
  group.add(meridian);
  const equator = mesh(ring, ringMat);
  equator.rotation.x = Math.PI / 2;
  group.add(equator);
  return group;
}

/* Sobre: buzones y correo. */
function envelope(ctx) {
  const group = new THREE.Group();
  group.add(mesh(geo('en.body', () => new THREE.BoxGeometry(1.5, 1, 0.12)), mat(ctx.color, 0.18)));

  const flap = mesh(geo('en.flap', () => new THREE.ConeGeometry(0.78, 0.5, 3)),
                    mat(shade(ctx.color, 0.65), 0.12), 0, 0.24, 0.08);
  flap.rotation.set(Math.PI / 2, 0, Math.PI);
  group.add(flap);
  return group;
}

/* Nube: cuentas cloud. Tres esferas y una base. */
function cloud(ctx) {
  const group = new THREE.Group();
  const puff = geo('cl.puff', () => new THREE.SphereGeometry(0.5, 12, 10));
  const body = mat(ctx.color, 0.24);
  group.add(mesh(puff, body, -0.42, -0.06, 0));
  group.add(mesh(puff, body, 0.42, -0.06, 0));
  const top = mesh(puff, body, 0, 0.24, 0);
  top.scale.setScalar(1.18);
  group.add(top);
  return group;
}

/* Llave: claves de registro y persistencia. */
function key(ctx) {
  const group = new THREE.Group();
  const metal = mat(ctx.color, 0.24);
  const head = mesh(geo('ky.head', () => new THREE.TorusGeometry(0.36, 0.11, 8, 18)), metal, 0, 0.55, 0);
  group.add(head);
  group.add(mesh(geo('ky.shaft', () => new THREE.CylinderGeometry(0.09, 0.09, 1.1, 8)), metal, 0, -0.28, 0));
  const tooth = geo('ky.tooth', () => new THREE.BoxGeometry(0.28, 0.11, 0.11));
  group.add(mesh(tooth, metal, 0.16, -0.58, 0));
  group.add(mesh(tooth, metal, 0.16, -0.8, 0));
  return group;
}

/* Hash: una rejilla de cubos. Sugiere "huella digital" sin recurrir a texto. */
function hashcube(ctx) {
  const group = new THREE.Group();
  const cube = geo('hs.cube', () => new THREE.BoxGeometry(0.42, 0.42, 0.42));
  const body = mat(ctx.color, 0.2);
  for (let x = 0; x < 2; x++) {
    for (let y = 0; y < 2; y++) {
      for (let z = 0; z < 2; z++) {
        group.add(mesh(cube, body, x * 0.5 - 0.25, y * 0.5 - 0.25, z * 0.5 - 0.25));
      }
    }
  }
  return group;
}

/* Dispositivo genérico: lo que no encaja en nada. Caja achaflanada con piloto. */
function endpoint(ctx) {
  const group = new THREE.Group();
  group.add(mesh(geo('ep.body', () => new THREE.IcosahedronGeometry(0.8, 0)), mat(ctx.color, 0.22)));
  group.add(mesh(geo('ep.led', () => new THREE.SphereGeometry(0.14, 8, 6)),
                 glow(ctx.screenColor), 0, 0, 0.78));
  return group;
}

const BUILDERS = {
  workstation, server, router, firewall, person, attacker, gear,
  document, alert, globe, envelope, cloud, key, hashcube, endpoint,
};

/* Geometrías simples para la calidad baja: cuando hay miles de nodos, la
   silueta detallada ni se aprecia y sí cuesta fotogramas. */
const SIMPLE = {
  sphere: () => new THREE.SphereGeometry(0.9, 10, 8),
  box: () => new THREE.BoxGeometry(1.4, 1.4, 1.4),
  cone: () => new THREE.ConeGeometry(0.85, 1.7, 10),
  cylinder: () => new THREE.CylinderGeometry(0.7, 0.7, 1.6, 10),
  octahedron: () => new THREE.OctahedronGeometry(1),
  tetrahedron: () => new THREE.TetrahedronGeometry(1.1),
  icosahedron: () => new THREE.IcosahedronGeometry(0.95),
  torus: () => new THREE.TorusGeometry(0.75, 0.28, 8, 16),
};

export function availableModels() {
  return Object.keys(BUILDERS);
}

/**
 * Construye la figura de un nodo.
 *
 * @param {object} spec
 *   model         nombre de la figura (ver availableModels)
 *   shape         geometría simple de respaldo para calidad baja
 *   radius        radio objetivo; la figura se escala para caber en él
 *   color         color del tipo de entidad
 *   severityColor color de la severidad, para pantallas y pilotos
 *   alarm         true si el nodo está en alerta (severidad alta o rol hostil)
 *   quality       'high' | 'medium' | 'low'
 */
export function buildModel(spec) {
  const quality = spec.quality || 'high';
  const ctx = {
    color: spec.color || '#94a3b8',
    severityColor: spec.severityColor || spec.color || '#94a3b8',
    screenColor: spec.alarm ? (spec.severityColor || '#ff2d55') : spec.color,
    alarm: Boolean(spec.alarm) && quality !== 'low',
  };

  let group;
  if (quality === 'low') {
    // A esta escala un icono que siempre mira a cámara se lee mucho mejor que
    // una geometría diminuta girada de canto.
    group = iconSprite({
      glyph: spec.glyph,
      color: ctx.color,
      accentColor: ctx.severityColor,
      radius: spec.radius || 6,
      alarm: Boolean(spec.alarm),
    });
  } else if (quality === 'medium') {
    const factory = SIMPLE[spec.shape] || SIMPLE.sphere;
    group = new THREE.Group();
    group.add(mesh(geo(`simple.${spec.shape || 'sphere'}`, factory),
                   mat(ctx.color, spec.alarm ? 0.5 : 0.2)));
    group.scale.setScalar((spec.radius || 6) / 1.15 * (spec.scale || 1));
    return group;
  } else {
    const builder = BUILDERS[spec.model] || BUILDERS.endpoint;
    group = builder(ctx);
  }

  // Los iconos de calidad baja ya vienen dimensionados al radio; las figuras se
  // modelan a ~2 unidades de alto y se escalan aquí, para que un host y un hash
  // sean comparables sin ajustar cada figura a mano.
  if (quality !== 'low') {
    group.scale.setScalar(((spec.radius || 6) / 1.15) * (spec.scale || 1));
  }
  return group;
}

/* Libera la GPU al reconstruir el grafo entero. Sin esto, cambiar de vista diez
   veces deja diez juegos de geometrías vivos. */
export function disposeCaches() {
  geometryCache.forEach((geometry) => geometry.dispose());
  materialCache.forEach((material) => material.dispose());
  geometryCache.clear();
  materialCache.clear();
}
