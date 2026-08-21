/* GLAMDRING :: links.js — que las aristas se lean.
 *
 * Una arista tiene que contar cuatro cosas a la vez: qué relación es, en qué
 * sentido va, cuánto volumen mueve y si es un hecho del log o algo inferido.
 * Aquí se reparte esa carga entre color, texto, partículas y trazo, en lugar de
 * meterlo todo en el color y que no se distinga nada.
 *
 * Técnicas del repositorio oficial que se usan:
 *   - texto:     linkThreeObject + linkPositionUpdate al punto medio (ej. text-links)
 *   - gradiente: BufferGeometry con vertexColors (ej. gradient-links)
 */

import * as THREE from 'three';
import SpriteText from '../vendor/three-spritetext.mjs';
import * as ont from '../ontology.js';
import { hexToRgba } from './colors.js';

const DASH_SEGMENTS = 14;

/* ------------------------------------------------------------------ texto */

/**
 * Etiqueta flotante de una arista. Devuelve null cuando no toca rotularla,
 * y quien llama debe entonces devolver un objeto vacío para que la librería
 * siga pintando la línea.
 */
export function linkLabel(link, options) {
  const meta = ont.relation(link.type);
  const text = link.count > 1
    ? `${meta.label} ×${link.count}`
    : meta.label;

  const sprite = new SpriteText(text);
  sprite.color = meta.color;
  sprite.textHeight = 2.2 * (options.size || 1);
  sprite.backgroundColor = 'rgba(7,10,16,0.72)';
  sprite.padding = 0.6;
  sprite.borderRadius = 1;
  // Sin esto, el rectángulo de fondo del sprite tapa lo que tiene detrás.
  sprite.material.depthWrite = false;
  return sprite;
}

/**
 * Decide si una arista concreta lleva texto ahora mismo.
 *
 *   never     nunca
 *   hover     solo la que está bajo el puntero
 *   selection solo las de la selección actual
 *   busy      solo las que superan un umbral de eventos
 *   always    todas (útil con pocos nodos, ilegible con muchos)
 */
export function shouldLabel(link, mode, context) {
  switch (mode) {
    case 'never': return false;
    case 'always': return true;
    case 'busy': return (link.count || 1) >= (context.busyThreshold || 5);
    case 'hover': return context.hoveredLink === link;
    case 'selection':
      return context.selectedLink === link || Boolean(context.highlightedLinks?.has(link));
    default: return false;
  }
}

/* -------------------------------------------------- posición de la etiqueta */

/**
 * ¿Son utilizables estos extremos?
 *
 * La librería llama a linkPositionUpdate también en los fotogramas en que un
 * extremo aún no tiene posición (justo tras graphData, o con un nodo oculto por
 * el cursor del replay). Sin esta comprobación se escriben NaN en la geometría,
 * y a partir de ahí three empieza a escupir "Computed radius is NaN" en cada
 * fotograma y el objeto desaparece de la escena para siempre.
 */
function usable(point) {
  return Boolean(point)
    && Number.isFinite(point.x) && Number.isFinite(point.y)
    && (point.z === undefined || Number.isFinite(point.z));
}

/** Coloca el sprite en el punto medio del segmento. */
export function positionLabel(object, { start, end }) {
  if (!object || !usable(start) || !usable(end)) return;
  object.position.set(
    start.x + (end.x - start.x) / 2,
    start.y + (end.y - start.y) / 2,
    (start.z || 0) + ((end.z || 0) - (start.z || 0)) / 2,
  );
}

/* --------------------------------------------------------------- gradiente */

/**
 * Línea con degradado del color del origen al del destino.
 *
 * Se construye a mano porque la librería pinta las aristas de un color plano.
 * Que la arista herede los dos colores ahorra tener que mirar los extremos para
 * saber qué une, que en un grafo denso es la mitad del trabajo.
 */
export function gradientLine(link, colorOf) {
  const geometry = new THREE.BufferGeometry();
  geometry.setAttribute('position', new THREE.BufferAttribute(new Float32Array(6), 3));

  const from = new THREE.Color(colorOf(link.source));
  const to = new THREE.Color(colorOf(link.target));
  geometry.setAttribute('color', new THREE.BufferAttribute(new Float32Array([
    from.r, from.g, from.b,
    to.r, to.g, to.b,
  ]), 3));

  const material = new THREE.LineBasicMaterial({
    vertexColors: true,
    transparent: true,
    opacity: 0.75,
  });
  return new THREE.Line(geometry, material);
}

/** Actualiza los extremos de una línea de gradiente en cada tick. */
export function positionGradient(object, { start, end }) {
  if (!object || !object.geometry) return;
  if (!usable(start) || !usable(end)) {
    object.visible = false;
    return;
  }
  object.visible = true;
  const positions = object.geometry.getAttribute('position');
  if (!positions) return;
  positions.setXYZ(0, start.x, start.y, start.z);
  positions.setXYZ(1, end.x, end.y, end.z || 0);
  positions.needsUpdate = true;
}

/* ----------------------------------------------------------------- trazo */

/**
 * Línea discontinua para las relaciones inferidas.
 *
 * La ontología marca `dashed: true` en las relaciones que son contexto y no un
 * hecho duro del log ('corre en', 'resuelve a', 'hash'). Hasta ahora ese dato
 * estaba y se ignoraba, así que un hecho observado y una inferencia se pintaban
 * exactamente igual, que en forense es justo la distinción que no se puede
 * perder.
 */
export function dashedLine(link) {
  const meta = ont.relation(link.type);
  const points = [];
  for (let i = 0; i <= DASH_SEGMENTS; i++) points.push(new THREE.Vector3());

  const geometry = new THREE.BufferGeometry().setFromPoints(points);
  const material = new THREE.LineDashedMaterial({
    color: new THREE.Color(meta.color),
    dashSize: 2.2,
    gapSize: 1.8,
    transparent: true,
    opacity: 0.6,
  });
  const line = new THREE.Line(geometry, material);
  line.userData.dashed = true;
  return line;
}

export function positionDashed(object, { start, end }) {
  if (!object || !object.geometry) return;
  if (!usable(start) || !usable(end)) {
    object.visible = false;
    return;
  }
  object.visible = true;
  const positions = object.geometry.getAttribute('position');
  if (!positions) return;
  const steps = positions.count - 1;
  for (let i = 0; i <= steps; i++) {
    const t = i / steps;
    positions.setXYZ(
      i,
      start.x + (end.x - start.x) * t,
      start.y + (end.y - start.y) * t,
      (start.z || 0) + ((end.z || 0) - (start.z || 0)) * t,
    );
  }
  positions.needsUpdate = true;
  // computeLineDistances es obligatorio tras mover los vértices: sin recalcular,
  // el patrón de guiones se queda congelado en la longitud anterior.
  object.computeLineDistances();
}

/* ------------------------------------------------------------- accesores */

/** Grosor: logarítmico, porque 500 eventos no pueden ser 500 veces más gordos. */
export function widthOf(link, options, context) {
  if (context.selectedLink === link) return 3.4 * (options.widthScale || 1);
  const base = (0.5 + Math.log10(1 + (link.count || 1)) * 1.5) * (options.widthScale || 1);
  return context.isDimmed(link) ? base * 0.4 : base;
}

export function colorOf(link, options, context) {
  const meta = ont.relation(link.type);
  if (context.selectedLink === link) return '#ffffff';
  if (context.isDimmed(link)) return hexToRgba(meta.color, context.dimOpacity ?? 0.07);
  // Cuando la relación se dibuja discontinua, la línea propia de la librería se
  // vuelve invisible: si no, quedarían las dos superpuestas y los huecos del
  // trazo se rellenarían con la línea sólida, anulando el efecto. La geometría
  // sigue ahí (transparente), así que el ratón la sigue detectando igual.
  if (options.dashed && meta.dashed) return 'rgba(0,0,0,0)';
  return hexToRgba(meta.color, 0.75);
}

/** Número de partículas: el volumen de eventos se ve fluir por la arista. */
export function particlesOf(link, options, context) {
  if (!options.particles || context.isDimmed(link)) return 0;
  if (context.heavy) return 0;   // con miles de aristas, las partículas asfixian
  const density = options.particleDensity ?? 1;
  return Math.min(8, Math.ceil(Math.log10(1 + (link.count || 1)) * 3 * density));
}

export function particleSpeedOf(link, options) {
  const factor = options.particleSpeed ?? 1;
  return (0.004 + Math.min(0.012, (link.count || 1) / 4000)) * factor;
}

/**
 * Curvatura en abanico para separar multiaristas entre el mismo par de nodos.
 *
 * OJO CON EL NOMBRE DEL CAMPO. Todo lo que guardamos en los objetos de arista
 * lleva el prefijo `__gd`. `three-forcegraph` guarda SU curva interna en
 * `link.__curve`, y usar ese mismo nombre hacía que nuestro accesor
 * `linkCurvature` leyera el objeto Curve de la librería en lugar de nuestro
 * número: la librería construía entonces un tubo a partir de basura y llenaba la
 * consola de "Computed radius is NaN" mientras las aristas curvas desaparecían.
 * Cualquier campo nuevo que se añada a un nodo o a una arista tiene que llevar
 * el prefijo.
 */
export function assignCurvature(links, amount = 0.22) {
  const pairs = new Map();
  links.forEach((link) => {
    const a = typeof link.source === 'object' ? link.source.id : link.source;
    const b = typeof link.target === 'object' ? link.target.id : link.target;
    const key = a < b ? `${a} ${b}` : `${b} ${a}`;
    if (!pairs.has(key)) pairs.set(key, []);
    pairs.get(key).push(link);
  });

  pairs.forEach((group) => {
    if (group.length === 1) {
      const link = group[0];
      const a = typeof link.source === 'object' ? link.source.id : link.source;
      const b = typeof link.target === 'object' ? link.target.id : link.target;
      // Un bucle sobre sí mismo necesita curvatura o no se vería en absoluto.
      link.__gdCurve = a === b ? 0.5 : 0;
      link.__gdCurveRot = 0;
      return;
    }
    group.forEach((link, index) => {
      link.__gdCurve = (index - (group.length - 1) / 2) * amount;
      link.__gdCurveRot = index * (Math.PI / group.length);
    });
  });
}

/* ------------------------------------------------------- resaltado en vivo */

/**
 * Atenúa o restaura las aristas YA dibujadas, sin reconstruir nada.
 *
 * El color de la arista lo pone el accesor `linkColor` de la librería, y
 * reasignarlo dispara una actualización completa del componente. Eso, sumado al
 * `refresh()` de los nodos, era lo que congelaba la aplicación cada vez que el
 * ratón rozaba algo.
 *
 * La librería guarda la línea de cada arista en `link.__lineObj`, así que se le
 * cambia la opacidad del material directamente. Las decoraciones nuestras
 * (texto, degradado, trazo discontinuo) cuelgan de `__gdObj` y llevan su propio
 * material, así que se tratan igual.
 */
export function applyHighlight(links, isDimmed, options) {
  const dim = Math.max(0.04, options.dimOpacity ?? 0.07);
  for (let i = 0; i < links.length; i += 1) {
    const link = links[i];
    const dimmed = isDimmed(link);
    const objetos = [link.__lineObj, link.__arrowObj, link.__gdObj];
    for (let j = 0; j < objetos.length; j += 1) {
      const obj = objetos[j];
      if (!obj) continue;
      obj.traverse((child) => {
        if (!child.material) return;
        // La opacidad de partida se guarda la primera vez que se toca: leerla
        // después de haber atenuado daría el valor atenuado como base y la
        // arista no volvería nunca a su aspecto original.
        if (child.userData.gdBaseOpacity === undefined) {
          child.userData.gdBaseOpacity = child.material.opacity;
          child.userData.gdBaseTransparent = child.material.transparent;
        }
        if (dimmed) {
          child.material.transparent = true;
          child.material.opacity = dim;
        } else {
          child.material.transparent = child.userData.gdBaseTransparent;
          child.material.opacity = child.userData.gdBaseOpacity;
        }
      });
    }
  }
}
