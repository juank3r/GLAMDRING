/* GLAMDRING :: sprites.js — iconos planos para la calidad baja.
 *
 * Cuando hay miles de nodos, la silueta detallada de una figura no se aprecia y
 * sí cuesta fotogramas. Un icono que siempre mira a cámara se lee mejor a esa
 * escala que una geometría diminuta girada de canto.
 *
 * Se dibujan en un <canvas> y se suben como CanvasTexture en lugar de cargar
 * PNG: cero ficheros de assets, nítidos a cualquier zoom, y el anillo de
 * severidad se pinta en tiempo de ejecución, que con imágenes fijas exigiría
 * una por cada combinación de tipo y severidad.
 */

import * as THREE from 'three';

const textureCache = new Map();
const ICON_PX = 128;

function hexToRgba(hex, alpha) {
  let value = String(hex || '#94a3b8').replace('#', '');
  if (value.length === 3) {
    value = value[0] + value[0] + value[1] + value[1] + value[2] + value[2];
  }
  const n = parseInt(value, 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
}

function iconTexture(glyph, color, accent) {
  const key = `${glyph}|${color}|${accent}`;
  if (textureCache.has(key)) return textureCache.get(key);

  const canvas = document.createElement('canvas');
  canvas.width = ICON_PX;
  canvas.height = ICON_PX;
  const ctx = canvas.getContext('2d');
  const c = ICON_PX / 2;

  // Disco de fondo: da contraste al glifo sobre cualquier color de escena.
  ctx.beginPath();
  ctx.arc(c, c, c * 0.78, 0, Math.PI * 2);
  ctx.fillStyle = 'rgba(7,10,16,0.92)';
  ctx.fill();

  // Anillo exterior con el color del TIPO.
  ctx.beginPath();
  ctx.arc(c, c, c * 0.80, 0, Math.PI * 2);
  ctx.lineWidth = ICON_PX * 0.055;
  ctx.strokeStyle = color;
  ctx.stroke();

  // Anillo interior con el color de la SEVERIDAD: se lee "qué es" y "cuánto
  // importa" sin abrir el inspector.
  if (accent && accent !== color) {
    ctx.beginPath();
    ctx.arc(c, c, c * 0.66, 0, Math.PI * 2);
    ctx.lineWidth = ICON_PX * 0.035;
    ctx.strokeStyle = accent;
    ctx.stroke();
  }

  ctx.font = `${Math.round(ICON_PX * 0.46)}px "Segoe UI Emoji", "Apple Color Emoji", `
           + '"Noto Color Emoji", sans-serif';
  ctx.textAlign = 'center';
  ctx.textBaseline = 'middle';
  ctx.fillStyle = color;
  ctx.fillText(glyph || '?', c, c + ICON_PX * 0.02);

  const texture = new THREE.CanvasTexture(canvas);
  if ('SRGBColorSpace' in THREE) texture.colorSpace = THREE.SRGBColorSpace;
  texture.anisotropy = 4;
  textureCache.set(key, texture);
  return texture;
}

/* Halo radial difuminado para los nodos graves. Es un Sprite y no un anillo
   plano porque un anillo visto de canto desaparece justo cuando más falta hace
   que se vea. */
function haloTexture(color) {
  const key = `halo|${color}`;
  if (textureCache.has(key)) return textureCache.get(key);

  const canvas = document.createElement('canvas');
  canvas.width = 128;
  canvas.height = 128;
  const ctx = canvas.getContext('2d');
  const gradient = ctx.createRadialGradient(64, 64, 26, 64, 64, 62);
  gradient.addColorStop(0.00, 'rgba(0,0,0,0)');
  gradient.addColorStop(0.55, hexToRgba(color, 0.0));
  gradient.addColorStop(0.72, hexToRgba(color, 0.7));
  gradient.addColorStop(0.86, hexToRgba(color, 0.22));
  gradient.addColorStop(1.00, hexToRgba(color, 0.0));
  ctx.fillStyle = gradient;
  ctx.fillRect(0, 0, 128, 128);

  const texture = new THREE.CanvasTexture(canvas);
  if ('SRGBColorSpace' in THREE) texture.colorSpace = THREE.SRGBColorSpace;
  textureCache.set(key, texture);
  return texture;
}

/**
 * Icono de un nodo como sprite.
 *
 * @param {object} spec  {glyph, color, accentColor, radius, alarm}
 */
export function iconSprite(spec) {
  const group = new THREE.Group();
  const radius = spec.radius || 5;

  const sprite = new THREE.Sprite(new THREE.SpriteMaterial({
    map: iconTexture(spec.glyph, spec.color, spec.accentColor),
    transparent: true,
    depthWrite: false,
  }));
  const scale = radius * 2.6;
  sprite.scale.set(scale, scale, 1);
  group.add(sprite);

  if (spec.alarm) {
    const halo = new THREE.Sprite(new THREE.SpriteMaterial({
      map: haloTexture(spec.accentColor || spec.color),
      transparent: true,
      depthWrite: false,
      opacity: 0.75,
    }));
    const haloScale = radius * 4.4;
    halo.scale.set(haloScale, haloScale, 1);
    group.add(halo);
  }
  return group;
}

export function disposeSprites() {
  textureCache.forEach((texture) => texture.dispose());
  textureCache.clear();
}
