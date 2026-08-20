/* GLAMDRING :: timeline.js — histograma inferior, brush y replay.
 *
 * El histograma se pinta en canvas y no con SVG: son hasta mil barras que se
 * repintan al arrastrar, y un DOM de mil nodos moviéndose va a tirones.
 *
 * Dos interacciones sobre la misma barra, y la distinción importa:
 *   arrastrar  -> brush: acota la ventana y RECARGA el grafo (cambian los datos)
 *   reproducir -> cursor: avanza en el tiempo SIN recargar, ocultando lo que
 *                 aún no ha ocurrido (cambia lo que se enseña, no lo que hay)
 */

import * as ont from '../ontology.js';

let canvas = null;
let ctx = null;
let track = null;
let cursorEl = null;
let brushEl = null;
let clockEl = null;

let buckets = [];
let range = { from: 0, to: 0 };
let bucketMs = 60000;

let brush = null;
let cursor = null;
let playing = false;
let rafId = null;
let lastFrame = 0;
let callbacks = {};

const REPLAY_SECONDS = 24;   // duración del replay completo, sea cual sea el span

const pad = (n) => (n < 10 ? `0${n}` : String(n));

function fmtTime(value) {
  if (!value) return '—';
  const d = new Date(value);
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function fmtFull(value) {
  if (!value) return '—';
  const d = new Date(value);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${fmtTime(value)}`;
}

const xToTime = (x) => {
  const width = track.clientWidth || 1;
  return range.from + Math.max(0, Math.min(1, x / width)) * (range.to - range.from);
};

const timeToX = (t) => {
  const span = (range.to - range.from) || 1;
  return ((t - range.from) / span) * (track.clientWidth || 1);
};

function draw() {
  if (!ctx || !canvas) return;
  const dpr = window.devicePixelRatio || 1;
  const width = track.clientWidth;
  const height = track.clientHeight;
  if (!width || !height) return;

  canvas.width = width * dpr;
  canvas.height = height * dpr;
  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  ctx.clearRect(0, 0, width, height);

  if (!buckets.length) {
    ctx.fillStyle = '#5b6880';
    ctx.font = '11px "Segoe UI", sans-serif';
    ctx.fillText('sin eventos', 8, height / 2);
    return;
  }

  const maxCount = buckets.reduce((max, bucket) => Math.max(max, bucket.count), 1);
  const span = (range.to - range.from) || 1;
  const barWidth = Math.max(1.5, (bucketMs / span) * width - 1);

  buckets.forEach((bucket) => {
    const x = timeToX(bucket.__t);
    // Escala raíz: en lineal, un pico de 500 eventos aplasta visualmente los
    // buckets de uno o dos, que suelen ser los interesantes.
    const barHeight = Math.max(2, Math.sqrt(bucket.count / maxCount) * (height - 16));
    const future = cursor !== null && bucket.__t > cursor;
    ctx.fillStyle = future ? 'rgba(91,104,128,0.25)' : ont.severity(bucket.maxSeverity || 0).color;
    ctx.globalAlpha = future ? 1 : 0.88;
    ctx.fillRect(x, height - barHeight - 2, barWidth, barHeight);
  });
  ctx.globalAlpha = 1;

  ctx.fillStyle = '#5b6880';
  ctx.font = '9px "Cascadia Mono", Consolas, monospace';
  ctx.fillText(fmtTime(range.from), 2, 10);
  const endLabel = fmtTime(range.to);
  ctx.fillText(endLabel, width - ctx.measureText(endLabel).width - 2, 10);
}

function updateOverlays() {
  if (cursor === null) {
    cursorEl.hidden = true;
  } else {
    cursorEl.hidden = false;
    cursorEl.style.left = `${timeToX(cursor)}px`;
  }

  if (!brush) {
    brushEl.hidden = true;
  } else {
    brushEl.hidden = false;
    const x1 = timeToX(brush.from);
    const x2 = timeToX(brush.to);
    brushEl.style.left = `${Math.min(x1, x2)}px`;
    brushEl.style.width = `${Math.abs(x2 - x1)}px`;
  }

  if (cursor !== null) clockEl.textContent = fmtFull(cursor);
  else if (brush) clockEl.textContent = `${fmtTime(brush.from)} → ${fmtTime(brush.to)}`;
  else clockEl.textContent = range.from ? `${fmtTime(range.from)} → ${fmtTime(range.to)}` : '—';
}

function tick(now) {
  if (!playing) return;
  const delta = lastFrame ? now - lastFrame : 16;
  lastFrame = now;

  const span = (range.to - range.from) || 1;
  const previous = cursor;
  cursor = (cursor === null ? range.from : cursor) + (span / (REPLAY_SECONDS * 1000)) * delta;

  if (cursor >= range.to) {
    cursor = range.to;
    pause();
  }
  callbacks.onCursor?.(cursor, previous);
  draw();
  updateOverlays();
  if (playing) rafId = requestAnimationFrame(tick);
}

export function init(handlers) {
  callbacks = handlers || {};
  track = document.getElementById('timeline');
  canvas = document.getElementById('timeline-canvas');
  ctx = canvas.getContext('2d');
  cursorEl = document.getElementById('timeline-cursor');
  brushEl = document.getElementById('timeline-brush');
  clockEl = document.getElementById('clock');

  let dragStart = null;

  track.addEventListener('mousedown', (event) => {
    if (!buckets.length) return;
    dragStart = event.offsetX;
  });

  track.addEventListener('mousemove', (event) => {
    if (dragStart === null) return;
    brush = {
      from: xToTime(Math.min(dragStart, event.offsetX)),
      to: xToTime(Math.max(dragStart, event.offsetX)),
    };
    updateOverlays();
  });

  window.addEventListener('mouseup', (event) => {
    if (dragStart === null) return;
    const moved = Math.abs((event.offsetX || 0) - dragStart) > 4;
    dragStart = null;
    if (!moved) {
      brush = null;   // click seco = quitar el recorte
      updateOverlays();
    }
    callbacks.onBrush?.(brush);
  });

  document.getElementById('btn-play').addEventListener('click', () => {
    if (playing) pause(); else play();
  });

  document.getElementById('btn-rewind').addEventListener('click', () => {
    pause();
    cursor = null;
    callbacks.onCursor?.(null, null);
    draw();
    updateOverlays();
  });

  window.addEventListener('resize', () => { draw(); updateOverlays(); });
  return { setData, play, pause, getBrush, getCursor, getRange };
}

export function setData(doc) {
  bucketMs = (doc.bucketSeconds || 60) * 1000;
  buckets = (doc.buckets || [])
    .map((bucket) => ({ ...bucket, __t: Date.parse(bucket.t) }))
    .filter((bucket) => !Number.isNaN(bucket.__t));

  range = buckets.length
    ? { from: buckets[0].__t, to: buckets[buckets.length - 1].__t + bucketMs }
    : { from: 0, to: 0 };
  cursor = null;
  draw();
  updateOverlays();
}

export function play() {
  if (!buckets.length) return;
  if (cursor === null || cursor >= range.to) cursor = range.from;
  playing = true;
  lastFrame = 0;
  document.getElementById('btn-play').textContent = '❚❚';
  rafId = requestAnimationFrame(tick);
}

export function pause() {
  playing = false;
  if (rafId) {
    cancelAnimationFrame(rafId);
    rafId = null;
  }
  document.getElementById('btn-play').textContent = '▶';
}

export const isPlaying = () => playing;
export const getBrush = () => brush;
export const getCursor = () => cursor;
export const getRange = () => range;

export function clearBrush() {
  brush = null;
  updateOverlays();
}
