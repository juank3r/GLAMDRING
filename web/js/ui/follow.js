/* GLAMDRING :: follow.js — seguir a una entidad, paso a paso.
 *
 * El grafo enseña el ESTADO FINAL de un incidente: quién tocó qué. Es útil para
 * mirar, pero no para explicárselo a nadie, porque falta el orden. Una
 * investigación se cuenta en el tiempo.
 *
 * Al seguir una entidad pasan dos cosas a la vez, y ese es el invento:
 *
 *   1. La pantalla se queda SOLO con lo suyo. De 38 nodos a 18. Lo que sobra no
 *      se atenúa, desaparece: atenuar sigue dejando ruido delante.
 *   2. La cámara recorre sus actos en orden, parándose en cada uno mientras se
 *      lee lo que pasó.
 *
 * Los pasos vienen de `GET /api/graph/story`, con la frase ya redactada por el
 * mismo motor que escribe la cronología de los informes. Aquí no se redacta
 * nada: que el recorrido en pantalla y el informe digan la misma frase evita la
 * forma más tonta de contradecirse.
 *
 * SALIR TIENE QUE DEVOLVER LAS COSAS A SU SITIO. Se guarda el grafo anterior, la
 * cámara y la selección antes de entrar. Un modo del que se sale y te deja en
 * otro sitio distinto del que estabas no lo usa nadie dos veces.
 */

import * as api from '../api.js';
import * as graph3d from '../render/graph3d.js';

/* La pausa sale de lo que hay que leer, no de un número fijo. «jlopez se
   autenticó en wks-0421» se lee en un segundo; una línea de comandos con la
   ruta entera necesita el triple. Un tiempo fijo deja las cortas eternas y
   corta las largas por la mitad. */
const PAUSA_MIN = 1500;
const PAUSA_MAX = 5200;
const MS_POR_CARACTER = 32;   // ~19 caracteres por segundo, lectura cómoda

let barra = null;
let handlers = {};

/* Todo lo que hay que devolver al salir. */
let previo = null;

const estado = {
  activo: false,
  nodo: null,
  pasos: [],
  indice: -1,
  reproduciendo: false,
  temporizador: null,
  velocidad: 1,
};

const el = (id) => document.getElementById(id);
const esc = (t) => String(t ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ------------------------------------------------------------------ pintar */

function pintar() {
  if (!barra) return;
  const paso = estado.pasos[estado.indice];
  const total = estado.pasos.length;

  el('follow-title').textContent = estado.nodo ? estado.nodo.label : '';
  el('follow-count').textContent = total ? `${estado.indice + 1} / ${total}` : '0 / 0';
  el('follow-play').textContent = estado.reproduciendo ? '❚❚' : '▶';
  el('follow-play').title = estado.reproduciendo ? 'Pausar' : 'Reproducir';
  el('follow-prev').disabled = estado.indice <= 0;
  el('follow-next').disabled = estado.indice >= total - 1;

  const cuerpo = el('follow-step');
  if (!paso) {
    cuerpo.innerHTML = '<span class="follow-idle">Pulsa ▶ para recorrer lo que hizo.</span>';
    el('follow-logs').hidden = true;
    return;
  }

  const hora = paso.time.slice(11, 19);
  const hasta = paso.until ? ` → ${paso.until.slice(11, 19)}` : '';
  const veces = paso.count > 1 ? `<span class="follow-times">×${paso.count}</span>` : '';
  const sentido = paso.outbound ? '→' : '←';
  cuerpo.innerHTML = `
    <span class="follow-clock">${esc(hora)}${esc(hasta)}</span>
    <span class="follow-arrow sev-${paso.severity}">${sentido}</span>
    <span class="follow-text">${esc(paso.text)}</span>${veces}`;

  el('follow-logs').hidden = false;

  // Progreso: una marca por paso, coloreada por gravedad. De un vistazo se ve
  // dónde están los momentos graves del recorrido y cuánto queda.
  el('follow-progress').innerHTML = estado.pasos.map((p, i) => {
    const clase = i === estado.indice ? 'aqui' : (i < estado.indice ? 'visto' : '');
    return `<i class="follow-tick sev-${p.severity} ${clase}" data-i="${i}"
               title="${esc(p.time.slice(11, 19))} — ${esc(p.text.slice(0, 90))}"></i>`;
  }).join('');
}

/* ------------------------------------------------------------------- pasos */

/* Cuánto tiene que quedarse este paso en pantalla. */
function pausaDe(paso) {
  const largo = (paso && paso.text ? paso.text.length : 40) * MS_POR_CARACTER;
  return Math.max(PAUSA_MIN, Math.min(PAUSA_MAX, largo)) / estado.velocidad;
}

function irA(indice) {
  if (!estado.pasos.length) return;
  estado.indice = Math.max(0, Math.min(estado.pasos.length - 1, indice));
  const paso = estado.pasos[estado.indice];

  // El grafo se va construyendo según avanza el recorrido: en cada paso aparece
  // lo que acaba de ocurrir y nada de lo que viene después. Enseñarlo entero
  // desde el principio cuenta el final antes que el principio.
  //
  // Reutiliza el cursor temporal, que ya sabe ocultar y enseñar por tiempo sin
  // reconstruir nada. Se le da un margen para que la arista del paso actual
  // entre dentro y no aparezca justo después de que la cámara llegue.
  const t = Date.parse(paso.until || paso.time);
  if (Number.isFinite(t)) graph3d.setTimeCursor(t + 1);

  const link = graph3d.linkById(paso.linkId);
  if (link) {
    graph3d.highlightPair(estado.nodo.id, link);
    const vuelo = graph3d.focusOnLink(link, { maxMs: 1500 / estado.velocidad });
    // El destello sale cuando la cámara ya casi ha llegado: lanzarlo antes lo
    // deja ocurriendo fuera de plano y no se ve.
    const espera = vuelo && vuelo.movida ? vuelo.ms * 0.7 : 60;
    setTimeout(() => graph3d.pulse(link), espera);
  }
  pintar();
}

function siguiente() {
  if (estado.indice >= estado.pasos.length - 1) {
    pausar();
    return;
  }
  irA(estado.indice + 1);
}

function programar() {
  clearTimeout(estado.temporizador);
  if (!estado.reproduciendo) return;
  estado.temporizador = setTimeout(() => {
    if (!estado.reproduciendo) return;
    if (estado.indice >= estado.pasos.length - 1) {
      handlers.onFinish?.(estado.nodo);
      pausar();
      return;
    }
    irA(estado.indice + 1);
    programar();
  }, pausaDe(estado.pasos[estado.indice]));
}

function reproducir() {
  if (!estado.pasos.length) return;
  estado.reproduciendo = true;
  if (estado.indice < 0) irA(0);
  else if (estado.indice >= estado.pasos.length - 1) irA(0);
  programar();
  pintar();
}

function pausar() {
  estado.reproduciendo = false;
  clearTimeout(estado.temporizador);
  estado.temporizador = null;
  pintar();
}

/* ------------------------------------------------------------ entrar/salir */

export async function follow(nodeId) {
  if (estado.activo) salir({ restaurar: false });

  handlers.onBusy?.(true);
  let payload;
  try {
    payload = await api.story(nodeId);
  } catch (error) {
    handlers.onBusy?.(false);
    handlers.onError?.(`No se pudo trazar el recorrido: ${error.message}`);
    return;
  }
  handlers.onBusy?.(false);

  if (!payload.steps || !payload.steps.length) {
    handlers.onError?.(`${payload.label || nodeId} no tiene acciones que recorrer.`);
    return;
  }

  // Se guarda ANTES de tocar nada, para poder deshacerlo entero al salir.
  previo = {
    doc: graph3d.currentData(),
    camara: graph3d.cameraState(),
    seleccion: graph3d.getSelection().node ? graph3d.getSelection().node.id : null,
  };

  estado.activo = true;
  estado.nodo = { id: payload.node, label: payload.label, type: payload.type, role: payload.role };
  estado.pasos = payload.steps;
  estado.indice = -1;
  estado.reproduciendo = false;

  graph3d.setData(payload.graph);
  barra.hidden = false;
  document.body.classList.add('following');
  pintar();

  // Cursor justo antes del primer acto: el grafo arranca vacío y se va llenando.
  const inicio = Date.parse(payload.steps[0].time);
  if (Number.isFinite(inicio)) graph3d.setTimeCursor(inicio - 1);

  // Un encuadre general antes de empezar: primero se ve dónde estamos, y luego
  // se entra al detalle. Arrancar ya pegado a la primera arista desorienta.
  graph3d.zoomToFit(600, 110);
  setTimeout(() => reproducir(), 900);

  handlers.onEnter?.(estado.nodo, payload);
}

export function salir({ restaurar = true } = {}) {
  if (!estado.activo) return;
  pausar();
  estado.activo = false;
  estado.pasos = [];
  estado.indice = -1;
  barra.hidden = true;
  document.body.classList.remove('following');

  // Sin esto, el grafo restaurado saldría recortado por el cursor del recorrido.
  graph3d.setTimeCursor(null);

  if (restaurar && previo) {
    graph3d.setData(previo.doc);
    if (previo.seleccion) graph3d.selectNode(previo.seleccion, false);
    else graph3d.clearSelection();
    graph3d.restoreCamera(previo.camara, 600);
  }
  previo = null;
  handlers.onExit?.();
}

export const activo = () => estado.activo;
export const pasoActual = () => estado.pasos[estado.indice] || null;

/* -------------------------------------------------------------------- init */

export function init(hooks) {
  handlers = hooks || {};
  barra = el('follow-bar');
  if (!barra) return { follow, salir, activo };

  el('follow-play').addEventListener('click', () => {
    if (estado.reproduciendo) pausar(); else reproducir();
  });
  el('follow-prev').addEventListener('click', () => { pausar(); irA(estado.indice - 1); });
  el('follow-next').addEventListener('click', () => { pausar(); siguiente(); });
  el('follow-close').addEventListener('click', () => salir());

  el('follow-speed').addEventListener('change', (event) => {
    estado.velocidad = parseFloat(event.target.value) || 1;
    if (estado.reproduciendo) programar();
  });

  // Saltar a un paso pinchando su marca en la barra de progreso.
  el('follow-progress').addEventListener('click', (event) => {
    const marca = event.target.closest('.follow-tick');
    if (!marca) return;
    pausar();
    irA(parseInt(marca.dataset.i, 10));
  });

  el('follow-logs').addEventListener('click', () => {
    const paso = pasoActual();
    if (paso) handlers.onShowLogs?.(paso);
  });

  return { follow, salir, activo, pasoActual };
}
