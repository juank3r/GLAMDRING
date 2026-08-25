/* GLAMDRING :: auto.js — el incidente contándose solo, en bucle.
 *
 * Se pulsa una vez y no hay que volver a tocar nada: la cámara va recorriendo
 * las entidades del incidente una tras otra, y al terminar vuelve a empezar.
 * Sirve para dejarlo en una pantalla del SOC, y para explicarle un caso a
 * alguien sin que nadie tenga que conducir.
 *
 * EL ORDEN ES LO QUE LE DA SENTIDO, y por eso no puede ser aleatorio ni por
 * riesgo. Se recorren por la hora de su PRIMERA aparición, que reproduce el
 * incidente tal como se desarrolló: primero quien abrió la puerta, luego lo que
 * tocó, luego adónde saltó. Ir por riesgo enseñaría antes el desenlace que el
 * principio, que es la manera más rápida de que no se entienda nada.
 *
 * Dentro de cada entidad manda `follow.js`, que ya recorre sus actos en orden y
 * va revelando el grafo según avanza.
 *
 * SE PARA SOLO EN CUANTO ALGUIEN TOCA ALGO. Un modo automático que se pelea con
 * el ratón es un modo automático que se acaba apagando.
 */

import * as follow from './follow.js';
import * as graph3d from '../render/graph3d.js';

/* Papeles que no merecen un turno. 'neutral' es el contexto forense de apoyo:
   hashes sueltos, artefactos que no cuentan nada por sí solos. Meterlos alarga
   el bucle sin añadir historia. Configurable por si alguien quiere verlo todo. */
const PAPELES_QUE_SE_SALTAN = new Set(['neutral']);

const ENTRE_ENTIDADES_MS = 2200;   // rótulo de quién viene ahora
const MIN_ACCIONES = 2;            // con una sola acción no hay recorrido que contar

let handlers = {};
let rotulo = null;

const estado = {
  activo: false,
  cola: [],
  posicion: 0,
  vueltas: 0,
  temporizador: null,
  incluirContexto: false,
};

const el = (id) => document.getElementById(id);
const esc = (t) => String(t ?? '').replace(/[&<>"']/g,
  (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

/* ------------------------------------------------------------------ la cola */

/**
 * Qué entidades se recorren y en qué orden.
 *
 * El criterio es la hora de la primera aparición. Los nodos sin hora van al
 * final: normalmente son artefactos derivados (un hash, una ruta) que no tienen
 * un momento propio en la historia.
 */
function construirCola(doc) {
  const nodos = (doc.nodes || []).filter((n) => {
    if (n.eventCount < MIN_ACCIONES) return false;
    const papel = (n.props || {}).role || 'neutral';
    if (!estado.incluirContexto && PAPELES_QUE_SE_SALTAN.has(papel)) return false;
    return true;
  });

  return nodos
    .map((n) => ({ nodo: n, t: Date.parse(n.firstSeen || '') }))
    .sort((a, b) => {
      const at = Number.isFinite(a.t) ? a.t : Infinity;
      const bt = Number.isFinite(b.t) ? b.t : Infinity;
      if (at !== bt) return at - bt;
      // A igualdad de hora, primero el de más riesgo: si dos cosas pasan en el
      // mismo segundo, se cuenta antes la que importa.
      return (b.nodo.risk || 0) - (a.nodo.risk || 0);
    })
    .map((x) => x.nodo);
}

/* ----------------------------------------------------------------- el rótulo */

/* Devuelve si el rotulo se ha llegado a enseñar.
   En pantalla completa no se enseña: es un cartel a pantalla partida que tapa
   justo el grafo que se ha ido a ver ahi. La misma informacion (quien es y por
   que paso va) esta en la barra de abajo a la izquierda, que si se queda. */
function mostrarRotulo(nodo, indice, total) {
  if (!rotulo || document.body.classList.contains('cine')) return false;
  const papel = (nodo.props || {}).role || '';
  rotulo.innerHTML = `
    <div class="auto-card">
      <div class="auto-kicker">${esc(indice)} de ${esc(total)} · vuelta ${esc(estado.vueltas + 1)}</div>
      <div class="auto-name">${esc(nodo.label)}</div>
      <div class="auto-meta">${esc(papel)} · ${esc(nodo.eventCount)} apariciones</div>
    </div>`;
  rotulo.hidden = false;
  return true;
}

const ocultarRotulo = () => { if (rotulo) rotulo.hidden = true; };

/* ------------------------------------------------------------------- el bucle */

function siguienteEntidad() {
  if (!estado.activo) return;

  if (estado.posicion >= estado.cola.length) {
    // Vuelta completa: encuadre general y a empezar otra vez.
    estado.posicion = 0;
    estado.vueltas += 1;
    follow.salir();
    graph3d.zoomToFit(900, 90);
    handlers.onLoop?.(estado.vueltas);
    estado.temporizador = setTimeout(siguienteEntidad, ENTRE_ENTIDADES_MS * 1.6);
    return;
  }

  const nodo = estado.cola[estado.posicion];
  // Sin rotulo que leer no hay nada que esperar: mantener la pausa larga seria
  // dejar la pantalla parada dos segundos sin decir por que.
  const espera = mostrarRotulo(nodo, estado.posicion + 1, estado.cola.length)
    ? ENTRE_ENTIDADES_MS : 450;

  estado.temporizador = setTimeout(async () => {
    if (!estado.activo) return;
    ocultarRotulo();
    // Si esta entidad no da recorrido, follow avisa por onError y aquí se pasa a
    // la siguiente sin dejar el bucle colgado.
    await follow.follow(nodo.id);
    if (!estado.activo) return;
    if (!follow.activo()) pasarAlSiguiente();
  }, espera);
}

function pasarAlSiguiente() {
  if (!estado.activo) return;
  estado.posicion += 1;
  clearTimeout(estado.temporizador);
  estado.temporizador = setTimeout(siguienteEntidad, 600);
}

/* ------------------------------------------------------------ arrancar/parar */

export function arrancar(doc) {
  if (estado.activo) { parar(); return; }
  const cola = construirCola(doc || graph3d.currentData());
  if (!cola.length) {
    handlers.onError?.('No hay entidades con suficientes acciones para recorrer.');
    return;
  }
  estado.activo = true;
  estado.cola = cola;
  estado.posicion = 0;
  estado.vueltas = 0;
  document.body.classList.add('auto-on');
  handlers.onStart?.(cola.length);
  siguienteEntidad();
}

export function parar({ avisar = true } = {}) {
  if (!estado.activo) return;
  estado.activo = false;
  clearTimeout(estado.temporizador);
  estado.temporizador = null;
  ocultarRotulo();
  document.body.classList.remove('auto-on');
  follow.salir();
  if (avisar) handlers.onStop?.();
}

export const activo = () => estado.activo;

/* Lo llama app.js cuando follow termina el recorrido de una entidad. */
export function entidadTerminada() {
  if (estado.activo) pasarAlSiguiente();
}

export function init(hooks) {
  handlers = hooks || {};
  rotulo = el('auto-card');

  const boton = el('btn-auto');
  if (boton) boton.addEventListener('click', () => arrancar());

  // Cualquier gesto sobre el lienzo lo para. Pelearse con el ratón mientras la
  // cámara va sola es lo que hace que este modo no se use dos veces.
  const lienzo = el('graph');
  if (lienzo) {
    ['pointerdown', 'wheel'].forEach((evento) => {
      lienzo.addEventListener(evento, () => {
        if (estado.activo) { parar(); handlers.onInterrupted?.(); }
      }, { passive: true });
    });
  }

  return { arrancar, parar, activo, entidadTerminada };
}
