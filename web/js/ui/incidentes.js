/* GLAMDRING :: incidentes.js — saltar de un incidente a otro sin salir.
 *
 * HOY la lista sale de `samples/`: los dos conjuntos de demostración y las
 * diecisiete muestras sintéticas, una por grupo de ransomware.
 *
 * MAÑANA saldrá de la base de datos de incidentes reales, y ese es el motivo de
 * que esto exista como pieza aparte. `GET /api/incidents` no devuelve ficheros:
 * devuelve FICHAS con id, título y subtítulo. El día que haya base de datos se
 * cambia lo que hay dentro de esa ruta y aquí no se toca nada, porque lo que se
 * consume es la ficha, no de dónde salió.
 *
 * CAMBIAR DE INCIDENTE SUSTITUYE, no acumula. Quedarse con dos mezclados daría
 * un grafo que no corresponde a ninguno de los dos, y encima verosímil, que es
 * lo peor que puede pasarle a una herramienta forense.
 */

import * as api from '../api.js';

let handlers = {};
let barra = null;
let selector = null;
let cuenta = null;
let cargando = false;

const el = (id) => document.getElementById(id);

const estado = {
  fichas: [],
  actual: null,
};

/* ------------------------------------------------------------------ pintar */

function pintar() {
  if (!selector) return;

  // Los de demostración primero y los grupos después: al abrir el desplegable
  // lo que se busca casi siempre es volver a la demo.
  const demos = estado.fichas.filter((f) => f.kind === 'demo');
  const apts = estado.fichas.filter((f) => f.kind !== 'demo');

  const opcion = (f) =>
    `<option value="${f.id}"${f.id === estado.actual ? ' selected' : ''}>${f.title}</option>`;

  selector.innerHTML = [
    demos.length ? `<optgroup label="Demostración">${demos.map(opcion).join('')}</optgroup>` : '',
    apts.length ? `<optgroup label="Grupos de ransomware">${apts.map(opcion).join('')}</optgroup>` : '',
  ].join('');

  const ficha = estado.fichas.find((f) => f.id === estado.actual);
  cuenta.textContent = ficha ? ficha.subtitle : `${estado.fichas.length} disponibles`;
  barra.hidden = estado.fichas.length < 2;
}

/* ------------------------------------------------------------------ cargar */

async function cambiar(id) {
  if (cargando || !id || id === estado.actual) return;
  cargando = true;
  selector.disabled = true;
  const anterior = estado.actual;
  cuenta.textContent = 'cargando…';

  try {
    const resultado = await api.loadIncident(id);
    estado.actual = id;
    pintar();
    await handlers.onLoaded?.(resultado, id);
  } catch (error) {
    // Volver a marcar el que sigue cargado de verdad: dejar el desplegable
    // enseñando uno que no se llegó a cargar es mentir sobre lo que hay en
    // pantalla.
    estado.actual = anterior;
    pintar();
    handlers.onError?.(`No se pudo cargar el incidente: ${error.message}`);
  } finally {
    cargando = false;
    selector.disabled = false;
  }
}

/** Marca cuál está cargado sin recargarlo. Lo usan los botones de demo. */
export function marcar(id) {
  estado.actual = id;
  pintar();
}

export const actual = () => estado.actual;

/* -------------------------------------------------------------------- init */

export async function init(hooks) {
  handlers = hooks || {};
  barra = el('incidente-bar');
  selector = el('incidente-select');
  cuenta = el('incidente-cuenta');
  if (!barra || !selector) return { marcar, actual };

  selector.addEventListener('change', (evento) => cambiar(evento.target.value));

  try {
    const payload = await api.incidents();
    estado.fichas = payload.incidents || [];
  } catch (error) {
    // Sin lista no hay selector, y no pasa nada: la aplicación funciona igual
    // con los botones de demostración de siempre.
    estado.fichas = [];
  }
  pintar();
  return { marcar, actual };
}
