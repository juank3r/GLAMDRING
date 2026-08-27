/* GLAMDRING :: amenaza.js — lo que se ha detectado, en pantalla.
 *
 * POR QUE EXISTE. El motor de amenazas lleva funcionando desde el principio:
 * detecta comportamientos, reconoce herramientas del catálogo de 17 grupos de
 * ransomware y calcula atribución. Todo eso salía por `/api/threat` y por el
 * informe, y **la interfaz no lo llamaba nunca**. Un analista podía tener
 * delante un volcado de credenciales detectado y no verlo salvo que se le
 * ocurriera consultar la API a mano.
 *
 * Va en el inspector cuando no hay nada seleccionado. Ese sitio hoy solo decía
 * «pincha un nodo», y es la mejor parcela de la pantalla: se ve nada más abrir
 * el incidente, antes de que nadie haya pinchado nada.
 *
 * LO MÁS DELICADO ES LA ATRIBUCIÓN, y por eso se pinta al revés de como pediría
 * el instinto. Sobre la demo, SafePay puntúa 0,705 por haber usado 7zip, que
 * está en el maletín de todo el mundo. Enseñar «SafePay 70%» sería una mentira
 * con aplomo: el que la lea va a actuar sobre ella.
 *
 * Así que manda la explicación del motor —que ahí dice literalmente «no permite
 * atribuir nada»—, la puntuación va detrás y en pequeño, y toda herramienta de
 * uso generalizado se marca como tal al lado del grupo al que supuestamente
 * apunta.
 */

import * as api from '../api.js';

const el = (id) => document.getElementById(id);

const esc = (texto) => String(texto ?? '').replace(/[&<>"']/g, (c) => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
}[c]));

/* Las etapas en el orden de una intrusión, no alfabético: el analista lee la
   lista de arriba abajo como si fuera la línea temporal del ataque. */
const ETAPAS = {
  access: 'Acceso inicial',
  execution: 'Ejecución',
  persistence: 'Persistencia',
  discovery: 'Reconocimiento',
  credentials: 'Credenciales',
  lateral: 'Movimiento lateral',
  collection: 'Recopilación',
  evasion: 'Evasión',
  exfiltration: 'Exfiltración',
  impact: 'Impacto',
};

let ultimo = null;

/* ------------------------------------------------------------- pintado */

function severidadClase(nivel) {
  if (nivel >= 5) return 'critica';
  if (nivel >= 4) return 'alta';
  if (nivel >= 3) return 'media';
  return 'baja';
}

function comportamiento(b) {
  const donde = b.where ? `<span class="am-donde">${esc(b.where)}</span>` : '';
  const etapa = ETAPAS[b.stage] || b.stage || '';
  // La evidencia es el log literal. Se recorta porque una línea de comandos
  // puede tener dos mil caracteres, pero se deja lo suficiente para reconocerla.
  const evidencia = b.evidence
    ? `<code class="am-evidencia" title="${esc(b.evidence)}">${esc(b.evidence.slice(0, 160))}</code>`
    : '';
  return `
    <div class="am-comportamiento sev-${severidadClase(b.severity)}">
      <div class="am-cab">
        <span class="am-sev">${b.severity}</span>
        <strong>${esc(b.label)}</strong>
        ${donde}
      </div>
      <div class="am-meta">${esc(etapa)}${b.mitre ? ` · ${esc(b.mitre)}` : ''}</div>
      ${b.why ? `<p class="am-porque">${esc(b.why)}</p>` : ''}
      ${evidencia}
    </div>`;
}

function herramientas(porCategoria) {
  const entradas = Object.entries(porCategoria || {});
  if (!entradas.length) return '';
  return `
    <div class="am-bloque">
      <h4>Herramientas reconocidas</h4>
      ${entradas.map(([categoria, lista]) => `
        <div class="am-herramienta">
          <span class="am-cat">${esc(categoria)}</span>
          <span>${lista.map((h) => `<code>${esc(h)}</code>`).join(' ')}</span>
        </div>`).join('')}
    </div>`;
}

function atribucion(a) {
  if (!a || !(a.candidates || []).length) return '';

  const generalizadas = new Set(a.ubiquitousTools || []);
  const candidatos = (a.candidates || []).slice(0, 4).map((c) => {
    // Se separa lo que DISTINGUE de lo que no. Un solape de 7zip no dice nada,
    // y presentarlo igual que un solape de una herramienta propia del grupo es
    // lo que convierte una pista en una acusación.
    const marcadas = (c.matched || []).map((h) => (generalizadas.has(h)
      ? `<code class="am-generalizada" title="De uso generalizado: no distingue a ningún grupo">${esc(h)}</code>`
      : `<code>${esc(h)}</code>`)).join(' ');
    return `
      <div class="am-candidato">
        <div class="am-cab">
          <strong>${esc(c.group)}</strong>
          <span class="am-confianza">${esc(c.confidence)}</span>
        </div>
        <div class="am-solape">${marcadas || '<span class="am-nada">sin solape de herramientas</span>'}</div>
      </div>`;
  }).join('');

  return `
    <div class="am-bloque">
      <h4>Atribución</h4>
      ${a.explanation ? `<p class="am-explicacion">${esc(a.explanation)}</p>` : ''}
      ${candidatos}
      ${a.caveat ? `<p class="am-caveat">${esc(a.caveat)}</p>` : ''}
    </div>`;
}

function pintar(datos) {
  const hueco = el('inspector-empty');
  if (!hueco) return;

  const d = datos.detection || {};
  const conductas = [...(d.behaviours || [])].sort((x, y) => (y.severity || 0) - (x.severity || 0));

  if (!conductas.length && !d.toolCount) {
    // Nada detectado NO es lo mismo que no haber mirado, y hay que decirlo:
    // un panel en blanco se lee como "esto no funciona".
    hueco.innerHTML = `
      <h2>Amenaza</h2>
      <p class="am-limpio">Analizados <strong>${datos.events || 0}</strong> eventos y no se ha
         reconocido ningún comportamiento ni herramienta del catálogo.</p>
      <p class="hint">Que no haya coincidencias no significa que no haya incidente: el
         catálogo cubre 17 grupos de ransomware, no todo lo que existe.</p>
      <p class="hint">Pincha un nodo o una arista para ver sus propiedades y los
         <strong>logs originales</strong>.</p>`;
    return;
  }

  hueco.innerHTML = `
    <h2>Amenaza</h2>
    <p class="am-resumen">
      <strong>${conductas.length}</strong> comportamiento${conductas.length === 1 ? '' : 's'} ·
      <strong>${d.toolCount || 0}</strong> herramienta${d.toolCount === 1 ? '' : 's'} ·
      sobre ${datos.events || 0} eventos
    </p>
    <div class="am-bloque">
      <h4>Qué se ha visto</h4>
      ${conductas.map(comportamiento).join('')}
    </div>
    ${herramientas(d.toolsByCategory)}
    ${atribucion(datos.attribution)}
    <p class="hint am-pie">Pincha un nodo o una arista para ver sus propiedades y los
       <strong>logs originales</strong> del SIEM.</p>`;
}

/* ------------------------------------------------------------- público */

/**
 * Recarga la valoración y la pinta. Se llama después de cada ingesta.
 *
 * Si falla, se deja lo que hubiera antes en vez de vaciar el panel: perder la
 * valoración porque una petición se cayó es peor que enseñar la de hace un
 * momento, sobre todo cuando el analista la está leyendo.
 */
export async function refrescar() {
  try {
    ultimo = await api.threat();
    pintar(ultimo);
  } catch (error) {
    if (!ultimo) {
      const hueco = el('inspector-empty');
      if (hueco) {
        hueco.innerHTML = `
          <h2>Inspector</h2>
          <p>Pincha un nodo o una arista para ver sus propiedades y los
             <strong>logs originales</strong> del SIEM que la generaron.</p>`;
      }
    }
  }
}

/** Lo último que se calculó, para el que lo necesite sin volver a pedirlo. */
export const actual = () => ultimo;
