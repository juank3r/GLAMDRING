/* GLAMDRING :: filters.js — panel izquierdo.
 *
 * Los filtros de contenido (severidad, fuentes, tácticas, texto) viajan al
 * backend porque cambian qué eventos se agregan y, por tanto, los recuentos de
 * las aristas. Los de topología (tipos de entidad y de relación) también, porque
 * podar en el cliente dejaría nodos huérfanos colgando.
 *
 * Las cuentas junto a cada chip salen del grafo YA filtrado: son "lo que hay
 * ahora en pantalla", no "lo que habría si...".
 */

import * as ont from '../ontology.js';

const state = {
  minSeverity: 0,
  types: {},
  relations: {},
  sources: {},
  tactics: {},
  roles: {},
  q: '',
};

let onChange = () => {};
let searchTimer = null;

const el = (id) => document.getElementById(id);

function chip(label, color, active, count, onToggle) {
  const node = document.createElement('span');
  node.className = `chip${active ? '' : ' off'}`;
  node.title = label;

  const dot = document.createElement('span');
  dot.className = 'dot';
  dot.style.background = color;
  node.appendChild(dot);

  const text = document.createElement('span');
  text.textContent = label;
  node.appendChild(text);

  if (count !== undefined && count !== null) {
    const counter = document.createElement('span');
    counter.className = 'count';
    counter.textContent = count;
    node.appendChild(counter);
  }

  node.addEventListener('click', () => {
    onToggle();
    onChange();
  });
  return node;
}

function tally(doc) {
  const counts = { types: {}, relations: {}, sources: {}, tactics: {}, roles: {} };
  (doc.nodes || []).forEach((node) => {
    counts.types[node.type] = (counts.types[node.type] || 0) + 1;
    const role = (node.props && node.props.role) || 'neutral';
    counts.roles[role] = (counts.roles[role] || 0) + 1;
    (node.sources || []).forEach((s) => { counts.sources[s] = (counts.sources[s] || 0) + 1; });
    (node.tactics || []).forEach((t) => { counts.tactics[t] = (counts.tactics[t] || 0) + 1; });
  });
  (doc.links || []).forEach((link) => {
    counts.relations[link.type] = (counts.relations[link.type] || 0) + 1;
  });
  return counts;
}

function fillBox(boxId, entries, emptyText) {
  const box = el(boxId);
  if (!box) return;
  box.innerHTML = '';
  entries.forEach((node) => box.appendChild(node));
  if (!box.children.length) {
    box.innerHTML = `<span class="count">${emptyText}</span>`;
  }
}

export function renderSeverityScale() {
  const scale = el('severity-scale');
  if (!scale) return;
  scale.innerHTML = '';
  ont.data().severity.forEach((level) => {
    const mark = document.createElement('span');
    mark.style.background = level.color;
    mark.title = level.label;
    if (level.id >= state.minSeverity) mark.classList.add('on');
    scale.appendChild(mark);
  });
  const slider = el('severity');
  if (slider) slider.title = `Severidad mínima: ${ont.severity(state.minSeverity).label}`;
}

export function init(callback) {
  onChange = callback || (() => {});

  // Todo activo de partida: el analista quita lo que le estorba, no tiene que ir
  // añadiendo lo que quiere ver.
  ont.entityTypes().forEach((t) => { state.types[t] = true; });
  ont.relationTypes().forEach((t) => { state.relations[t] = true; });
  Object.keys(ont.data().sources).forEach((s) => { state.sources[s] = true; });
  Object.keys(ont.data().roles).forEach((r) => { state.roles[r] = true; });
  ont.data().tactics.forEach((t) => { state.tactics[t] = true; });

  const severity = el('severity');
  severity.addEventListener('input', () => {
    state.minSeverity = parseInt(severity.value, 10) || 0;
    renderSeverityScale();
    onChange();
  });
  renderSeverityScale();

  const search = el('search');
  search.addEventListener('input', () => {
    // Cada pulsación reconstruye el grafo entero en el servidor: se espera a que
    // el analista deje de escribir.
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      state.q = search.value.trim();
      onChange();
    }, 320);
  });

  document.querySelectorAll('[data-toggle-all]').forEach((button) => {
    button.addEventListener('click', () => {
      const group = button.getAttribute('data-toggle-all');
      const bucket = state[group];
      const allOn = Object.keys(bucket).every((key) => bucket[key]);
      Object.keys(bucket).forEach((key) => { bucket[key] = !allOn; });
      onChange();
    });
  });

  return { render, toQuery, state };
}

export function render(doc) {
  const counts = tally(doc || { nodes: [], links: [] });

  fillBox('type-filters', ont.entityTypes()
    .filter((type) => counts.types[type] || !state.types[type])
    .sort((a, b) => (counts.types[b] || 0) - (counts.types[a] || 0))
    .map((type) => {
      const meta = ont.entity(type);
      return chip(meta.label, meta.color, state.types[type], counts.types[type] || 0,
                  () => { state.types[type] = !state.types[type]; });
    }), 'sin entidades');

  fillBox('role-filters', Object.keys(ont.data().roles)
    .filter((role) => counts.roles[role] || !state.roles[role])
    .map((role) => {
      const meta = ont.role(role);
      return chip(meta.label, meta.color, state.roles[role], counts.roles[role] || 0,
                  () => { state.roles[role] = !state.roles[role]; });
    }), 'sin papeles');

  fillBox('relation-filters', ont.relationTypes()
    .filter((type) => counts.relations[type] || !state.relations[type])
    .sort((a, b) => (counts.relations[b] || 0) - (counts.relations[a] || 0))
    .map((type) => {
      const meta = ont.relation(type);
      return chip(meta.label, meta.color, state.relations[type], counts.relations[type] || 0,
                  () => { state.relations[type] = !state.relations[type]; });
    }), 'sin relaciones');

  fillBox('source-filters', Object.keys(ont.data().sources)
    .filter((id) => counts.sources[id])
    .map((id) => {
      const meta = ont.source(id);
      return chip(meta.label, meta.color, state.sources[id], counts.sources[id],
                  () => { state.sources[id] = !state.sources[id]; });
    }), 'sin datos');

  fillBox('tactic-filters', ont.data().tactics
    .filter((slug) => counts.tactics[slug])
    .map((slug) => chip(ont.tacticLabel(slug), '#fbbf24', state.tactics[slug],
                        counts.tactics[slug],
                        () => { state.tactics[slug] = !state.tactics[slug]; })),
    'sin tácticas etiquetadas');
}

/* El filtro por papel se aplica en el cliente y no en el servidor: el rol se
   calcula sobre el grafo ya construido, así que mandarlo al backend obligaría a
   construirlo dos veces. Se expone aparte para que app.js lo aplique al pintar. */
export function roleFilter() {
  const keys = Object.keys(state.roles);
  const on = keys.filter((key) => state.roles[key]);
  return on.length === keys.length ? null : new Set(on);
}

export function toQuery() {
  const selected = (bucket) => {
    const keys = Object.keys(bucket);
    const on = keys.filter((key) => bucket[key]);
    if (on.length === keys.length) return null;      // todo activo = sin filtro
    // Nada activo tiene que vaciar el grafo, no ignorarse: si el analista apaga
    // todos los chips, espera ver el lienzo vacío.
    return on.length ? on : ['__ninguno__'];
  };

  return {
    minSeverity: state.minSeverity || null,
    types: selected(state.types),
    relations: selected(state.relations),
    sources: selected(state.sources),
    tactics: selected(state.tactics),
    q: state.q || null,
  };
}

export { state };
