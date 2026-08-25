/* GLAMDRING :: app.js — pega todas las piezas.
 *
 * Un solo estado y un solo camino para refrescar: cualquier cambio (filtro,
 * brush, búsqueda, ingesta, perfil visual) acaba en `reload()`, que pide el
 * grafo al servidor y repinta. Sin caminos alternativos no hay estados
 * inconsistentes que perseguir después.
 */

import * as api from './api.js';
import * as ont from './ontology.js';
import graph3d from './render/graph3d.js';
import { legendFor, nodeColor } from './render/colors.js';
import * as filters from './ui/filters.js';
import * as timeline from './ui/timeline.js';
import * as inspector from './ui/inspector.js';
import * as interactions from './ui/interactions.js';
import * as admin from './ui/admin.js';
import * as report from './ui/report.js';
import * as follow from './ui/follow.js';
import * as auto from './ui/auto.js';

const state = {
  window: { from: null, to: null },
  loading: false,
  hasData: false,
  graph: { nodes: [], links: [] },
  hidden: new Set(),          // nodos ocultados a mano desde el menú contextual
  colorMode: 'type',
  profile: null,
};

const el = (id) => document.getElementById(id);

const esc = (value) => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

function toast(message, kind, ms = 4200) {
  const box = el('toast');
  box.textContent = message;
  box.className = `stage-overlay stage-toast${kind ? ` ${kind}` : ''}`;
  box.hidden = false;
  clearTimeout(box.__timer);
  box.__timer = setTimeout(() => { box.hidden = true; }, ms);
}

/* ------------------------------------------------------------------ tema */

/* El tema del perfil se vuelca a variables CSS. Así el panel del sysadmin cambia
   el aspecto de TODA la interfaz, no solo el del grafo, con una sola fuente. */
function applyTheme(theme) {
  if (!theme) return;
  const root = document.documentElement;
  const map = {
    background: '--bg', panel: '--bg-panel', panelAlt: '--bg-panel-alt',
    border: '--border', text: '--text', textDim: '--text-dim', accent: '--accent',
  };
  Object.entries(map).forEach(([key, variable]) => {
    if (theme[key]) root.style.setProperty(variable, theme[key]);
  });
  if (theme.fontScale) root.style.setProperty('--font-scale', theme.fontScale);
  root.dataset.theme = theme.preset || 'soc-dark';
}

function applyProfile(profile) {
  state.profile = profile;
  applyTheme(profile.theme);
  ont.applyProfile(profile);
  graph3d.applyProfile(profile);
  if (profile.colorMode && profile.colorMode !== state.colorMode) {
    setColorMode(profile.colorMode);
  }
  renderLegend(state.graph);
}

/* --------------------------------------------------------------- recargar */

function currentQuery() {
  const query = filters.toQuery();
  query.from = state.window.from;
  query.to = state.window.to;
  return query;
}

/* Filtros que se aplican en el cliente porque dependen de datos que solo
   existen una vez montado el grafo (el papel) o de decisiones del analista que
   no tiene sentido persistir (nodos ocultados a mano). */
function applyClientFilters(doc) {
  const roles = filters.roleFilter();
  const hidden = state.hidden;
  if (!roles && !hidden.size) return doc;

  const nodes = doc.nodes.filter((node) => {
    if (hidden.has(node.id)) return false;
    if (roles && !roles.has((node.props && node.props.role) || 'neutral')) return false;
    return true;
  });
  const ids = new Set(nodes.map((node) => node.id));
  const links = doc.links.filter((link) => ids.has(link.source) && ids.has(link.target));
  return { ...doc, nodes, links };
}

async function reload({ fit = true, keepTimeline = false } = {}) {
  if (state.loading) return;
  state.loading = true;
  el('stage-loading').hidden = false;

  try {
    const query = currentQuery();
    const [doc, tl] = await Promise.all([
      api.graph(query),
      api.timeline({
        buckets: 160,
        minSeverity: query.minSeverity,
        sources: query.sources,
        q: query.q,
      }),
    ]);

    const filtered = applyClientFilters(doc);
    state.graph = filtered;
    state.hasData = filtered.nodes.length > 0;

    graph3d.setData(filtered);
    filters.render(filtered);
    renderStats(filtered);
    renderLegend(filtered);

    // El brush no se toca al recargar por filtros: si no, se pelearía con el
    // analista cada vez que mueve un chip.
    if (!keepTimeline) timeline.setData(tl);

    el('empty-state').style.display = state.hasData ? 'none' : 'flex';
    if (fit) setTimeout(() => graph3d.zoomToFit(), 450);
  } catch (error) {
    toast(`Error al cargar el grafo: ${error.message}`, 'error', 7000);
  } finally {
    state.loading = false;
    el('stage-loading').hidden = true;
  }
}

/* -------------------------------------------------------------- overlays */

function renderStats(doc) {
  const meta = doc.meta || {};
  const counts = meta.counts || {};
  const parts = [
    `<span><b>${counts.events || 0}</b> eventos</span>`,
    `<span><b>${doc.nodes.length}</b> entidades</span>`,
    `<span><b>${doc.links.length}</b> relaciones</span>`,
  ];
  if ((meta.sources || []).length) {
    parts.push(`<span>${meta.sources.map((s) => {
      const src = ont.source(s);
      return `<b style="color:${src.color}">${esc(src.label)}</b>`;
    }).join(' · ')}</span>`);
  }
  if (state.hidden.size) {
    parts.push(`<span class="warn">${state.hidden.size} ocultos</span>`);
  }
  if (meta.truncated) parts.push('<span class="warn">grafo recortado</span>');
  el('stats').innerHTML = parts.join('');
}

function renderLegend(doc) {
  const legend = legendFor(state.colorMode, doc.nodes || []);
  const title = (ont.colorModes().find((m) => m.id === state.colorMode) || {}).label
    || 'Tipo de entidad';

  if (legend.kind === 'ramp') {
    const stops = legend.ramp.join(',');
    el('legend').innerHTML = `<div class="head">${esc(title)}</div>
      <div class="legend-ramp" style="background:linear-gradient(90deg,${stops})"></div>
      <div class="legend-ramp-labels"><span>${esc(legend.from)}</span>
        <span>${esc(legend.to)}</span></div>`;
    return;
  }

  const rows = legend.items.slice(0, 14).map((item) =>
    `<div class="row"><span class="swatch" style="background:${item.color}"></span>
      ${esc(item.label)}</div>`).join('');
  el('legend').innerHTML = `<div class="head">${esc(title)}</div>${rows}
    <div class="head" style="margin-top:8px">Severidad</div>
    ${ont.data().severity.slice(2).map((level) =>
      `<div class="row"><span class="swatch" style="background:${level.color}"></span>
        ${esc(level.label)}</div>`).join('')}`;
}

/* ------------------------------------------------------------- selección */

function selectNode(nodeId, focusCamera = true) {
  const node = graph3d.selectNode(nodeId, focusCamera);
  if (node) inspector.showNode(node, graph3d.neighborsOf(nodeId));
}

function selectLink(link) {
  graph3d.selectLink(link.id);
  inspector.showLink(
    link,
    graph3d.nodeById(graph3d.idOf(link.source)),
    graph3d.nodeById(graph3d.idOf(link.target)),
  );
}

function setColorMode(mode) {
  state.colorMode = mode;
  graph3d.setColorMode(mode);
  renderLegend(state.graph);
  const select = el('color-mode');
  if (select && select.value !== mode) select.value = mode;
}

/* --------------------------------------------------------------- ingesta */

async function ingestFiles(fileList) {
  const files = [...(fileList || [])];
  if (!files.length) return;
  toast(`Ingiriendo ${files.length} fichero(s)…`, null, 20000);

  // Secuencial: un fichero que falle no debe abortar los demás, y así se puede
  // decir exactamente cuál ha fallado.
  const summary = { added: 0, unmatched: 0, errors: [] };
  for (const file of files) {
    try {
      const result = await api.ingestFile(file);
      summary.added += result.added || 0;
      summary.unmatched += result.unmatched || 0;
    } catch (error) {
      summary.errors.push(`${file.name}: ${error.message}`);
    }
  }

  let message = `${summary.added} eventos nuevos`;
  if (summary.unmatched) message += ` · ${summary.unmatched} sin normalizador`;
  if (summary.errors.length) toast(`${message} · fallos: ${summary.errors.join(' | ')}`, 'error', 9000);
  else toast(message, 'ok');

  state.window = { from: null, to: null };
  state.hidden.clear();
  await reload();
}

/* ----------------------------------------------------------------- modal */

function openModal(title, html) {
  el('modal-title').textContent = title;
  el('modal-body').innerHTML = html;
  el('modal').hidden = false;
}

const closeModal = () => { el('modal').hidden = true; };

async function openSiemModal() {
  try {
    const payload = await api.connectors();
    const options = payload.connectors.map((connector) =>
      `<option value="${esc(connector.name)}"${connector.configured ? '' : ' disabled'}>
        ${esc(connector.name)}${connector.configured ? '' : ' (sin credenciales)'}</option>`).join('');
    const status = payload.connectors.map((connector) =>
      `<div class="status-line"><span class="dot${connector.configured ? ' on' : ''}"></span>
        ${esc(connector.name)} — ${esc(connector.queryLanguage)}</div>`).join('');
    const examples = Object.fromEntries(
      payload.connectors.map((c) => [c.name, c.exampleQuery || '']));

    openModal('Consultar SIEM en vivo', `
      ${status}
      <label><span>Conector</span><select id="q-connector">${options}</select></label>
      <label><span>Consulta</span><textarea id="q-text" spellcheck="false"></textarea></label>
      <div class="modal-hint">La ventana temporal acepta ISO-8601 o atajos relativos:
        <code>-24h</code>, <code>-7d</code>, <code>-30m</code>.</div>
      <label><span>Desde</span><input type="text" id="q-from" value="-24h"></label>
      <label><span>Hasta</span><input type="text" id="q-to" placeholder="ahora"></label>
      <div class="modal-actions">
        <button class="btn" id="q-cancel">Cancelar</button>
        <button class="btn btn-primary" id="q-run">Ejecutar</button>
      </div>`);

    const connectorSelect = el('q-connector');
    const queryText = el('q-text');
    const applyExample = () => { queryText.value = examples[connectorSelect.value] || ''; };
    connectorSelect.addEventListener('change', applyExample);
    applyExample();

    el('q-cancel').addEventListener('click', closeModal);
    el('q-run').addEventListener('click', async () => {
      const button = el('q-run');
      button.disabled = true;
      button.textContent = 'Consultando…';
      try {
        const result = await api.querySiem({
          connector: connectorSelect.value,
          query: queryText.value,
          from: el('q-from').value || null,
          to: el('q-to').value || null,
        });
        closeModal();
        toast(`${result.added} eventos nuevos desde ${result.connector}`, 'ok');
        state.window = { from: null, to: null };
        reload();
      } catch (error) {
        button.disabled = false;
        button.textContent = 'Ejecutar';
        toast(error.message, 'error', 9000);
      }
    });
  } catch (error) {
    toast(`No se pudo listar conectores: ${error.message}`, 'error');
  }
}

/* ------------------------------------------------------------- cableado */

function wireTopbar() {
  el('view-switch').addEventListener('click', (event) => {
    const button = event.target.closest('.view-btn');
    if (!button) return;
    setView(button.getAttribute('data-view'));
  });

  el('color-mode').addEventListener('change', (event) => setColorMode(event.target.value));

  // Dos conjuntos de ejemplo con el mismo manejador. El minimo existe para
  // poder ver la forma del grafo sin nada encima, y para distinguir "va lento
  // por el volumen" de "va lento por otra cosa".
  const cargarDemo = async (id, set) => {
    const button = el(id);
    button.disabled = true;
    toast('Cargando incidente de ejemplo…', null, 15000);
    try {
      const result = await api.demo(set);
      toast(`Demo cargada: ${result.events} eventos de ${result.files.length} ficheros`, 'ok');
      state.window = { from: null, to: null };
      state.hidden.clear();
      await reload();
    } catch (error) {
      toast(`No se pudo cargar la demo: ${error.message}`, 'error', 8000);
    } finally {
      button.disabled = false;
    }
  };
  el('btn-demo').addEventListener('click', () => cargarDemo('btn-demo', 'completo'));
  el('btn-demo-min').addEventListener('click', () => cargarDemo('btn-demo-min', 'minimo'));

  el('btn-upload').addEventListener('click', () => el('file-input').click());
  el('file-input').addEventListener('change', (event) => {
    ingestFiles(event.target.files);
    event.target.value = '';
  });

  el('btn-siem').addEventListener('click', openSiemModal);
  el('btn-report').addEventListener('click', () => report.toggle(true));
  el('modal-close').addEventListener('click', closeModal);
  el('modal').addEventListener('click', (event) => {
    if (event.target === el('modal')) closeModal();
  });
}

function setView(name) {
  document.querySelectorAll('.view-btn').forEach((button) => {
    button.classList.toggle('is-active', button.getAttribute('data-view') === name);
  });
  graph3d.setView(name);
  setTimeout(() => graph3d.zoomToFit(), 700);
}

function wireDragAndDrop() {
  const stage = document.querySelector('.stage');
  ['dragenter', 'dragover'].forEach((name) => {
    stage.addEventListener(name, (event) => {
      event.preventDefault();
      stage.classList.add('is-dragging');
    });
  });
  ['dragleave', 'drop'].forEach((name) => {
    stage.addEventListener(name, (event) => {
      event.preventDefault();
      if (name === 'dragleave' && stage.contains(event.relatedTarget)) return;
      stage.classList.remove('is-dragging');
    });
  });
  stage.addEventListener('drop', (event) => ingestFiles(event.dataTransfer.files));
}

/* --------------------------------------------------- acciones del menú */

async function expandNode(node) {
  try {
    const doc = await api.neighbors(node.id, 1);
    const known = new Set(state.graph.nodes.map((item) => item.id));
    const fresh = doc.nodes.filter((item) => !known.has(item.id));
    if (!fresh.length) {
      toast('No hay vecinos nuevos que traer');
      return;
    }
    // Se fusiona en el grafo actual en vez de reemplazarlo: expandir tiene que
    // añadir contexto, no perder lo que el analista ya tenía colocado.
    const linkIds = new Set(state.graph.links.map((item) => item.id));
    const merged = {
      ...state.graph,
      nodes: [...state.graph.nodes, ...fresh],
      links: [...state.graph.links, ...doc.links.filter((item) => !linkIds.has(item.id))],
    };
    state.graph = merged;
    graph3d.setData(merged);
    renderStats(merged);
    filters.render(merged);
    toast(`${fresh.length} entidades nuevas`, 'ok');
  } catch (error) {
    toast(error.message, 'error');
  }
}

function contextActions() {
  return {
    follow: ({ node }) => follow.follow(node.id),
    focus: ({ node }) => selectNode(node.id, true),
    expand: ({ node }) => expandNode(node),
    pin: ({ node }) => {
      const live = graph3d.nodeById(node.id);
      if (!live) return;
      if (live.fx === undefined) {
        live.fx = live.x; live.fy = live.y; live.fz = live.z;
        toast('Nodo fijado');
      } else {
        live.fx = undefined; live.fy = undefined; live.fz = undefined;
        toast('Nodo suelto');
      }
    },
    hide: ({ node }) => {
      state.hidden.add(node.id);
      reload({ fit: false, keepTimeline: true });
      toast(`${node.label} oculto`);
    },
    ioc: async ({ node }) => {
      const value = (node.props && node.props.full) || node.label;
      await interactions.copyToClipboard(value);
      toast(`Copiado: ${value}`, 'ok');
    },
    copyId: async ({ node }) => {
      await interactions.copyToClipboard(node.id);
      toast('Identificador copiado', 'ok');
    },
    search: ({ node }) => {
      el('search').value = node.label;
      el('search').dispatchEvent(new Event('input'));
    },
    inspect: ({ link }) => selectLink(link),
    pulseLink: ({ link }) => graph3d.pulse(link),
    hideRelation: ({ link }) => {
      filters.state.relations[link.type] = false;
      reload({ fit: false, keepTimeline: true });
      toast(`Relación '${ont.relation(link.type).label}' oculta`);
    },
    escape: () => {
      // Salir del recorrido va primero: si se sigue a alguien, escape significa
      // "sacame de aqui", no "quita la seleccion".
      if (auto.activo()) { auto.parar(); return; }
      if (follow.activo()) { follow.salir(); return; }
      graph3d.clearSelection();
      inspector.clear();
      closeModal();
      admin.toggle(false);
      report.toggle(false);
    },
    followSelected: () => {
      const seleccionado = graph3d.getSelection().node;
      if (follow.activo()) follow.salir();
      else if (seleccionado) follow.follow(seleccionado.id);
      else toast('Selecciona una entidad antes de seguirla.', null, 3000);
    },
    toggleAuto: () => auto.arrancar(state.graph),
    fit: () => graph3d.zoomToFit(),
    togglePlay: () => (timeline.isPlaying() ? timeline.pause() : timeline.play()),
    setView,
    cycleColorMode: () => {
      const modes = ont.colorModes().map((mode) => mode.id);
      const index = modes.indexOf(state.colorMode);
      setColorMode(modes[(index + 1) % modes.length]);
    },
    openAdmin: () => admin.toggle(true),
    openReport: () => report.toggle(true),
  };
}

/* ----------------------------------------------------------------- arranque */

let lastClick = { id: null, at: 0 };
/* Perfil visual descargado en el arranque, compartido entre el grafo y el panel. */
let adminPayload = null;

async function boot() {
  // La ontología del servidor manda sobre la copia local.
  try {
    ont.adopt(await api.ontology());
  } catch (error) {
    /* sin backend, la copia local evita una página en blanco */
  }

  // El perfil visual se pide ANTES de construir el grafo, no después.
  //
  // `controlType`, `extraRenderers` y `rendererConfig` son opciones de
  // construcción: si el perfil llega más tarde y no coincide con lo que se usó,
  // hay que destruir la instancia y levantar otra. Eso pasaba en cada carga de
  // página, y además destapaba un fallo del bundle: al destruirse deja vivo un
  // fotograma de `_animationCycle` que `pauseAnimation()` no cancela, y suelta
  // un «Cannot read properties of undefined (reading 'tick')» en la consola.
  //
  // Construyendo ya con el perfil bueno no hay reconstrucción, no hay error, y
  // el arranque se ahorra montar el lienzo dos veces.
  let bootProfile = null;
  try {
    adminPayload = await api.getAppearance();
    bootProfile = adminPayload.appearance;
    ont.applyProfile(bootProfile);
  } catch (error) {
    /* sin perfil, los valores de fábrica del propio JS */
  }

  graph3d.init(el('graph'), {
    onNodeClick: (node, event) => {
      if (event && (event.ctrlKey || event.shiftKey)) {
        const selected = graph3d.toggleMultiSelect(node);
        if (selected.length > 1) inspector.showComparison(selected);
        else if (selected.length === 1) selectNode(selected[0].id, false);
        else inspector.clear();
        return;
      }
      // Doble clic detectado a mano: la librería no expone onNodeDoubleClick.
      const now = Date.now();
      if (lastClick.id === node.id && now - lastClick.at < 380) {
        lastClick = { id: null, at: 0 };
        if (state.profile?.interaction?.expandOnDoubleClick !== false) expandNode(node);
        return;
      }
      lastClick = { id: node.id, at: now };
      selectNode(node.id, true);
    },
    onNodeRightClick: (node, event) => {
      event.preventDefault?.();
      interactions.openNodeMenu(node, event);
    },
    onLinkClick: (link) => selectLink(link),
    onBackgroundClick: () => {
      graph3d.clearSelection();
      inspector.clear();
    },
  }, bootProfile);

  filters.init(() => reload({ fit: false }));

  timeline.init({
    onBrush: (brush) => {
      state.window = brush
        ? { from: new Date(brush.from).toISOString(), to: new Date(brush.to).toISOString() }
        : { from: null, to: null };
      // keepTimeline: el histograma refleja la investigación completa, no el
      // recorte; redibujarlo con el recorte le quitaría el contexto al brush.
      reload({ fit: false, keepTimeline: true });
    },
    onCursor: (cursor, previous) => {
      graph3d.setTimeCursor(cursor);
      // Destello en las aristas que ocurren justo en este instante: el evento
      // "se dispara" a la vista en el momento exacto en que pasó.
      if (cursor !== null && previous !== null) {
        state.graph.links.forEach((link) => {
          if (link.__gdFirst > previous && link.__gdFirst <= cursor) graph3d.pulse(link);
        });
      }
    },
  });

  inspector.init({ onNavigate: (nodeId) => selectNode(nodeId, true) });
  interactions.init(contextActions());

  follow.init({
    onBusy: (busy) => { el('stage-loading').hidden = !busy; },
    onError: (mensaje) => toast(mensaje, 'error', 6000),
    onEnter: (entidad, payload) => {
      const recortado = payload.truncated ? ' (recortado a los mas graves)' : '';
      toast(`Siguiendo a ${entidad.label}: ${payload.total} acciones${recortado}`, 'ok', 4500);
      selectNode(entidad.id, false);
    },
    onExit: () => { if (!auto.activo()) toast('Recorrido terminado', null, 2200); },
    // Cuando termina el recorrido de una entidad, el modo automatico pasa a la
    // siguiente. Sin esto el bucle se quedaria parado en la primera.
    onFinish: () => auto.entidadTerminada(),
    // El log del paso se abre en el inspector, que es donde ya se leen los logs
    // de todo lo demas: no hace falta otro sitio distinto para lo mismo.
    onShowLogs: (paso) => {
      const link = graph3d.linkById(paso.linkId);
      if (link) selectLink(link);
    },
  });

  auto.init({
    onStart: (total) => toast(`Recorrido automático: ${total} entidades en orden cronológico`, 'ok', 4000),
    onStop: () => toast('Recorrido automático detenido', null, 2200),
    onLoop: (vuelta) => toast(`Vuelta ${vuelta} completada`, null, 2600),
    onInterrupted: () => toast('Recorrido detenido: has tomado el control', null, 2600),
    onError: (mensaje) => toast(mensaje, 'error', 5000),
  });
  report.init({
    getSnapshot: () => graph3d.snapshot(),
    getFilters: () => {
      const query = currentQuery();
      return {
        from: query.from, to: query.to, minSeverity: query.minSeverity,
        sources: query.sources, tactics: query.tactics, types: query.types, q: query.q,
      };
    },
    onDone: (message) => toast(message, 'ok'),
    onError: (message) => toast(message, 'error', 8000),
  });

  try {
    // Se le pasa lo ya descargado: pedirlo otra vez sería una llamada de más y,
    // peor, podría traer un perfil distinto del que construyó el grafo.
    const panel = await admin.init({ onApply: applyProfile, payload: adminPayload });
    applyProfile(panel.profile);
  } catch (error) {
    toast(`No se pudo cargar el perfil visual: ${error.message}`, 'error');
  }

  wireTopbar();
  wireDragAndDrop();

  // Los modos de color salen de la ontología del servidor.
  el('color-mode').innerHTML = ont.colorModes()
    .map((mode) => `<option value="${esc(mode.id)}">${esc(mode.label)}</option>`).join('');
  el('color-mode').value = state.colorMode;

  try {
    const info = await api.health();
    if (info.events > 0) await reload();
    else {
      filters.render({ nodes: [], links: [] });
      el('empty-state').style.display = 'flex';
    }
  } catch (error) {
    toast(`No hay backend en /api: ${error.message}`, 'error', 9000);
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}

export { reload, selectNode, state };
