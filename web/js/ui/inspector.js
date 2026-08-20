/* GLAMDRING :: inspector.js — panel derecho.
 *
 * La parte que hace la herramienta defendible: cualquier cosa que se vea en el
 * grafo se puede abrir y contrastar con el log literal del SIEM. Un grafo bonito
 * del que no se puede volver al log original no sirve para un informe.
 */

import * as api from '../api.js';
import * as ont from '../ontology.js';

let emptyBox = null;
let bodyBox = null;
let callbacks = {};

const esc = (value) => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const pad = (n) => (n < 10 ? `0${n}` : String(n));

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ` +
         `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function duration(fromIso, toIso) {
  const a = Date.parse(fromIso);
  const b = Date.parse(toIso);
  if (Number.isNaN(a) || Number.isNaN(b) || b <= a) return null;
  const seconds = Math.round((b - a) / 1000);
  if (seconds < 60) return `${seconds} s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)} min`;
  return `${(seconds / 3600).toFixed(1)} h`;
}

function severityBadge(level) {
  const meta = ont.severity(level);
  return `<span class="sev-badge" style="background:${meta.color}22;color:${meta.color};
          border:1px solid ${meta.color}55">${esc(meta.label)}</span>`;
}

function roleBadge(roleId) {
  const meta = ont.role(roleId);
  return `<span class="sev-badge" title="${esc(meta.hint || '')}"
          style="background:${meta.color}22;color:${meta.color};
          border:1px solid ${meta.color}55">${esc(meta.label)}</span>`;
}

function kv(pairs) {
  const rows = pairs.filter(([, value]) => value !== undefined && value !== null && value !== '');
  if (!rows.length) return '';
  return `<dl class="kv">${rows
    .map(([key, value]) => `<dt>${esc(key)}</dt><dd>${esc(value)}</dd>`)
    .join('')}</dl>`;
}

/* Los logs crudos se cargan bajo demanda: un nodo puede tener 200 uids y
   traerlos siempre haría el panel lento sin motivo. */
async function loadRawEvents(params, targetId) {
  const target = document.getElementById(targetId);
  if (!target) return;
  target.innerHTML = '<div class="count">cargando logs…</div>';

  try {
    const payload = await api.events(params);
    if (!payload.events.length) {
      target.innerHTML = '<div class="count">sin logs asociados</div>';
      return;
    }
    target.innerHTML = payload.events.map((event) => {
      const src = ont.source(event.source);
      return `<details class="raw-event">
        <summary>
          <span class="t">${esc(fmtDate(event.time))}</span>
          <span class="src-dot" style="background:${src.color}"></span>
          <span class="m">${esc(event.message || event.activity)}</span>
        </summary>
        <pre>${esc(JSON.stringify(event.raw, null, 2))}</pre>
      </details>`;
    }).join('');
  } catch (error) {
    target.innerHTML = `<div class="count" style="color:#fb7185">${esc(error.message)}</div>`;
  }
}

export function init(handlers) {
  callbacks = handlers || {};
  emptyBox = document.getElementById('inspector-empty');
  bodyBox = document.getElementById('inspector-body');
  return { showNode, showLink, showComparison, clear };
}

export function clear() {
  emptyBox.hidden = false;
  bodyBox.hidden = true;
  bodyBox.innerHTML = '';
}

export function showNode(node, neighbors) {
  const meta = ont.entity(node.type);
  const props = node.props || {};
  const roleId = props.role || 'neutral';
  emptyBox.hidden = true;
  bodyBox.hidden = false;

  const hidden = new Set(['eventUids', 'level', 'role', 'model', 'cluster', 'external',
                          'touchedByAlert']);
  const propRows = Object.keys(props)
    .filter((key) => !hidden.has(key))
    .map((key) => [key, props[key]]);

  let html = `
    <div class="insp-head">
      <div class="insp-kind"><span class="dot" style="background:${meta.color}"></span>
        ${esc(meta.label)}</div>
      <h1 class="insp-title">${esc(node.label)}</h1>
      <div class="insp-sub">${esc(node.id)}</div>
      <div class="insp-badges">${roleBadge(roleId)} ${severityBadge(node.maxSeverity)}</div>
    </div>

    <div class="insp-metrics">
      <div class="insp-metric"><div class="k">Riesgo</div>
        <div class="v" style="color:${ont.severity(node.maxSeverity).color}">${node.risk || 0}</div></div>
      <div class="insp-metric"><div class="k">Eventos</div><div class="v">${node.eventCount || 0}</div></div>
      <div class="insp-metric"><div class="k">Conexiones</div><div class="v">${node.degree || 0}</div></div>
    </div>

    <div class="insp-section"><h3>Ventana temporal</h3>
      ${kv([
        ['Primera vez', fmtDate(node.firstSeen)],
        ['Última vez', fmtDate(node.lastSeen)],
        ['Duración', duration(node.firstSeen, node.lastSeen)],
      ])}
    </div>`;

  if ((node.tactics || []).length) {
    html += `<div class="insp-section"><h3>Tácticas MITRE</h3><div class="pill-row">
      ${node.tactics.map((t) => `<span class="pill tactic">${esc(ont.tacticLabel(t))}</span>`).join('')}
    </div></div>`;
  }

  if ((node.sources || []).length) {
    html += `<div class="insp-section"><h3>Visto en</h3><div class="pill-row">
      ${node.sources.map((s) => {
        const src = ont.source(s);
        return `<span class="pill" style="border-color:${src.color}55;color:${src.color}">
          ${esc(src.label)}</span>`;
      }).join('')}
    </div></div>`;
  }

  if (propRows.length) {
    html += `<div class="insp-section"><h3>Propiedades</h3>${kv(propRows)}</div>`;
  }

  if (neighbors && neighbors.length) {
    html += `<div class="insp-section"><h3>Relaciones (${neighbors.length})</h3>`;
    neighbors.slice(0, 40).forEach(({ node: other, link }) => {
      const otherMeta = ont.entity(other.type);
      const relMeta = ont.relation(link.type);
      html += `<div class="neighbor" data-node="${esc(other.id)}">
        <span class="dot" style="background:${otherMeta.color}"></span>
        <span class="name">${esc(other.label)}</span>
        <span class="rel" style="color:${relMeta.color}">${esc(relMeta.label)}</span>
        <span class="rel">×${link.count || 1}</span>
      </div>`;
    });
    if (neighbors.length > 40) {
      html += `<div class="count">… y ${neighbors.length - 40} más</div>`;
    }
    html += '</div>';
  }

  html += `<div class="insp-section"><h3>Logs originales del SIEM</h3>
    <div id="raw-events"></div></div>`;

  bodyBox.innerHTML = html;
  bodyBox.scrollTop = 0;

  bodyBox.querySelectorAll('.neighbor').forEach((row) => {
    row.addEventListener('click', () => callbacks.onNavigate?.(row.getAttribute('data-node')));
  });

  loadRawEvents({ node: node.id, limit: 60 }, 'raw-events');
}

export function showLink(link, sourceNode, targetNode) {
  const meta = ont.relation(link.type);
  const sourceMeta = ont.entity(sourceNode ? sourceNode.type : '');
  const targetMeta = ont.entity(targetNode ? targetNode.type : '');
  emptyBox.hidden = true;
  bodyBox.hidden = false;

  const propRows = Object.entries(link.props || {});

  bodyBox.innerHTML = `
    <div class="insp-head">
      <div class="insp-kind"><span class="dot" style="background:${meta.color}"></span>Relación</div>
      <h1 class="insp-title insp-relation">
        <span style="color:${sourceMeta.color}">${esc(sourceNode ? sourceNode.label : link.source)}</span>
        <span style="color:${meta.color}"> — ${esc(meta.label)} → </span>
        <span style="color:${targetMeta.color}">${esc(targetNode ? targetNode.label : link.target)}</span>
      </h1>
      <div class="insp-badges">${severityBadge(link.severity)}
        ${meta.dashed ? '<span class="pill">relación inferida</span>' : ''}</div>
    </div>

    <div class="insp-metrics">
      <div class="insp-metric"><div class="k">Eventos</div><div class="v">${link.count || 1}</div></div>
      <div class="insp-metric"><div class="k">Severidad</div>
        <div class="v" style="color:${ont.severity(link.severity).color}">${link.severity || 0}</div></div>
      <div class="insp-metric"><div class="k">Duración</div>
        <div class="v sm">${duration(link.firstSeen, link.lastSeen) || '—'}</div></div>
    </div>

    <div class="insp-section"><h3>Ventana temporal</h3>
      ${kv([['Primera vez', fmtDate(link.firstSeen)], ['Última vez', fmtDate(link.lastSeen)]])}
    </div>
    ${propRows.length ? `<div class="insp-section"><h3>Detalles</h3>${kv(propRows)}</div>` : ''}

    <div class="insp-section"><h3>Logs originales del SIEM</h3>
      <div class="count" style="margin-bottom:8px">
        ${(link.eventUids || []).length} evento(s) generaron esta arista</div>
      <div id="raw-events"></div>
    </div>`;

  bodyBox.scrollTop = 0;
  loadRawEvents({ uids: (link.eventUids || []).slice(0, 60), limit: 60 }, 'raw-events');
}

/* Comparación de varios nodos seleccionados con ctrl+click. Sirve para
   responder "¿qué tienen en común estas tres máquinas?" sin abrirlas una a una. */
export function showComparison(nodes) {
  emptyBox.hidden = true;
  bodyBox.hidden = false;

  const common = nodes.reduce((acc, node) => {
    const tactics = new Set(node.tactics || []);
    return acc === null ? tactics : new Set([...acc].filter((t) => tactics.has(t)));
  }, null) || new Set();

  bodyBox.innerHTML = `
    <div class="insp-head">
      <div class="insp-kind"><span class="dot" style="background:#2dd4bf"></span>Comparación</div>
      <h1 class="insp-title">${nodes.length} entidades seleccionadas</h1>
    </div>
    <div class="insp-section">
      <h3>Tácticas en común</h3>
      ${common.size
        ? `<div class="pill-row">${[...common]
            .map((t) => `<span class="pill tactic">${esc(ont.tacticLabel(t))}</span>`).join('')}</div>`
        : '<div class="count">ninguna en común</div>'}
    </div>
    <div class="insp-section"><h3>Entidades</h3>
      ${nodes.map((node) => {
        const meta = ont.entity(node.type);
        return `<div class="neighbor" data-node="${esc(node.id)}">
          <span class="dot" style="background:${meta.color}"></span>
          <span class="name">${esc(node.label)}</span>
          <span class="rel">riesgo ${node.risk || 0}</span>
        </div>`;
      }).join('')}
    </div>`;

  bodyBox.querySelectorAll('.neighbor').forEach((row) => {
    row.addEventListener('click', () => callbacks.onNavigate?.(row.getAttribute('data-node')));
  });
}
