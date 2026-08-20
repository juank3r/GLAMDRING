/* GLAMDRING :: admin.js — el panel del sysadmin.
 *
 * Los controles NO están escritos a mano uno por uno: se generan a partir del
 * `spec` que manda el servidor con cada sección, su tipo y su rango. Así, añadir
 * un ajuste nuevo es tocar `appearance.py` y aparece aquí solo, con sus límites
 * correctos y sin posibilidad de que el rango del slider y el del validador se
 * desincronicen.
 *
 * Los cambios se aplican al vuelo en el grafo y se guardan en el servidor con un
 * retardo, para no escribir el fichero en cada píxel que se arrastra.
 */

import * as api from '../api.js';
import * as ont from '../ontology.js';
import { availableModels } from '../render/models.js';

const LABELS = {
  theme: 'Tema', render: 'Render', physics: 'Física', labels: 'Etiquetas',
  links: 'Aristas', camera: 'Cámara', interaction: 'Interacción',
};

const FIELD_LABELS = {
  preset: 'Preajuste', background: 'Fondo', panel: 'Paneles', panelAlt: 'Paneles (alt.)',
  border: 'Bordes', text: 'Texto', textDim: 'Texto atenuado', accent: 'Acento',
  fontScale: 'Escala de fuente',
  modelQuality: 'Calidad de figuras', nodeResolution: 'Detalle de nodos',
  linkResolution: 'Detalle de aristas', nodeOpacity: 'Opacidad de nodos',
  linkOpacity: 'Opacidad de aristas', bloom: 'Resplandor (bloom)',
  bloomStrength: 'Intensidad del resplandor', bloomRadius: 'Radio del resplandor',
  bloomThreshold: 'Umbral del resplandor', fog: 'Niebla de profundidad',
  fogDensity: 'Densidad de niebla', grid: 'Rejilla de suelo',
  enablePointerInteraction: 'Interacción con el ratón',
  linkHoverPrecision: 'Precisión al señalar aristas', showNavInfo: 'Ayuda de navegación',
  heavyThreshold: 'Umbral de grafo pesado',
  forceEngine: 'Motor de fuerzas', numDimensions: 'Dimensiones',
  chargeStrength: 'Repulsión entre nodos', linkDistance: 'Longitud de arista',
  collide: 'Evitar solapes', collideRadius: 'Margen de separación',
  d3AlphaDecay: 'Enfriado de la simulación', d3VelocityDecay: 'Rozamiento',
  warmupTicks: 'Ticks de calentamiento', cooldownTicks: 'Ticks hasta parar',
  dagMode: 'Modo DAG (kill-chain)', dagLevelDistance: 'Separación entre capas DAG',
  layerSpacing: 'Separación entre capas',
  nodeMode: 'Etiquetas de nodo', nodeRiskThreshold: 'Riesgo mínimo para rotular',
  nodeSize: 'Tamaño de etiqueta', linkMode: 'Etiquetas de arista',
  linkBusyThreshold: 'Eventos para rotular arista', linkSize: 'Tamaño de texto en aristas',
  renderer: 'Motor de etiquetas',
  particles: 'Partículas de flujo', particleDensity: 'Densidad de partículas',
  particleSpeed: 'Velocidad de partículas', particleWidth: 'Grosor de partículas',
  arrows: 'Flechas de sentido', arrowLength: 'Tamaño de flecha',
  gradient: 'Degradado en aristas', dashed: 'Trazo discontinuo si es inferida',
  curvature: 'Curvatura de multiaristas', widthScale: 'Escala de grosor',
  controlType: 'Tipo de control', autoOrbit: 'Órbita automática',
  orbitSpeed: 'Velocidad de órbita', focusDistance: 'Distancia de enfoque',
  transitionMs: 'Duración de transiciones',
  dimOnSelect: 'Atenuar el resto al seleccionar', dimOpacity: 'Opacidad al atenuar',
  hoverHighlight: 'Resaltar al pasar por encima', fixOnDrag: 'Fijar al arrastrar',
  expandOnDoubleClick: 'Expandir con doble clic',
};

const ENUM_LABELS = {
  'soc-dark': 'SOC oscuro', matrix: 'Matrix', contrast: 'Alto contraste', paper: 'Claro (informes)',
  auto: 'Automática', high: 'Alta', medium: 'Media', low: 'Baja',
  d3: 'd3-force', ngraph: 'ngraph',
  '': 'desactivado', td: 'arriba→abajo', bu: 'abajo→arriba', lr: 'izq→der',
  rl: 'der→izq', zout: 'hacia fuera', zin: 'hacia dentro',
  radialout: 'radial hacia fuera', radialin: 'radial hacia dentro',
  never: 'nunca', hover: 'al señalar', selection: 'en la selección',
  smart: 'inteligente', always: 'siempre', busy: 'solo las concurridas',
  sprite: 'sprite 3D', css2d: 'HTML (CSS2D)',
  trackball: 'trackball', orbit: 'órbita', fly: 'vuelo libre',
};

/* Preajustes de tema. El sysadmin elige uno y luego afina lo que quiera. */
const THEME_PRESETS = {
  'soc-dark': { background: '#070a10', panel: '#0d121c', panelAlt: '#121927',
                border: '#1d2635', text: '#dce4f0', textDim: '#8b98ad', accent: '#2dd4bf' },
  matrix: { background: '#000a04', panel: '#04140a', panelAlt: '#061d0f',
            border: '#0d3b1e', text: '#b9f6ca', textDim: '#4caf7d', accent: '#00e676' },
  contrast: { background: '#000000', panel: '#0a0a0a', panelAlt: '#141414',
              border: '#3a3a3a', text: '#ffffff', textDim: '#c8c8c8', accent: '#ffd400' },
  paper: { background: '#eef1f6', panel: '#ffffff', panelAlt: '#f4f6fa',
           border: '#d3dae5', text: '#16202f', textDim: '#5b6880', accent: '#0f766e' },
};

let profile = null;
let spec = null;
let defaults = null;
let onApply = () => {};
let saveTimer = null;
let panel = null;
let activeTab = 'theme';

const esc = (value) => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const fieldLabel = (key) => FIELD_LABELS[key] || key;
const enumLabel = (value) => ENUM_LABELS[value] ?? String(value);

/* ------------------------------------------------------------ persistencia */

/* Cambios acumulados a la espera de mandarse. */
let pending = {};

function scheduleSave(patch) {
  // Se acumulan los cambios y se manda uno solo: arrastrar un slider dispara
  // decenas de eventos y no tiene sentido escribir el fichero en cada uno.
  pending = deepMerge(pending, patch);
  clearTimeout(saveTimer);
  saveTimer = setTimeout(async () => {
    const body = pending;
    pending = {};
    try {
      const result = await api.putAppearance(body);
      profile = result.appearance;
      if (result.rejected.length) {
        setStatus(`Descartado: ${result.rejected.join(', ')}`, true);
      } else {
        setStatus('Guardado en el servidor');
      }
    } catch (error) {
      setStatus(`No se pudo guardar: ${error.message}`, true);
    }
  }, 450);
}


function deepMerge(base, patch) {
  const out = { ...base };
  Object.entries(patch).forEach(([key, value]) => {
    if (value && typeof value === 'object' && !Array.isArray(value)
        && out[key] && typeof out[key] === 'object') {
      out[key] = deepMerge(out[key], value);
    } else {
      out[key] = value;
    }
  });
  return out;
}

function setStatus(text, isError = false) {
  const status = panel.querySelector('.admin-status');
  if (!status) return;
  status.textContent = text;
  status.classList.toggle('error', isError);
  clearTimeout(status.__timer);
  status.__timer = setTimeout(() => { status.textContent = ''; }, 3200);
}

function change(section, key, value) {
  profile[section] = profile[section] || {};
  profile[section][key] = value;
  onApply(profile);
  scheduleSave({ [section]: { [key]: value } });
}

/* --------------------------------------------------------------- controles */

function control(section, key, rule, value) {
  const [kind] = rule;
  const row = document.createElement('label');
  row.className = 'admin-row';

  const name = document.createElement('span');
  name.className = 'admin-label';
  name.textContent = fieldLabel(key);
  row.appendChild(name);

  if (kind === 'bool') {
    const input = document.createElement('input');
    input.type = 'checkbox';
    input.checked = Boolean(value);
    input.addEventListener('change', () => change(section, key, input.checked));
    row.appendChild(input);
    row.classList.add('is-bool');
    return row;
  }

  if (kind === 'color') {
    const wrap = document.createElement('span');
    wrap.className = 'admin-color';
    const input = document.createElement('input');
    input.type = 'color';
    input.value = /^#[0-9a-f]{6}$/i.test(value || '') ? value : '#000000';
    const hex = document.createElement('input');
    hex.type = 'text';
    hex.className = 'admin-hex';
    hex.value = value || '';
    const push = (next) => {
      hex.value = next;
      input.value = next;
      change(section, key, next);
    };
    input.addEventListener('input', () => push(input.value));
    hex.addEventListener('change', () => {
      if (/^#[0-9a-f]{3,8}$/i.test(hex.value)) push(hex.value);
    });
    wrap.append(input, hex);
    row.appendChild(wrap);
    return row;
  }

  if (kind === 'enum') {
    const select = document.createElement('select');
    rule[1].forEach((option) => {
      const item = document.createElement('option');
      item.value = option;
      item.textContent = enumLabel(option);
      if (String(option) === String(value)) item.selected = true;
      select.appendChild(item);
    });
    select.addEventListener('change', () => {
      change(section, key, select.value);
      // Cambiar de preajuste reescribe toda la paleta de golpe.
      if (section === 'theme' && key === 'preset') applyThemePreset(select.value);
    });
    row.appendChild(select);
    return row;
  }

  // number | int
  const [, min, max] = rule;
  const wrap = document.createElement('span');
  wrap.className = 'admin-slider';
  const input = document.createElement('input');
  input.type = 'range';
  input.min = min;
  input.max = max;
  input.step = kind === 'int' ? 1 : Math.max((max - min) / 200, 0.0001);
  input.value = value;
  const readout = document.createElement('output');
  readout.textContent = value;
  input.addEventListener('input', () => {
    const next = kind === 'int' ? parseInt(input.value, 10) : parseFloat(input.value);
    readout.textContent = kind === 'int' ? next : Number(next.toFixed(4));
    change(section, key, next);
  });
  wrap.append(input, readout);
  row.appendChild(wrap);
  return row;
}

function applyThemePreset(name) {
  const preset = THEME_PRESETS[name];
  if (!preset) return;
  profile.theme = { ...profile.theme, ...preset, preset: name };
  onApply(profile);
  scheduleSave({ theme: { ...preset, preset: name } });
  renderTab();   // los selectores de color tienen que reflejar la paleta nueva
}

/* ------------------------------------------------------------- pestañas */

function sectionTab(section) {
  const box = document.createElement('div');
  const rules = spec.sections[section] || {};
  Object.entries(rules).forEach(([key, rule]) => {
    const value = (profile[section] || {})[key];
    box.appendChild(control(section, key, rule, value));
  });
  return box;
}

function ontologyTab() {
  const box = document.createElement('div');
  const models = availableModels();

  const intro = document.createElement('p');
  intro.className = 'admin-hint';
  intro.textContent = 'Color, figura y visibilidad de cada tipo. Lo que se cambie aquí '
    + 'manda sobre la ontología del servidor.';
  box.appendChild(intro);

  ont.entityTypes().forEach((type) => {
    const meta = ont.entity(type);
    const row = document.createElement('div');
    row.className = 'admin-entity';
    row.innerHTML = `<span class="admin-entity-name">
      <span class="dot" style="background:${meta.color}"></span>${esc(meta.label)}</span>`;

    const color = document.createElement('input');
    color.type = 'color';
    color.value = /^#[0-9a-f]{6}$/i.test(meta.color) ? meta.color : '#888888';
    color.addEventListener('input', () => patchEntity(type, { color: color.value }));

    const model = document.createElement('select');
    models.forEach((name) => {
      const item = document.createElement('option');
      item.value = name;
      item.textContent = name;
      if (name === meta.model) item.selected = true;
      model.appendChild(item);
    });
    model.addEventListener('change', () => patchEntity(type, { model: model.value }));

    const scale = document.createElement('input');
    scale.type = 'range';
    scale.min = 0.4; scale.max = 2.5; scale.step = 0.05;
    scale.value = meta.scale || 1;
    scale.title = 'Escala';
    scale.addEventListener('input', () => patchEntity(type, { scale: parseFloat(scale.value) }));

    const visible = document.createElement('input');
    visible.type = 'checkbox';
    visible.checked = meta.visible !== false;
    visible.title = 'Visible';
    visible.addEventListener('change', () => patchEntity(type, { visible: visible.checked }));

    row.append(color, model, scale, visible);
    box.appendChild(row);
  });

  const relTitle = document.createElement('h4');
  relTitle.className = 'admin-subtitle';
  relTitle.textContent = 'Relaciones';
  box.appendChild(relTitle);

  ont.relationTypes().forEach((type) => {
    const meta = ont.relation(type);
    const row = document.createElement('div');
    row.className = 'admin-entity';
    row.innerHTML = `<span class="admin-entity-name">
      <span class="dot" style="background:${meta.color}"></span>${esc(meta.label)}</span>`;

    const color = document.createElement('input');
    color.type = 'color';
    color.value = /^#[0-9a-f]{6}$/i.test(meta.color) ? meta.color : '#888888';
    color.addEventListener('input', () => patchRelation(type, { color: color.value }));

    const dashed = document.createElement('input');
    dashed.type = 'checkbox';
    dashed.checked = Boolean(meta.dashed);
    dashed.title = 'Trazo discontinuo (relación inferida)';
    dashed.addEventListener('change', () => patchRelation(type, { dashed: dashed.checked }));

    const visible = document.createElement('input');
    visible.type = 'checkbox';
    visible.checked = meta.visible !== false;
    visible.title = 'Visible';
    visible.addEventListener('change', () => patchRelation(type, { visible: visible.checked }));

    row.append(color, dashed, visible);
    box.appendChild(row);
  });

  return box;
}

function patchEntity(type, patch) {
  profile.entities = profile.entities || {};
  profile.entities[type] = { ...(profile.entities[type] || {}), ...patch };
  onApply(profile);
  scheduleSave({ entities: { [type]: patch } });
}

function patchRelation(type, patch) {
  profile.relations = profile.relations || {};
  profile.relations[type] = { ...(profile.relations[type] || {}), ...patch };
  onApply(profile);
  scheduleSave({ relations: { [type]: patch } });
}

function rulesTab() {
  const box = document.createElement('div');
  const intro = document.createElement('p');
  intro.className = 'admin-hint';
  intro.textContent = 'Pesos de la puntuación de riesgo. Deciden el orden en que el '
    + 'analista mira las cosas y, con ello, el tamaño de cada figura.';
  box.appendChild(intro);

  const weights = profile.riskWeights || {};
  Object.keys(defaults.riskWeights || {}).forEach((key) => {
    const row = document.createElement('label');
    row.className = 'admin-row';
    row.innerHTML = `<span class="admin-label">${esc(key)}</span>`;
    const wrap = document.createElement('span');
    wrap.className = 'admin-slider';
    const input = document.createElement('input');
    input.type = 'range';
    input.min = 0; input.max = 60; input.step = 1;
    input.value = weights[key] ?? defaults.riskWeights[key];
    const readout = document.createElement('output');
    readout.textContent = input.value;
    input.addEventListener('input', () => {
      readout.textContent = input.value;
      profile.riskWeights = { ...(profile.riskWeights || {}), [key]: parseInt(input.value, 10) };
      scheduleSave({ riskWeights: { [key]: parseInt(input.value, 10) } });
    });
    wrap.append(input, readout);
    row.appendChild(wrap);
    box.appendChild(row);
  });

  const note = document.createElement('p');
  note.className = 'admin-hint';
  note.textContent = 'Los pesos se aplican al recargar el grafo.';
  box.appendChild(note);
  return box;
}

function profileTab() {
  const box = document.createElement('div');

  const buttons = document.createElement('div');
  buttons.className = 'admin-actions';

  const exportBtn = document.createElement('button');
  exportBtn.className = 'btn';
  exportBtn.textContent = 'Exportar perfil';
  exportBtn.addEventListener('click', () => {
    const blob = new Blob([JSON.stringify(profile, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement('a');
    anchor.href = url;
    anchor.download = 'glamdring-perfil.json';
    anchor.click();
    setTimeout(() => URL.revokeObjectURL(url), 3000);
  });

  const importBtn = document.createElement('button');
  importBtn.className = 'btn';
  importBtn.textContent = 'Importar perfil';
  const importInput = document.createElement('input');
  importInput.type = 'file';
  importInput.accept = '.json';
  importInput.hidden = true;
  importBtn.addEventListener('click', () => importInput.click());
  importInput.addEventListener('change', async () => {
    const file = importInput.files[0];
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      const result = await api.putAppearance(parsed);
      profile = result.appearance;
      onApply(profile);
      renderTab();
      setStatus(result.rejected.length
        ? `Importado, descartando: ${result.rejected.slice(0, 4).join(', ')}`
        : 'Perfil importado');
    } catch (error) {
      setStatus(`No se pudo importar: ${error.message}`, true);
    }
    importInput.value = '';
  });

  const resetBtn = document.createElement('button');
  resetBtn.className = 'btn btn-danger';
  resetBtn.textContent = 'Restablecer de fábrica';
  resetBtn.addEventListener('click', async () => {
    const result = await api.resetAppearance();
    profile = result.appearance;
    onApply(profile);
    renderTab();
    setStatus('Perfil restablecido');
  });

  buttons.append(exportBtn, importBtn, importInput, resetBtn);
  box.appendChild(buttons);

  const modelsTitle = document.createElement('h4');
  modelsTitle.className = 'admin-subtitle';
  modelsTitle.textContent = 'Modelos 3D propios (.glb)';
  box.appendChild(modelsTitle);

  const hint = document.createElement('p');
  hint.className = 'admin-hint';
  hint.textContent = 'Sustituye una figura procedural por un modelo propio. Se escala '
    + 'automáticamente para que no descuadre el grafo.';
  box.appendChild(hint);

  availableModels().forEach((name) => {
    const row = document.createElement('div');
    row.className = 'admin-entity';
    const installed = (profile.models || {})[name];
    row.innerHTML = `<span class="admin-entity-name">${esc(name)}
      ${installed ? '<em class="admin-tag">personalizado</em>' : ''}</span>`;

    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.glb';
    input.hidden = true;
    const upload = document.createElement('button');
    upload.className = 'btn btn-sm';
    upload.textContent = installed ? 'Reemplazar' : 'Subir .glb';
    upload.addEventListener('click', () => input.click());
    input.addEventListener('change', async () => {
      const file = input.files[0];
      if (!file) return;
      try {
        const result = await api.uploadModel(name, file);
        profile = result.appearance;
        onApply(profile);
        renderTab();
        setStatus(`Modelo '${name}' actualizado`);
      } catch (error) {
        setStatus(error.message, true);
      }
      input.value = '';
    });
    row.append(input, upload);

    if (installed) {
      const remove = document.createElement('button');
      remove.className = 'btn btn-sm btn-danger';
      remove.textContent = 'Quitar';
      remove.addEventListener('click', async () => {
        const result = await api.deleteModel(name);
        profile = result.appearance;
        onApply(profile);
        renderTab();
        setStatus(`Modelo '${name}' eliminado`);
      });
      row.append(remove);
    }
    box.appendChild(row);
  });

  return box;
}

const TABS = [
  ...Object.keys(LABELS).map((id) => ({ id, label: LABELS[id], build: () => sectionTab(id) })),
  { id: 'ontology', label: 'Ontología', build: ontologyTab },
  { id: 'rules', label: 'Reglas', build: rulesTab },
  { id: 'profile', label: 'Perfil', build: profileTab },
];

function renderTabs() {
  const bar = panel.querySelector('.admin-tabs');
  bar.innerHTML = '';
  TABS.forEach((tab) => {
    const button = document.createElement('button');
    button.className = `admin-tab${tab.id === activeTab ? ' is-active' : ''}`;
    button.textContent = tab.label;
    button.addEventListener('click', () => {
      activeTab = tab.id;
      renderTabs();
      renderTab();
    });
    bar.appendChild(button);
  });
}

function renderTab() {
  const body = panel.querySelector('.admin-body');
  body.innerHTML = '';
  const tab = TABS.find((item) => item.id === activeTab) || TABS[0];
  body.appendChild(tab.build());
}

/* -------------------------------------------------------------------- API */

export function isOpen() {
  return panel && !panel.hidden;
}

export function toggle(force) {
  if (!panel) return;
  panel.hidden = force === undefined ? !panel.hidden : !force;
  if (!panel.hidden) {
    renderTabs();
    renderTab();
  }
}

export async function init(handlers) {
  panel = document.getElementById('admin-panel');
  onApply = handlers.onApply || (() => {});

  const payload = await api.getAppearance();
  profile = payload.appearance;
  defaults = payload.defaults;
  spec = payload.spec;

  panel.querySelector('.admin-close').addEventListener('click', () => toggle(false));
  document.getElementById('btn-admin').addEventListener('click', () => toggle());

  return { profile, toggle, isOpen, current: () => profile };
}

export const current = () => profile;
