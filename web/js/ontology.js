/* GLAMDRING :: ontology.js — copia cliente de la ontología.
 *
 * Existe por dos razones: la página se dibuja antes de que responda
 * /api/ontology y sin colores no hay nada que pintar, y sirve de contrato para
 * saber qué campos esperar. La fuente de verdad es glamdring/graph/ontology.py,
 * y `adopt()` sobrescribe esta copia con lo que diga el servidor.
 *
 * Encima de la ontología se aplica el perfil visual del equipo (`applyProfile`),
 * que es lo que el sysadmin toca desde el panel. El orden importa: ontología
 * primero, perfil después, para que el perfil siempre gane.
 */

const FALLBACK = {
  entities: {
    alert:    { label: 'Alerta',       color: '#ff2d55', model: 'alert',       shape: 'octahedron',  glyph: '🚨', rank: 0, size: 9 },
    user:     { label: 'Usuario',      color: '#4ea8ff', model: 'person',      shape: 'sphere',      glyph: '👤', rank: 1, size: 7 },
    host:     { label: 'Host',         color: '#4ade80', model: 'workstation', shape: 'box',         glyph: '🖥', rank: 2, size: 8 },
    process:  { label: 'Proceso',      color: '#fb923c', model: 'gear',        shape: 'cone',        glyph: '⚙', rank: 3, size: 5 },
    file:     { label: 'Fichero',      color: '#d4a5ff', model: 'document',    shape: 'cylinder',    glyph: '📄', rank: 4, size: 4 },
    ip:       { label: 'IP',           color: '#2dd4bf', model: 'endpoint',    shape: 'icosahedron', glyph: '🌐', rank: 5, size: 5 },
    domain:   { label: 'Dominio',      color: '#818cf8', model: 'globe',       shape: 'torus',       glyph: '🔗', rank: 5, size: 5 },
    url:      { label: 'URL',          color: '#a78bfa', model: 'globe',       shape: 'torus',       glyph: '🔗', rank: 5, size: 4 },
    hash:     { label: 'Hash',         color: '#94a3b8', model: 'hashcube',    shape: 'tetrahedron', glyph: '#',  rank: 6, size: 4 },
    mailbox:  { label: 'Buzón',        color: '#f472b6', model: 'envelope',    shape: 'sphere',      glyph: '✉', rank: 2, size: 5 },
    account:  { label: 'Cuenta cloud', color: '#22d3ee', model: 'cloud',       shape: 'box',         glyph: '☁', rank: 2, size: 6 },
    service:  { label: 'Servicio',     color: '#a3e635', model: 'gear',        shape: 'cylinder',    glyph: '⚭', rank: 4, size: 4 },
    registry: { label: 'Registro',     color: '#eab308', model: 'key',         shape: 'box',         glyph: '🗝', rank: 4, size: 4 },
  },
  unknownEntity: { label: 'Otro', color: '#78909c', model: 'endpoint', shape: 'sphere', glyph: '?', rank: 9, size: 4 },

  relations: {
    authenticated: { label: 'autentica en',    color: '#4ea8ff', dashed: false, weight: 3 },
    failed_auth:   { label: 'fallo login en',  color: '#fb7185', dashed: true,  weight: 2 },
    executed:      { label: 'ejecuta',         color: '#fb923c', dashed: false, weight: 3 },
    spawned:       { label: 'lanza',           color: '#fbbf24', dashed: false, weight: 4 },
    ran_on:        { label: 'corre en',        color: '#4ade80', dashed: true,  weight: 1 },
    connected:     { label: 'conecta con',     color: '#2dd4bf', dashed: false, weight: 3 },
    blocked:       { label: 'bloqueado hacia', color: '#78716c', dashed: true,  weight: 1 },
    resolved:      { label: 'resuelve a',      color: '#818cf8', dashed: true,  weight: 1 },
    wrote:         { label: 'escribe',         color: '#d4a5ff', dashed: false, weight: 2 },
    read:          { label: 'lee',             color: '#a78bfa', dashed: true,  weight: 1 },
    deleted:       { label: 'borra',           color: '#ef4444', dashed: false, weight: 2 },
    has_hash:      { label: 'hash',            color: '#94a3b8', dashed: true,  weight: 1 },
    triggered:     { label: 'dispara',         color: '#ff2d55', dashed: false, weight: 5 },
    affects:       { label: 'afecta a',        color: '#f43f5e', dashed: false, weight: 5 },
    owns:          { label: 'posee',           color: '#f472b6', dashed: true,  weight: 1 },
    lateral:       { label: 'movimiento lat.', color: '#f97316', dashed: false, weight: 5 },
    persisted:     { label: 'persiste en',     color: '#eab308', dashed: false, weight: 4 },
    downloaded:    { label: 'descarga',        color: '#06b6d4', dashed: false, weight: 3 },
    sent_to:       { label: 'envía a',         color: '#f472b6', dashed: false, weight: 2 },
    contains_url:  { label: 'contiene URL',    color: '#a78bfa', dashed: true,  weight: 2 },
  },
  unknownRelation: { label: 'relacionado', color: '#64748b', dashed: true, weight: 1 },

  roles: {
    hostile:    { label: 'Hostil',      color: '#ff2d55', emissive: 0.75, hint: 'Infraestructura del atacante' },
    victim:     { label: 'Víctima',     color: '#fb923c', emissive: 0.55, hint: 'Entidad propia con impacto confirmado' },
    suspicious: { label: 'Sospechosa',  color: '#eab308', emissive: 0.40, hint: 'Entidad propia con indicios' },
    asset:      { label: 'Activo sano', color: '#4ade80', emissive: 0.18, hint: 'Entidad propia sin hallazgos' },
    neutral:    { label: 'Contexto',    color: '#94a3b8', emissive: 0.12, hint: 'Artefacto forense de apoyo' },
  },

  severity: [
    { id: 0, key: 'unknown',  label: 'Desconocida', color: '#64748b' },
    { id: 1, key: 'info',     label: 'Informativa', color: '#38bdf8' },
    { id: 2, key: 'low',      label: 'Baja',        color: '#4ade80' },
    { id: 3, key: 'medium',   label: 'Media',       color: '#fbbf24' },
    { id: 4, key: 'high',     label: 'Alta',        color: '#f97316' },
    { id: 5, key: 'critical', label: 'Crítica',     color: '#ff2d55' },
  ],

  tactics: [
    'reconnaissance', 'resource-development', 'initial-access', 'execution',
    'persistence', 'privilege-escalation', 'defense-evasion', 'credential-access',
    'discovery', 'lateral-movement', 'collection', 'command-and-control',
    'exfiltration', 'impact',
  ],
  tacticLabels: {},
  sources: {
    splunk:   { label: 'Splunk',             color: '#65a637' },
    sentinel: { label: 'Microsoft Sentinel', color: '#0078d4' },
    qradar:   { label: 'IBM QRadar',         color: '#1f70c1' },
    elastic:  { label: 'Elastic',            color: '#f04e98' },
    generic:  { label: 'Genérico',           color: '#94a3b8' },
  },
  colorModes: [{ id: 'type', label: 'Tipo de entidad' }],
  riskRamp: ['#4ade80', '#a3e635', '#fbbf24', '#f97316', '#ff2d55'],
  clusterPalette: ['#4ea8ff', '#fb923c', '#4ade80', '#f472b6', '#a78bfa',
                   '#2dd4bf', '#eab308', '#f43f5e', '#818cf8', '#a3e635'],
};

/* Ontología servida por el backend, sin tocar. */
let base = structuredClone(FALLBACK);
/* Ontología con el perfil visual del equipo aplicado encima. Es la que se usa. */
let live = structuredClone(FALLBACK);
let profileOverrides = { entities: {}, relations: {} };

function rebuild() {
  live = structuredClone(base);
  Object.entries(profileOverrides.entities || {}).forEach(([name, patch]) => {
    if (live.entities[name]) Object.assign(live.entities[name], patch);
  });
  Object.entries(profileOverrides.relations || {}).forEach(([name, patch]) => {
    if (live.relations[name]) Object.assign(live.relations[name], patch);
  });
}

export function adopt(payload) {
  if (payload && typeof payload === 'object') {
    base = { ...structuredClone(FALLBACK), ...structuredClone(payload) };
    rebuild();
  }
  return live;
}

export function applyProfile(profile) {
  profileOverrides = {
    entities: (profile && profile.entities) || {},
    relations: (profile && profile.relations) || {},
  };
  rebuild();
  return live;
}

export const data = () => live;
export const pristine = () => base;

export const entity = (type) => live.entities[type] || live.unknownEntity;
export const relation = (type) => live.relations[type] || live.unknownRelation;
export const role = (id) => live.roles[id] || live.roles.neutral;
export const source = (id) => live.sources[id] || live.sources.generic;
export const severity = (level) => live.severity[Math.max(0, Math.min(5, level | 0))] || live.severity[0];
export const tacticLabel = (slug) => live.tacticLabels[slug] || slug;
export const tacticRank = (slug) => {
  const index = live.tactics.indexOf(slug);
  return index < 0 ? 99 : index;
};
export const entityTypes = () => Object.keys(live.entities);
export const relationTypes = () => Object.keys(live.relations);
export const colorModes = () => live.colorModes || [];

/* Un tipo o una relación que el sysadmin ha ocultado desde el panel. Se
   comprueba aquí y no en cada consumidor para que "oculto" signifique lo mismo
   en el grafo, en la leyenda y en los filtros. */
export const entityVisible = (type) => entity(type).visible !== false;
export const relationVisible = (type) => relation(type).visible !== false;
