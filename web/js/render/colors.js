/* GLAMDRING :: colors.js — de qué color va cada nodo, según lo que se pregunte.
 *
 * El grafo es siempre el mismo; lo que cambia es qué dimensión se lleva el
 * color. "¿Qué tipo de cosa es esto?" y "¿quién es el atacante?" son preguntas
 * distintas y merecen mapas de color distintos, en vez de obligar al analista a
 * deducir una a partir de la otra.
 */

import * as ont from '../ontology.js';

/* Interpolación en RGB. Es suficiente para una rampa de riesgo de cinco paradas
   y evita meter una dependencia de espacios de color perceptuales por algo que
   solo se mira de reojo. */
function lerpHex(a, b, t) {
  const pa = parseInt(a.slice(1), 16);
  const pb = parseInt(b.slice(1), 16);
  const mix = (shift) => {
    const ca = (pa >> shift) & 255;
    const cb = (pb >> shift) & 255;
    return Math.round(ca + (cb - ca) * t);
  };
  const value = (mix(16) << 16) | (mix(8) << 8) | mix(0);
  return `#${value.toString(16).padStart(6, '0')}`;
}

function rampColor(ramp, ratio) {
  if (!ramp || !ramp.length) return '#94a3b8';
  if (ramp.length === 1) return ramp[0];
  const clamped = Math.max(0, Math.min(1, ratio));
  const scaled = clamped * (ramp.length - 1);
  const index = Math.min(ramp.length - 2, Math.floor(scaled));
  return lerpHex(ramp[index], ramp[index + 1], scaled - index);
}

export function hexToRgba(hex, alpha) {
  let value = String(hex || '#94a3b8').replace('#', '');
  if (value.length === 3) {
    value = value[0] + value[0] + value[1] + value[1] + value[2] + value[2];
  }
  const n = parseInt(value, 16);
  return `rgba(${(n >> 16) & 255},${(n >> 8) & 255},${n & 255},${alpha})`;
}

const RESOLVERS = {
  type: (node) => ont.entity(node.type).color,
  role: (node) => ont.role(node.props && node.props.role).color,
  severity: (node) => ont.severity(node.maxSeverity).color,
  risk: (node) => rampColor(ont.data().riskRamp, (node.risk || 0) / 100),
  source: (node) => ont.source((node.sources || [])[0]).color,
  tactic: (node) => {
    const tactics = node.tactics || [];
    if (!tactics.length) return '#3f4a5c';
    // El color va por posición en la cadena: el mismo degradado sirve para
    // leer "esto es del principio del ataque" o "esto es del final".
    const ratio = ont.tacticRank(tactics[0]) / Math.max(1, ont.data().tactics.length - 1);
    return rampColor(ont.data().riskRamp, ratio);
  },
  cluster: (node) => {
    const palette = ont.data().clusterPalette || [];
    const index = Number(node.props && node.props.cluster) || 0;
    return palette[index % palette.length] || '#94a3b8';
  },
};

export function nodeColor(node, mode = 'type') {
  const resolver = RESOLVERS[mode] || RESOLVERS.type;
  try {
    return resolver(node) || '#94a3b8';
  } catch (error) {
    return '#94a3b8';
  }
}

/* El color de acento de un nodo: lo urgente. Se usa en pantallas, pilotos y
   halos, y NO cambia con el modo de color, porque la severidad tiene que poder
   leerse siempre, se esté mirando lo que se esté mirando. */
export function accentColor(node) {
  const role = node.props && node.props.role;
  if (role === 'hostile') return ont.role('hostile').color;
  return ont.severity(node.maxSeverity).color;
}

export function isAlarmed(node) {
  const role = node.props && node.props.role;
  return (node.maxSeverity || 0) >= 4 || role === 'hostile' || role === 'victim';
}

/* Leyenda del modo activo: qué significa cada color ahora mismo.
   Se genera a partir de los datos en pantalla y no de la ontología completa,
   porque una leyenda con trece tipos cuando solo hay cuatro estorba. */
export function legendFor(mode, nodes) {
  const seen = new Map();
  const push = (key, label, color) => {
    if (!seen.has(key)) seen.set(key, { label, color });
  };

  (nodes || []).forEach((node) => {
    switch (mode) {
      case 'role': {
        const id = (node.props && node.props.role) || 'neutral';
        push(id, ont.role(id).label, ont.role(id).color);
        break;
      }
      case 'severity': {
        const level = node.maxSeverity || 0;
        push(`s${level}`, ont.severity(level).label, ont.severity(level).color);
        break;
      }
      case 'source': {
        const id = (node.sources || [])[0] || 'generic';
        push(id, ont.source(id).label, ont.source(id).color);
        break;
      }
      case 'tactic': {
        const tactic = (node.tactics || [])[0];
        if (tactic) push(tactic, ont.tacticLabel(tactic), nodeColor(node, 'tactic'));
        break;
      }
      case 'cluster': {
        const index = Number(node.props && node.props.cluster) || 0;
        push(`c${index}`, `Comunidad ${index + 1}`, nodeColor(node, 'cluster'));
        break;
      }
      case 'risk':
        break;  // el riesgo es continuo: se dibuja como barra, no como lista
      default:
        push(node.type, ont.entity(node.type).label, ont.entity(node.type).color);
    }
  });

  if (mode === 'risk') {
    return {
      kind: 'ramp',
      ramp: ont.data().riskRamp,
      from: 'Riesgo 0',
      to: 'Riesgo 100',
    };
  }

  const items = [...seen.entries()].map(([id, item]) => ({ id, ...item }));
  if (mode === 'severity') items.sort((a, b) => a.id.localeCompare(b.id));
  else if (mode === 'tactic') items.sort((a, b) => ont.tacticRank(a.id) - ont.tacticRank(b.id));
  else items.sort((a, b) => a.label.localeCompare(b.label));
  return { kind: 'list', items };
}
