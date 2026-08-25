/* GLAMDRING :: interactions.js — menú contextual, atajos y ayuda.
 *
 * Lo que separa un visor de una herramienta de trabajo: poder pivotar, ocultar,
 * fijar y copiar sin soltar el ratón. Las acciones viven aquí y no en app.js
 * para que añadir una nueva sea tocar una lista, no buscar entre el cableado.
 */

import * as ont from '../ontology.js';

let menuEl = null;
let helpEl = null;
let actions = {};

/* Cada acción declara cuándo aplica y qué hace. `when` recibe el contexto del
   click (nodo o arista) y decide si la entrada aparece. */
const NODE_ACTIONS = [
  { id: 'follow', label: 'Seguir a esta entidad',
    hint: 'Deja solo lo suyo y recorre sus acciones en orden' },
  // Antes se llamaba "Centrar aquí" y prometía aislar, que es justo lo que NO
  // hace: solo selecciona y mueve la cámara. Aislar de verdad es el recorrido.
  { id: 'focus', label: 'Centrar la cámara', hint: 'Enfoca este nodo sin tocar el resto' },
  { id: 'expand', label: 'Expandir vecinos', hint: 'Trae del servidor lo que le rodea' },
  { id: 'pin', label: 'Fijar / soltar', hint: 'Ancla el nodo en su sitio' },
  { id: 'hide', label: 'Ocultar', hint: 'Quita este nodo de la vista actual' },
  { id: 'ioc', label: 'Copiar como IOC', hint: 'Copia el valor al portapapeles' },
  { id: 'copyId', label: 'Copiar identificador' },
  { id: 'search', label: 'Buscar en el grafo', hint: 'Filtra por este valor' },
];

const LINK_ACTIONS = [
  { id: 'inspect', label: 'Ver logs de esta relación' },
  { id: 'pulseLink', label: 'Marcar con un destello' },
  { id: 'hideRelation', label: 'Ocultar este tipo de relación' },
];

const SHORTCUTS = [
  ['clic', 'seleccionar y centrar'],
  ['ctrl + clic', 'añadir a la selección múltiple'],
  ['doble clic', 'expandir vecinos desde el servidor'],
  ['s', 'seguir a la entidad seleccionada'],
  ['clic derecho', 'menú contextual'],
  ['arrastrar nodo', 'fijarlo en su sitio'],
  ['espacio', 'reproducir / pausar la cronología'],
  ['f', 'encuadrar todo el grafo'],
  ['1 · 2 · 3', 'explorar · kill-chain · cronología'],
  ['c', 'cambiar el modo de color'],
  ['/', 'ir al buscador'],
  ['a', 'abrir el panel de administrador'],
  ['r', 'generar informe'],
  ['esc', 'limpiar selección y cerrar diálogos'],
  ['?', 'esta ayuda'],
];

function closeMenu() {
  if (menuEl) menuEl.hidden = true;
}

function buildMenu(items, context) {
  menuEl.innerHTML = '';
  items.forEach((item) => {
    const entry = document.createElement('button');
    entry.className = 'ctx-item';
    entry.innerHTML = `<span>${item.label}</span>${
      item.hint ? `<em>${item.hint}</em>` : ''}`;
    entry.addEventListener('click', () => {
      closeMenu();
      actions[item.id]?.(context);
    });
    menuEl.appendChild(entry);
  });
}

function placeMenu(event) {
  menuEl.hidden = false;
  // Se mide después de mostrarlo para poder voltearlo si se sale de pantalla.
  const rect = menuEl.getBoundingClientRect();
  const x = Math.min(event.clientX, window.innerWidth - rect.width - 8);
  const y = Math.min(event.clientY, window.innerHeight - rect.height - 8);
  menuEl.style.left = `${Math.max(8, x)}px`;
  menuEl.style.top = `${Math.max(8, y)}px`;
}

export function openNodeMenu(node, event) {
  if (!menuEl) return;
  const header = { label: node.label, type: ont.entity(node.type).label };
  buildMenu(NODE_ACTIONS, { kind: 'node', node, header });
  placeMenu(event);
}

export function openLinkMenu(link, event) {
  if (!menuEl) return;
  buildMenu(LINK_ACTIONS, { kind: 'link', link });
  placeMenu(event);
}

export function toggleHelp(force) {
  if (!helpEl) return;
  helpEl.hidden = force === undefined ? !helpEl.hidden : !force;
}

export function copyToClipboard(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  // Sin contexto seguro (http://, que es como se despliega esto en un SOC) la
  // API de portapapeles no existe: se cae al truco del textarea oculto.
  const helper = document.createElement('textarea');
  helper.value = text;
  helper.style.position = 'fixed';
  helper.style.opacity = '0';
  document.body.appendChild(helper);
  helper.select();
  try {
    document.execCommand('copy');
  } finally {
    helper.remove();
  }
  return Promise.resolve();
}

export function init(handlers) {
  actions = handlers || {};
  menuEl = document.getElementById('context-menu');
  helpEl = document.getElementById('help-overlay');

  helpEl.querySelector('.help-body').innerHTML = SHORTCUTS
    .map(([keys, what]) => `<div class="help-row"><kbd>${keys}</kbd><span>${what}</span></div>`)
    .join('');

  document.addEventListener('click', (event) => {
    if (menuEl && !menuEl.contains(event.target)) closeMenu();
  });
  document.addEventListener('scroll', closeMenu, true);
  window.addEventListener('blur', closeMenu);

  helpEl.addEventListener('click', () => toggleHelp(false));
  document.getElementById('btn-help').addEventListener('click', () => toggleHelp());

  document.addEventListener('keydown', (event) => {
    const typing = event.target.matches('input, textarea, select');
    if (typing) {
      if (event.key === 'Escape') event.target.blur();
      return;
    }
    if (event.ctrlKey || event.metaKey || event.altKey) return;

    switch (event.key) {
      case 'Escape': closeMenu(); toggleHelp(false); actions.escape?.(); break;
      case '?': toggleHelp(); break;
      case 'f': case 'F': actions.fit?.(); break;
      case ' ': event.preventDefault(); actions.togglePlay?.(); break;
      case '1': actions.setView?.('explore'); break;
      case '2': actions.setView?.('killchain'); break;
      case '3': actions.setView?.('timeline3d'); break;
      case 'c': case 'C': actions.cycleColorMode?.(); break;
      case 's': case 'S': actions.followSelected?.(); break;
      case 'a': case 'A': actions.openAdmin?.(); break;
      case 'r': case 'R': actions.openReport?.(); break;
      case '/': event.preventDefault(); document.getElementById('search').focus(); break;
      default: break;
    }
  });

  return { openNodeMenu, openLinkMenu, toggleHelp, copyToClipboard };
}
