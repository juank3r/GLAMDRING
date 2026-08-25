/* GLAMDRING :: cine.js — el grafo a pantalla completa, sin nada alrededor.
 *
 * PARA QUE. El modo automatico esta pensado para dejarlo puesto: en una pantalla
 * del SOC, o proyectado mientras se explica un caso. Y en ese momento los
 * filtros, el inspector y la barra de herramientas no los va a tocar nadie: solo
 * quitan sitio al grafo y ensucian la foto.
 *
 * Aqui se apaga todo menos el lienzo y la tarjeta que va contando cada paso.
 *
 * EL FONDO SE ELIGE, y no es un capricho. El tema oscuro esta pensado para una
 * sala en penumbra, que es donde trabaja un SOC. Proyectado en una reunion con
 * luz, un fondo casi negro se come el contraste y las figuras se pierden. Hay
 * tres opciones, y ninguna es "la buena": depende de donde se este mirando.
 *
 *   sala    el tema de siempre (#070a10)
 *   negro   negro puro, para pantallas OLED y salas a oscuras
 *   papel   blanco, para proyectar con luz o para una captura de informe
 *
 * En 'papel' no basta con cambiar el fondo: sobre blanco, las etiquetas claras y
 * la niebla oscura desaparecen. Se ajustan tambien, y se restauran al salir.
 */

import graph3d from '../render/graph3d.js';
import { setLightBackground } from '../render/colors.js';

const FONDOS = [
  { id: 'sala',  label: 'Sala',  color: '#070a10', texto: '#dce4f0', claro: false },
  { id: 'negro', label: 'Negro', color: '#000000', texto: '#f0f4fa', claro: false },
  { id: 'papel', label: 'Papel', color: '#ffffff', texto: '#0b1220', claro: true },
];

let handlers = {};
let barra = null;

const estado = {
  activo: false,
  fondo: 'sala',
  previo: null,     // ajustes que hay que devolver al salir
};

const el = (id) => document.getElementById(id);

/* ------------------------------------------------------------------ fondos */

function aplicarFondo(id) {
  const f = FONDOS.find((x) => x.id === id) || FONDOS[0];
  estado.fondo = f.id;
  document.body.dataset.cineFondo = f.id;
  document.body.classList.toggle('cine-claro', f.claro);

  // La paleta esta calculada para fondo oscuro. Sobre blanco hay que oscurecer
  // los tonos conservando el matiz, o el grafo se queda en un fantasma: medido,
  // con solo cambiar el fondo las figuras casi no se veian.
  setLightBackground(f.claro);

  // El fondo del lienzo lo pone el CSS, porque la escena se dibuja transparente.
  handlers.onFondo?.({
    theme: { background: f.color, text: f.texto },
    render: {
      // La niebla se apaga sobre blanco. Su color sale del tema, asi que seria
      // niebla BLANCA sobre fondo blanco: a la misma densidad que en oscuro se
      // come el grafo entero antes de dar ninguna sensacion de profundidad.
      fog: !f.claro,
      // El bloom sobre blanco no aporta: lo claro ya esta saturado y solo
      // consigue emborronar los bordes de las figuras.
      bloom: !f.claro,
      // Las aristas finas se pierden sobre blanco mucho antes que sobre negro.
      linkOpacity: f.claro ? 0.85 : 0.55,
    },
  });

  barra?.querySelectorAll('.cine-fondo-btn').forEach((b) => {
    b.classList.toggle('activo', b.dataset.fondo === f.id);
  });
}

export const fondoActual = () => estado.fondo;
export const fondos = () => FONDOS.map((f) => ({ id: f.id, label: f.label }));

/* ------------------------------------------------------------ entrar/salir */

export function entrar() {
  if (estado.activo) return;
  estado.activo = true;
  estado.previo = handlers.snapshotProfile?.() || null;

  document.body.classList.add('cine');
  barra.hidden = false;
  aplicarFondo(estado.fondo);
  reflejarAuto(handlers.autoActivo?.());

  // El lienzo cambia de tamano al desaparecer los paneles: si no se le avisa,
  // la escena se queda con la relacion de aspecto anterior y sale estirada.
  requestAnimationFrame(() => {
    graph3d.resize();
    graph3d.zoomToFit(700, 80);
  });

  handlers.onEnter?.();
}

export function salir() {
  if (!estado.activo) return;
  estado.activo = false;
  document.body.classList.remove('cine', 'cine-claro');
  delete document.body.dataset.cineFondo;
  barra.hidden = true;

  // Devolver el perfil tal cual estaba: entrar en modo escaparate no puede
  // dejarle el tema cambiado a quien lo use despues.
  setLightBackground(false);
  if (estado.previo) handlers.restoreProfile?.(estado.previo);
  estado.previo = null;

  requestAnimationFrame(() => {
    graph3d.resize();
    graph3d.zoomToFit(700, 90);
  });

  handlers.onExit?.();
}

export const activo = () => estado.activo;
export const alternar = () => (estado.activo ? salir() : entrar());

/* Pone el boton del recorrido al dia. Lo llama app.js cada vez que el modo
   automatico arranca, se para o lo interrumpe alguien tocando el lienzo: sin
   esto el boton diria "parar" con el recorrido ya detenido. */
export function reflejarAuto(corriendo) {
  const boton = el('cine-auto');
  if (!boton) return;
  boton.classList.toggle('corriendo', Boolean(corriendo));
  el('cine-auto-icono').textContent = corriendo ? '❚❚' : '▶';
  el('cine-auto-texto').textContent = corriendo ? 'Parar' : 'Auto';
  boton.title = corriendo
    ? 'Parar el recorrido automático (t)'
    : 'Reanudar el recorrido automático (t)';
}

/* -------------------------------------------------------------------- init */

export function init(hooks) {
  handlers = hooks || {};
  barra = el('cine-bar');
  if (!barra) return { entrar, salir, alternar, activo };

  barra.querySelectorAll('.cine-fondo-btn').forEach((boton) => {
    boton.addEventListener('click', () => aplicarFondo(boton.dataset.fondo));
  });
  el('cine-salir')?.addEventListener('click', () => salir());
  el('btn-cine')?.addEventListener('click', () => alternar());
  el('cine-auto')?.addEventListener('click', () => handlers.onToggleAuto?.());

  return { entrar, salir, alternar, activo, fondoActual, reflejarAuto };
}
