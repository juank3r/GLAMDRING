/* GLAMDRING :: orient.js — que las figuras se lean desde donde estés.
 *
 * EL PROBLEMA
 * Las figuras nunca se giran solas: se modelan con el eje Y hacia arriba y ahí
 * se quedan. Lo que se mueve es la cámara. Con `controlType: 'trackball'` no hay
 * eje vertical fijo, así que arrastrando se puede rodar el mundo entero y una
 * persona acaba boca abajo. Eso ya está resuelto poniendo `orbit` por defecto.
 *
 * Pero queda la otra mitad: aunque la vertical esté fija, si giras alrededor de
 * un puesto de trabajo acabas mirándole la parte de atrás, que es una caja. Una
 * persona vista por la espalda es una silueta sin cara. La información está en
 * el frente de la figura, y el frente apunta a donde le tocó al construirla.
 *
 * LA SOLUCIÓN
 * Girar cada fotograma las figuras que tienen frente para que te lo den a ti.
 *
 *   yaw        gira solo sobre el eje vertical. La figura sigue de pie, apoyada
 *              en el suelo, pero mirándote. Es el modo por defecto porque
 *              conserva la sensación de que hay gravedad.
 *   billboard  encara la cámara por completo. Se lee perfecto desde cualquier
 *              sitio, pero las figuras se despegan de la vertical y el grafo
 *              parece un collage. Útil con muchísimos nodos.
 *   fixed      no gira nada.
 *
 * POR QUÉ NO SE GIRA EL GRUPO ENTERO
 * El objeto de cada nodo es un Group con la figura y, encima, su etiqueta. La
 * etiqueta cuelga en (0, altura, 0), o sea justo sobre el eje de giro: girando
 * en `yaw` no se mueve de sitio. Pero en `billboard` el giro es completo y la
 * etiqueta saldría orbitando alrededor del nodo. Por eso se gira SOLO la figura,
 * que `graph3d.js` deja anotada en `userData.gdFigure`.
 *
 * COSTE
 * Un atan2 por figura y fotograma. A 5.000 nodos es ruido comparado con lo que
 * cuesta la propia simulación de fuerzas. Aun así solo se recorren los nodos con
 * frente, que son bastantes menos que el total.
 */

let frame = null;
let ctx = null;

/* Reutilizados entre fotogramas: crear vectores dentro del bucle a 60 fps es
   la forma más fácil de darle trabajo al recolector de basura sin motivo. */
const camPos = { x: 0, y: 0, z: 0 };

function tick() {
  frame = requestAnimationFrame(tick);
  if (!ctx) return;

  const mode = ctx.getMode();
  if (mode === 'fixed') return;

  const camera = ctx.getCamera();
  if (!camera) return;
  camPos.x = camera.position.x;
  camPos.y = camera.position.y;
  camPos.z = camera.position.z;

  const nodes = ctx.getNodes();
  for (let i = 0; i < nodes.length; i += 1) {
    const node = nodes[i];
    const group = node.__threeObj;
    if (!group || !group.userData.gdFaces) continue;
    const figure = group.userData.gdFigure;
    if (!figure) continue;

    if (mode === 'billboard') {
      // El giro de la cámara se copia tal cual: la figura queda paralela al
      // plano de la pantalla, que es exactamente lo que hace un sprite.
      figure.quaternion.copy(camera.quaternion);
      continue;
    }

    // yaw: solo el rumbo. Se mide en el plano horizontal, así que da igual si
    // la cámara está por encima o por debajo: la figura no se tumba nunca.
    const dx = camPos.x - (node.x || 0);
    const dz = camPos.z - (node.z || 0);
    // atan2(x, z) y no (z, x): en three.js el frente de un objeto es -Z, y esta
    // forma es la que hace coincidir el frente con la dirección de la cámara.
    figure.rotation.set(0, Math.atan2(dx, dz), 0);
  }
}

/**
 * Arranca el bucle de orientación.
 *
 * @param {object} hooks
 * @param {() => object} hooks.getCamera  cámara actual (puede cambiar al reconstruir)
 * @param {() => Array}  hooks.getNodes   nodos del grafo, con su `__threeObj`
 * @param {() => string} hooks.getMode    'fixed' | 'yaw' | 'billboard'
 */
export function start(hooks) {
  stop();
  ctx = hooks;
  frame = requestAnimationFrame(tick);
}

export function stop() {
  if (frame !== null) cancelAnimationFrame(frame);
  frame = null;
  ctx = null;
}

/**
 * Devuelve las figuras a su posición de reposo.
 *
 * Hace falta al cambiar a modo `fixed`: si no, cada figura se queda congelada
 * con el último giro que le tocó, que es peor que no haber girado nunca porque
 * el desorden parece intencionado.
 */
export function reset(nodes) {
  (nodes || []).forEach((node) => {
    const figure = node.__threeObj && node.__threeObj.userData.gdFigure;
    if (figure) figure.rotation.set(0, 0, 0);
  });
}
