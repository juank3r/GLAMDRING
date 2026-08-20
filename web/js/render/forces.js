/* GLAMDRING :: forces.js — fuerza de colisión propia.
 *
 * El ejemplo `collision-detection` del repositorio usa `forceCollide` de
 * d3-force-3d, pero el bundle UMD de 3d-force-graph no expone esa librería, y
 * vendorizar d3-force-3d entero por una sola función no compensa.
 *
 * Hace falta de verdad desde que los nodos dejaron de ser esferas pequeñas: un
 * rack, un monitor y una figura humana ocupan volumen, y sin separación se
 * atraviesan entre sí y el grafo parece un amasijo.
 *
 * Implementa la interfaz que espera el motor de fuerzas: `force(alpha)` en cada
 * tick y `initialize(nodes)` al montar la simulación.
 */

/**
 * Separación entre nodos que se solapan.
 *
 * Rejilla espacial en vez de comparar todos contra todos: con 800 nodos, el
 * bucle O(n²) son 320.000 comparaciones por fotograma y se nota. Con celdas del
 * tamaño del radio mayor, cada nodo solo mira sus 27 celdas vecinas.
 *
 * @param {(node) => number} radiusOf  radio de colisión de cada nodo
 * @param {number} strength            0-1, cuánto se corrige el solape por tick
 */
export function forceCollide(radiusOf, strength = 0.7) {
  let nodes = [];
  let radii = [];
  let cellSize = 20;

  function force(alpha) {
    if (!nodes.length) return;

    const buckets = new Map();
    const keyOf = (x, y, z) =>
      `${Math.floor(x / cellSize)},${Math.floor(y / cellSize)},${Math.floor(z / cellSize)}`;

    nodes.forEach((node, index) => {
      const key = keyOf(node.x || 0, node.y || 0, node.z || 0);
      let bucket = buckets.get(key);
      if (!bucket) {
        bucket = [];
        buckets.set(key, bucket);
      }
      bucket.push(index);
    });

    const push = strength * alpha;

    nodes.forEach((node, index) => {
      const cx = Math.floor((node.x || 0) / cellSize);
      const cy = Math.floor((node.y || 0) / cellSize);
      const cz = Math.floor((node.z || 0) / cellSize);

      for (let dx = -1; dx <= 1; dx++) {
        for (let dy = -1; dy <= 1; dy++) {
          for (let dz = -1; dz <= 1; dz++) {
            const bucket = buckets.get(`${cx + dx},${cy + dy},${cz + dz}`);
            if (!bucket) continue;

            for (const other of bucket) {
              // Solo se resuelve cada pareja una vez.
              if (other <= index) continue;
              const target = nodes[other];

              let vx = (target.x || 0) - (node.x || 0);
              let vy = (target.y || 0) - (node.y || 0);
              let vz = (target.z || 0) - (node.z || 0);
              let distance = Math.sqrt(vx * vx + vy * vy + vz * vz);
              const minimum = radii[index] + radii[other];
              if (distance >= minimum) continue;

              // Dos nodos exactamente encima no tienen dirección de separación:
              // se les da un empujón determinista para que no se queden pegados.
              if (distance === 0) {
                vx = (index % 3) - 1 || 0.5;
                vy = (other % 3) - 1 || 0.5;
                vz = 0.3;
                distance = Math.sqrt(vx * vx + vy * vy + vz * vz);
              }

              const correction = ((minimum - distance) / distance) * push;
              const halfX = vx * correction * 0.5;
              const halfY = vy * correction * 0.5;
              const halfZ = vz * correction * 0.5;

              node.vx = (node.vx || 0) - halfX;
              node.vy = (node.vy || 0) - halfY;
              node.vz = (node.vz || 0) - halfZ;
              target.vx = (target.vx || 0) + halfX;
              target.vy = (target.vy || 0) + halfY;
              target.vz = (target.vz || 0) + halfZ;
            }
          }
        }
      }
    });
  }

  force.initialize = (incoming) => {
    nodes = incoming || [];
    radii = nodes.map((node) => {
      try {
        return Math.max(1, Number(radiusOf(node)) || 1);
      } catch (error) {
        return 1;
      }
    });
    cellSize = Math.max(8, 2 * Math.max(1, ...radii));
  };

  force.strength = (value) => {
    if (value === undefined) return strength;
    strength = value;
    return force;
  };

  return force;
}
