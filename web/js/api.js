/* GLAMDRING :: api.js — cliente HTTP contra /api/*.
 *
 * Todo pasa por `request()` para que el mensaje real del backend llegue a la
 * interfaz. Un "Error 500" genérico obliga al analista a abrir la consola del
 * navegador, y eso es exactamente lo que no queremos en una herramienta que se
 * usa con prisa.
 */

function qs(params) {
  const parts = [];
  Object.entries(params || {}).forEach(([key, raw]) => {
    let value = raw;
    if (value === undefined || value === null || value === '') return;
    if (Array.isArray(value)) {
      if (!value.length) return;
      value = value.join(',');
    }
    parts.push(`${encodeURIComponent(key)}=${encodeURIComponent(value)}`);
  });
  return parts.length ? `?${parts.join('&')}` : '';
}

async function request(url, options) {
  const response = await fetch(url, options);
  const isJson = (response.headers.get('content-type') || '').includes('json');
  const payload = isJson ? await response.json() : await response.text();
  if (!response.ok) {
    const detail = (payload && payload.detail) || payload || `HTTP ${response.status}`;
    const error = new Error(typeof detail === 'string' ? detail : JSON.stringify(detail));
    error.status = response.status;
    throw error;
  }
  return payload;
}

/* Descarga un fichero generado por el backend sin salir de la página.
   Se usa un blob y no una navegación directa porque el informe se pide por POST
   con la captura del canvas dentro. */
async function download(url, options, fallbackName) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const isJson = (response.headers.get('content-type') || '').includes('json');
    const payload = isJson ? await response.json() : await response.text();
    throw new Error((payload && payload.detail) || `HTTP ${response.status}`);
  }
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename="?([^"]+)"?/);
  const blob = await response.blob();
  const href = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = href;
  anchor.download = match ? match[1] : fallbackName;
  anchor.style.display = 'none';
  document.body.appendChild(anchor);
  anchor.click();

  // El enlace se retira y el blob se libera CON RETRASO, no justo después del
  // click. Chromium cancela la descarga si el ancla desaparece del DOM de forma
  // síncrona, y Firefox la cancela si se revoca el objectURL antes de tiempo.
  // Con la limpieza inmediata, el fichero simplemente no llegaba y no había
  // ningún error que lo explicase.
  setTimeout(() => {
    anchor.remove();
    URL.revokeObjectURL(href);
  }, 4000);
  return anchor.download;
}

export const health = () => request('api/health');
export const ontology = () => request('api/ontology');
export const connectors = () => request('api/connectors');

/* Comprobacion REAL de que cada fuente responde. Va aparte de connectors()
   porque aquel es instantaneo y este habla por la red: si se pidieran juntos,
   abrir el dialogo del SIEM costaria varios segundos cada vez. */
export const pingConnectors = () => request('api/connectors/ping');
export const demo = (set = 'completo') =>
  request(`api/demo?set=${encodeURIComponent(set)}`, { method: 'POST' });

/* Incidentes que se pueden cargar. Hoy salen de samples/; manana, de la base de
   datos. La interfaz consume la ficha (id, titulo, subtitulo) y no sabe de
   donde viene, que es lo que permite cambiar la fuente sin tocar el front. */
export const incidents = () => request('api/incidents');
export const loadIncident = (id) =>
  request(`api/incidents/load?id=${encodeURIComponent(id)}`, { method: 'POST' });
export const reset = () => request('api/reset', { method: 'POST' });

export function ingestFile(file) {
  const form = new FormData();
  form.append('file', file, file.name);
  return request('api/ingest', { method: 'POST', body: form });
}

export function ingestText(text, formatHint) {
  const form = new FormData();
  form.append('text', text);
  if (formatHint) form.append('format_hint', formatHint);
  return request('api/ingest', { method: 'POST', body: form });
}

export const querySiem = (payload) => request('api/query', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(payload),
});

export const graph = (filters) => request(`api/graph${qs(filters)}`);
export const neighbors = (node, hops = 1) => request(`api/graph/neighbors${qs({ node, hops })}`);
/* El recorrido de una entidad: sus actos en orden, y el subgrafo aislado a su
   vecindad. Vienen juntos a proposito, para que no puedan no cuadrar. */
export const story = (node, hops = 1) => request(`api/graph/story${qs({ node, hops })}`);
export const timeline = (filters) => request(`api/timeline${qs(filters)}`);
export const events = (params) => request(`api/events${qs(params)}`);

export const getAppearance = () => request('api/appearance');
export const putAppearance = (patch) => request('api/appearance', {
  method: 'PUT',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify(patch),
});
export const resetAppearance = () => request('api/appearance/reset', { method: 'POST' });

export function uploadModel(name, file) {
  const form = new FormData();
  form.append('file', file, file.name);
  return request(`api/appearance/model/${encodeURIComponent(name)}`, {
    method: 'POST', body: form,
  });
}

export const deleteModel = (name) =>
  request(`api/appearance/model/${encodeURIComponent(name)}`, { method: 'DELETE' });

export const reportPreview = (filters) => request(`api/report/preview${qs(filters)}`);
export const iocs = (filters) => request(`api/iocs${qs(filters)}`);

export const downloadReport = (payload) => download('api/report', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ ...payload, download: true }),
}, 'informe.html');
