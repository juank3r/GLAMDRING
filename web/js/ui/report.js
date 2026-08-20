/* GLAMDRING :: report.js — diálogo de informe.
 *
 * El servidor genera el documento; aquí solo se recogen el título, el formato y
 * la captura del lienzo. La captura sale del canvas WebGL y se manda como
 * data-URL, que es la única forma de que la imagen del grafo acabe DENTRO del
 * fichero HTML y este siga siendo un solo adjunto.
 */

import * as api from '../api.js';
import * as ont from '../ontology.js';

const FORMATS = [
  { id: 'html', label: 'HTML autocontenido', hint: 'Un fichero, imprimible a PDF con Ctrl+P' },
  { id: 'markdown', label: 'Markdown', hint: 'Para Jira, TheHive o el wiki del SOC' },
  { id: 'json', label: 'JSON completo', hint: 'El informe entero en estructura' },
  { id: 'stix', label: 'STIX-lite', hint: 'Indicadores para un TIP' },
  { id: 'iocs', label: 'Lista de IOCs', hint: 'Texto plano para firewall o EDR' },
];

let dialog = null;
let getSnapshot = () => null;
let getFilters = () => ({});

const esc = (value) => String(value ?? '')
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

function fmtTime(iso) {
  if (!iso) return '—';
  return String(iso).replace('T', ' ').slice(0, 19);
}

async function renderPreview() {
  const box = dialog.querySelector('#report-preview');
  box.innerHTML = '<div class="count">preparando el informe…</div>';
  try {
    const preview = await api.reportPreview(getFilters());
    const summary = preview.summary;
    box.innerHTML = `
      <div class="report-cards">
        ${[['Eventos', summary.events], ['Entidades', summary.nodes],
           ['Relaciones', summary.links], ['Indicadores', summary.iocCount]]
          .map(([k, v]) => `<div class="report-card"><div class="k">${k}</div>
            <div class="v">${v}</div></div>`).join('')}
      </div>
      <div class="report-meta">
        ${esc(fmtTime(preview.window.from))} → ${esc(fmtTime(preview.window.to))}
        ${preview.window.duration ? `· ${esc(preview.window.duration)}` : ''}
        · severidad máxima <b>${esc(summary.maxSeverityLabel)}</b>
      </div>
      <h4>Cadena de ataque</h4>
      <div class="pill-row">
        ${preview.killchain.length
          ? preview.killchain.map((stage) =>
              `<span class="pill tactic">${esc(stage.label)}</span>`).join('')
          : '<span class="count">sin tácticas etiquetadas</span>'}
      </div>
      <h4>Primeras líneas de la cronología</h4>
      <ol class="report-timeline">
        ${preview.narrative.slice(0, 6).map((entry) => `
          <li><span class="t">${esc(fmtTime(entry.time))}</span>
              <span>${esc(entry.text)}</span>
              ${entry.count > 1 ? `<b>×${entry.count}</b>` : ''}</li>`).join('')}
      </ol>
      <h4>Acciones recomendadas</h4>
      <ul class="report-recs">
        ${preview.recommendations.slice(0, 4).map((item) =>
          `<li><b>${esc(item.label)}</b> — ${esc(item.text)}</li>`).join('')
          || '<li class="count">sin recomendaciones automáticas</li>'}
      </ul>`;
    dialog.querySelector('#report-title').placeholder = preview.title;
  } catch (error) {
    box.innerHTML = `<div class="count" style="color:#fb7185">${esc(error.message)}</div>`;
  }
}

export function init(handlers) {
  dialog = document.getElementById('report-dialog');
  getSnapshot = handlers.getSnapshot || (() => null);
  getFilters = handlers.getFilters || (() => ({}));

  dialog.querySelector('#report-formats').innerHTML = FORMATS.map((format, index) => `
    <label class="report-format">
      <input type="radio" name="report-format" value="${format.id}"
             ${index === 0 ? 'checked' : ''}>
      <span class="report-format-body">
        <b>${esc(format.label)}</b>
        <em>${esc(format.hint)}</em>
      </span>
    </label>`).join('');

  dialog.querySelector('.report-close').addEventListener('click', () => toggle(false));
  dialog.addEventListener('click', (event) => {
    if (event.target === dialog) toggle(false);
  });

  dialog.querySelector('#report-generate').addEventListener('click', async () => {
    const button = dialog.querySelector('#report-generate');
    const format = dialog.querySelector('input[name="report-format"]:checked').value;
    const includeImage = dialog.querySelector('#report-image').checked;

    button.disabled = true;
    button.textContent = 'Generando…';
    try {
      const payload = {
        ...getFilters(),
        format,
        title: dialog.querySelector('#report-title').value.trim(),
        analyst: dialog.querySelector('#report-analyst').value.trim(),
      };
      // La imagen solo tiene sentido en el HTML: en Markdown o JSON es un
      // churro de base64 que nadie va a leer.
      if (includeImage && format === 'html') {
        payload.image = getSnapshot();
      }
      const name = await api.downloadReport(payload);
      handlers.onDone?.(`Informe descargado: ${name}`);
      toggle(false);
    } catch (error) {
      handlers.onError?.(error.message);
    } finally {
      button.disabled = false;
      button.textContent = 'Generar informe';
    }
  });

  dialog.querySelectorAll('input[name="report-format"]').forEach((input) => {
    input.addEventListener('change', () => {
      const imageRow = dialog.querySelector('.report-image-row');
      imageRow.classList.toggle('is-disabled', input.value !== 'html');
    });
  });

  return { toggle };
}

export function toggle(force) {
  if (!dialog) return;
  const next = force === undefined ? dialog.hidden : force;
  dialog.hidden = !next;
  if (next) renderPreview();
}

export const isOpen = () => dialog && !dialog.hidden;
