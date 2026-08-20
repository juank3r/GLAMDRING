# Pendiente

Estado al 20 de agosto de 2026. Todo lo de abajo está publicado y en verde
(260 tests); esto es lo que queda por hacer, por orden de lo que más aporta.

---

## 1. Activar la wiki de GitHub

**Bloqueado, y solo lo puede desbloquear una persona.** GitHub no deja empujar a
`GLAMDRING.wiki.git` hasta que la wiki existe: hoy responde *Repository not found*.

Hay que entrar una vez a <https://github.com/juank3r/GLAMDRING/wiki> y pulsar
**Create the first page** (vale con guardar cualquier cosa). Después:

```powershell
cd <scratchpad>\wikipush
git push origin master
```

Las 16 páginas ya están escritas y versionadas en [`wiki/`](../wiki/) dentro del
repo, así que mientras tanto se leen desde ahí. No se pierde nada, solo no están
en la pestaña Wiki.

## 2. Documentar la detección de ransomware en la wiki

El README ya la explica, pero la wiki no tiene página propia:

- Página nueva sobre las tres vías de detección, las ocho etapas y la ponderación
  de la atribución. El material está en [`docs/diagrams/06-cadena-ransomware.svg`](diagrams/06-cadena-ransomware.svg)
  y en los docstrings de `glamdring/threat/`.
- Página para los 17 incidentes de [`samples/apt/`](../samples/apt/): qué grupo
  representa cada uno y qué se espera ver al cargarlo.
- Añadir ambas a `wiki/_Sidebar.md` y a `wiki/Home.md`, que hoy no las indexan.
- Enlazar los seis diagramas desde la wiki, no solo desde el README.

## 3. Enseñar la valoración de amenaza en la interfaz

Ahora mismo solo sale por `GET /api/threat` y en los informes. En la interfaz no
hay nada. Faltaría un panel con:

- las etapas de despliegue alcanzadas, con la que marca el punto de no retorno
- las herramientas vistas, agrupadas por categoría
- la atribución con su grado de confianza y el aviso de que es una hipótesis

El endpoint ya devuelve todo lo necesario; es trabajo de frontend.

---

## Dos cosas del entorno que conviene recordar

**Puerto 8000 ocupado.** Hay un `uvicorn` colgado de otra sesión, con código
viejo, que no se deja matar (acceso denegado). No sirve para probar nada. Levanta
en otro puerto:

```powershell
uvicorn glamdring.main:app --port 8001
```

**Para ver los SVG renderizados** sin Node instalado, vale Edge sin cabeza:

```powershell
& "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" `
  --headless --disable-gpu --window-size=1360,900 `
  --screenshot=salida.png "file:///ruta/al/diagrama.svg"
```

Escribe el fichero con retardo, así que hay que esperar un par de segundos antes
de abrirlo.
