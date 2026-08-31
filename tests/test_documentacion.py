"""La documentación tiene que seguir siendo verdad.

POR QUÉ ESTE FICHERO. Después de tres tandas de trabajo, el README no mencionaba
ni una sola vez Netskope, Zscaler, el receptor ni el vocabulario cerrado;
`CONNECTORS.md` documentaba un contrato de conector que ya no existía, y
`ONTOLOGY.md` no conocía tres tipos de nodo que el código sí creaba. Un diagrama
llegó a afirmar «no abre puertos hacia fuera» cuando el receptor ya escuchaba.

Nada de eso rompe un test convencional, porque la documentación no se ejecuta. Y
sin embargo es de lo que más daño hace: quien la lee toma decisiones con ella, y
una documentación que miente con aplomo es peor que no tenerla.

Lo que se comprueba aquí es lo que se puede comprobar sin opinar: que lo que el
código EXPONE está documentado, y que lo documentado existe.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from glamdring.connectors import _FACTORIES
from glamdring.graph import ontology
from glamdring.models import ACTIVITIES

RAIZ = Path(__file__).resolve().parent.parent
DOCS = RAIZ / "docs"
README = RAIZ / "README.md"


def _texto(ruta: Path) -> str:
    return ruta.read_text(encoding="utf-8")


def _claves_en_tablas(texto: str) -> set:
    """Los `identificadores` que aparecen en la primera columna de una tabla."""
    encontradas = set()
    for linea in texto.splitlines():
        if linea.startswith("| `"):
            trozos = linea.split("`")
            if len(trozos) > 1:
                encontradas.add(trozos[1])
    return encontradas


# ---------------------------------------------------------------- ontología

def test_toda_entidad_del_codigo_esta_documentada():
    """Si el grafo crea un tipo de nodo, tiene que estar en la ontología escrita.

    'tunnel', 'group' y 'registry' estuvieron creándose sin figurar aquí: quien
    leía el documento no sabía que existían.
    """
    documentadas = _claves_en_tablas(_texto(DOCS / "ONTOLOGY.md"))
    faltan = set(ontology.ENTITIES) - documentadas
    assert not faltan, f"tipos de entidad sin documentar: {sorted(faltan)}"


def test_toda_relacion_del_codigo_esta_documentada():
    documentadas = _claves_en_tablas(_texto(DOCS / "ONTOLOGY.md"))
    faltan = set(ontology.RELATIONS) - documentadas
    assert not faltan, f"tipos de relación sin documentar: {sorted(faltan)}"


# -------------------------------------------------------------- vocabulario

def test_toda_actividad_esta_en_el_documento_del_vocabulario():
    """El vocabulario es cerrado, así que la lista escrita tiene que estar entera.

    Media lista documentada es peor que ninguna: da por hecho que lo que no
    aparece no existe.
    """
    texto = _texto(DOCS / "VOCABULARIO.md")
    faltan = [a for a in ACTIVITIES if f"`{a}`" not in texto]
    assert not faltan, f"actividades sin documentar: {sorted(faltan)}"


# --------------------------------------------------------------- conectores

def test_todo_conector_registrado_aparece_en_su_documento():
    texto = _texto(DOCS / "CONNECTORS.md").lower()
    # 'files' se documenta como 'Ficheros', que es como se llama de cara a quien
    # lo usa; el resto lleva su nombre de fabricante.
    alias = {"files": "ficheros", "zscaler_zpa": "zpa"}
    faltan = [n for n in _FACTORIES if alias.get(n, n) not in texto]
    assert not faltan, f"conectores sin documentar: {sorted(faltan)}"


def test_zia_se_documenta_como_lo_que_es():
    """Que ZIA no tenga conector es una decisión, no un olvido.

    Y tiene que estar escrito, porque el siguiente que pase por aquí va a
    preguntarse por qué falta y podría 'arreglarlo'.
    """
    texto = _texto(DOCS / "CONNECTORS.md")
    assert "ZIA" in texto
    assert "receive" in texto, "hay que decir por dónde entra ZIA"


# -------------------------------------------------------------------- README

def test_el_readme_menciona_todas_las_fuentes():
    """Es el escaparate del repositorio: si una fuente no está, no existe."""
    texto = _texto(README)
    for fuente in ("Splunk", "Sentinel", "QRadar", "CEF", "Netskope", "Zscaler"):
        assert fuente in texto, f"el README no menciona {fuente}"


def test_el_readme_dice_que_la_autenticacion_viene_apagada_y_como_encenderla():
    """Es lo único que puede hacer daño de verdad al desplegarlo.

    Antes este test buscaba la frase "no authentication" y ya está. Ahora la
    autenticación existe pero viene APAGADA, así que decir sólo que no la hay
    sería mentira y decir sólo que la hay sería peor: quien lea eso desplegará
    creyendo que está protegido. Tienen que estar las dos mitades, y el nombre
    de la variable, que es lo único accionable de todo el párrafo.
    """
    texto = _texto(README).lower()
    assert "no authentication by default" in texto
    assert "glamdring_api_key" in texto


def test_el_readme_explica_lo_que_protege_sin_credencial():
    """La comprobación de origen y los topes de cuerpo no dependen de la clave.

    Son los que protegen el caso de HOY -la herramienta en el portátil, atada a
    loopback- y quien lea el README pensando "esto es sólo para servidores" se
    saltará justo la parte que le aplica.
    """
    texto = _texto(README).lower()
    assert "sec-fetch-site" in texto
    assert "content-length" in texto


@pytest.mark.parametrize("documento", sorted(
    [p.name for p in DOCS.glob("*.md")] + ["README.md"]))
def test_los_enlaces_internos_no_estan_rotos(documento):
    """Un enlace roto en el README es lo primero que ve quien llega."""
    ruta = README if documento == "README.md" else DOCS / documento
    base = ruta.parent
    rotos = []
    for destino in re.findall(r"\]\(([^)]+)\)", _texto(ruta)):
        if destino.startswith(("http://", "https://", "#", "mailto:")):
            continue
        objetivo = (base / destino.split("#")[0]).resolve()
        if not objetivo.exists():
            rotos.append(destino)
    assert not rotos, f"{documento} tiene enlaces rotos: {rotos}"


# --------------------------------------------------------------- diagramas

def test_los_diagramas_son_validos_y_nada_se_sale():
    """Un SVG mal cerrado no se ve en GitHub y no avisa: sale la imagen rota."""
    import sys

    sys.path.insert(0, str(RAIZ / "tools"))
    from check_diagrams import revisar

    problemas = {}
    for svg in sorted((DOCS / "diagrams").glob("*.svg")):
        fallos = revisar(svg)
        if fallos:
            problemas[svg.name] = fallos
    assert not problemas, f"diagramas con problemas: {problemas}"


def test_todo_diagrama_esta_enlazado_desde_el_readme():
    """Un diagrama que nadie enlaza es trabajo que no ve nadie."""
    texto = _texto(README)
    huerfanos = [svg.name for svg in sorted((DOCS / "diagrams").glob("*.svg"))
                 if svg.name not in texto]
    assert not huerfanos, f"diagramas sin enlazar desde el README: {huerfanos}"


# ----------------------------------------------- la ontologia y las figuras 3D

def _registro_de_models_js(nombre: str) -> set:
    """Los nombres declarados en un objeto de models.js."""
    from glamdring.config import WEB_DIR

    fuente = (WEB_DIR / "js" / "render" / "models.js").read_text(encoding="utf-8")
    bloque = re.search(r"const " + nombre + r" = {(.*?)^};", fuente, re.S | re.M)
    assert bloque, f"no encuentro el registro {nombre} en models.js"
    cuerpo = bloque.group(1)
    # Tanto 'pipe,' como 'sphere: () =>' cuentan como declarado.
    con_valor = set(re.findall(r"^\s*(\w+)\s*:", cuerpo, re.M))
    sueltos = {trozo.strip() for linea in cuerpo.splitlines()
               for trozo in linea.split(",")
               if trozo.strip() and re.fullmatch(r"\w+", trozo.strip())}
    return con_valor | sueltos


def test_todo_modelo_de_la_ontologia_existe_en_el_frontend():
    """Un tipo de nodo cuyo modelo no existe se dibuja como uno generico.

    Y eso es peor que un fallo visible. 'tunnel' y 'group' se anadieron
    declarando los modelos 'pipe' y 'shield', que no existian, asi que salian con
    la figura de 'endpoint'. En un grafo 3D la silueta se lee desde el otro
    extremo de la escena y el texto no: un tunel con forma de equipo es una
    afirmacion falsa dicha en el idioma que mas rapido se lee.

    No lanza ningun error porque el respaldo es silencioso
    (BUILDERS[spec.model] || BUILDERS.endpoint). Por eso hace falta el test.
    """
    from glamdring.graph import ontology

    disponibles = _registro_de_models_js("BUILDERS")
    declarados = {e["model"] for e in ontology.ENTITIES.values() if e.get("model")}
    faltan = declarados - disponibles
    assert not faltan, (
        f"la ontologia declara modelos que models.js no sabe dibujar: {sorted(faltan)}. "
        "Se dibujarian como 'endpoint' sin avisar.")


def test_toda_forma_simple_de_la_ontologia_existe():
    """Con miles de nodos se usa la geometria simple, y ahi pasa lo mismo."""
    from glamdring.graph import ontology

    disponibles = _registro_de_models_js("SIMPLE")
    declaradas = {e["shape"] for e in ontology.ENTITIES.values() if e.get("shape")}
    faltan = declaradas - disponibles
    assert not faltan, f"formas simples que la ontologia declara y no existen: {sorted(faltan)}"
