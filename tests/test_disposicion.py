"""Los tres fallos que ensuciaban el grafo mirase uno la vista que mirase.

Ninguno era una cuestion de gusto y ninguno se veia leyendo el codigo por
encima:

  1. la vista elegida no sobrevivia a una recarga, asi que siempre se acababa
     en `explore`, la unica disposicion sin ningun eje con significado;
  2. arrastrar un nodo lo clavaba en Y y en Z PARA SIEMPRE, en las tres vistas,
     sin ninguna forma de soltarlo;
  3. la camara no se reorientaba al cambiar de vista, asi que la promesa de
     "se lee de izquierda a derecha" se rompia en cuanto alguien giraba la
     escena, que con controles de orbita es lo primero que hace todo el mundo.

Aqui no se ejecuta JavaScript, igual que en `test_web.py`: se comprueba la
FORMA del codigo, y en concreto la forma que el fallo violaba. Cada test de
abajo se cae si se revierte su arreglo -comprobado revirtiendolos uno a uno-.
"""

from __future__ import annotations

import re

import pytest

from glamdring.config import WEB_DIR

GRAPH3D = WEB_DIR / "js" / "render" / "graph3d.js"
APP = WEB_DIR / "js" / "app.js"
INTERACCIONES = WEB_DIR / "js" / "ui" / "interactions.js"


def _texto(ruta) -> str:
    return ruta.read_text(encoding="utf-8")


def _sin_comentarios(fuente: str) -> str:
    """Quita comentarios y cadenas antes de analizar.

    NO ES COSMETICO: la primera version de estos tests buscaba `soltarTodo()`
    en el cuerpo de `applyLayout`, y ahi hay un comentario que MENCIONA
    `soltarTodo()`. Al quitar la llamada de verdad, el texto del comentario
    seguia haciendo pasar el test. Se descubrio revirtiendo el arreglo, que es
    justo para lo que sirve hacerlo.

    Un test que lee comentarios no comprueba codigo: comprueba prosa, y la
    prosa sobrevive al borrado de lo que describe.
    """
    fuente = re.sub(r"/\*.*?\*/", " ", fuente, flags=re.S)      # bloque
    fuente = re.sub(r"//[^\n]*", " ", fuente)                   # linea
    fuente = re.sub(r"'[^'\n]*'", "''", fuente)                 # cadenas simples
    return fuente


def _cuerpo_de(bruto: str, firma: str) -> str:
    """El cuerpo de una funcion, contando llaves.

    Hace falta acotar: buscar `fy` en el fichero entero encontraria las decenas
    de sitios donde se lee la posicion de un nodo, y el test pasaria sin que el
    arreglo estuviera.
    """
    fuente = _sin_comentarios(bruto)
    inicio = fuente.index(firma)
    i = fuente.index("{", inicio)
    profundidad = 0
    for j in range(i, len(fuente)):
        if fuente[j] == "{":
            profundidad += 1
        elif fuente[j] == "}":
            profundidad -= 1
            if profundidad == 0:
                return fuente[i:j + 1]
    raise AssertionError(f"no se cierra el cuerpo de {firma}")


# ------------------------------------------- 1. la vista sobrevive la recarga

def test_la_vista_se_recuerda_en_el_navegador():
    """`profile.view` se validaba en el backend y NADIE lo leia en el frontend.

    Faltaba el `if` analogo al de `colorMode`, y no habia `localStorage` en todo
    `web/js`. Cada recarga devolvia al analista a `explore`.
    """
    fuente = _texto(APP)
    assert "localStorage" in fuente, "sin memoria, la vista no sobrevive a F5"
    assert "vistaRecordada" in fuente and "recordarVista" in fuente


def test_elegir_vista_la_guarda():
    cuerpo = _cuerpo_de(_texto(APP), "function setView(name)")
    assert "recordarVista(name)" in cuerpo, "setView tiene que dejar constancia"


def test_el_arranque_aplica_la_vista_recordada():
    """Y con el defecto del perfil por detras: el servidor pone el defecto, el
    analista manda sobre el."""
    cuerpo = _cuerpo_de(_texto(APP), "async function boot()")
    assert "vistaRecordada()" in cuerpo
    assert "state.profile.view" in cuerpo, "falta el defecto del perfil"


def test_la_memoria_aguanta_que_el_navegador_la_prohiba():
    """En ventana privada o con el almacenamiento bloqueado por politica de
    empresa, `localStorage` LANZA. Sin try/catch, el arranque entero se cae y
    la pagina se queda en blanco. En un portatil corporativo esto no es un caso
    raro."""
    fuente = _texto(APP)
    for firma in ("function vistaRecordada()", "function recordarVista(name)"):
        cuerpo = _cuerpo_de(fuente, firma)
        assert "try" in cuerpo and "catch" in cuerpo, f"{firma} sin proteger"


def test_la_vista_no_se_aplica_dentro_de_applyProfile():
    """Y NO puede ir ahi, aunque sea el sitio obvio.

    `applyProfile()` se llama tambien cada vez que el panel de administrador
    previsualiza un cambio. Aplicar la vista ahi devolveria el grafo a `explore`
    a media investigacion, cada vez que alguien abre el panel.
    """
    cuerpo = _cuerpo_de(_texto(APP), "function applyProfile(profile)")
    assert "setView" not in cuerpo


# ------------------------------------------------ 2. los nodos que se clavaban

def test_cambiar_de_disposicion_suelta_los_tres_ejes():
    """EL FALLO QUE MAS ENSUCIABA, y el unico que empeoraba con el uso.

    Con `fixOnDrag` activo -que lo esta por defecto-, arrastrar un nodo le fija
    `fx`, `fy` y `fz`. Pero `applyLayout()` solo limpiaba `fx`. Cada nodo movido
    alguna vez quedaba clavado en Y y en Z para siempre, en las tres vistas.
    Como el desorden crecia poco a poco, no parecia un fallo sino la herramienta
    siendo asi.
    """
    fuente = _texto(GRAPH3D)
    soltar = _cuerpo_de(fuente, "function soltarTodo()")
    for eje in ("fx", "fy", "fz"):
        assert f"node.{eje} = undefined" in soltar, f"{eje} sigue clavado"

    layout = _cuerpo_de(fuente, "function applyLayout()")
    assert "soltarTodo()" in layout, "applyLayout no suelta nada antes de recolocar"


def test_soltar_va_antes_de_fijar_las_posiciones_nuevas():
    """El orden importa: si se soltara DESPUES, se borraria el `fx` que la
    propia disposicion acaba de calcular y las capas desaparecerian."""
    layout = _cuerpo_de(_texto(GRAPH3D), "function applyLayout()")
    assert layout.index("soltarTodo()") < layout.index("node.fx = node.__gdLevel")


def test_hay_forma_de_soltar_sin_cambiar_de_vista():
    """`releaseFixed()` estaba exportada y NO LA LLAMABA NADIE.

    Un pinchazo del que no se puede salir no es una funcion, es una trampa. Y la
    ayuda anunciaba 'arrastrar nodo: fijarlo en su sitio' sin decir como
    deshacerlo, porque no se podia.
    """
    assert "graph3d.releaseFixed()" in _texto(APP), "sigue siendo codigo muerto"
    assert "soltarFijados" in _texto(INTERACCIONES), "sin tecla que lo dispare"


def test_la_tecla_de_soltar_esta_en_la_ayuda():
    """Un atajo que no esta en la ayuda no existe: nadie lo va a adivinar."""
    fuente = _texto(INTERACCIONES)
    assert re.search(r"\['x',\s*'soltar", fuente), "la tecla x no se documenta"


# --------------------------------------------------- 3. la camara y el encuadre

def test_cambiar_de_vista_reorienta_la_camara():
    """Sin esto, la kill-chain 'funciona' pero deja de leerse.

    El eje X sigue bien puesto; lo que pasa es que apunta hacia la camara o en
    diagonal, y el resultado practico es que pulsar el boton parece no hacer
    nada.
    """
    fuente = _texto(GRAPH3D)
    assert "function orientarParaLeer(" in fuente
    cuerpo = _cuerpo_de(fuente, "export function setView(name)")
    assert "orientarParaLeer(" in cuerpo


def test_solo_se_reorienta_donde_el_eje_significa_algo():
    """En `explore` no hay eje que enderezar, y girarle la camara al analista
    sin motivo es peor que no hacer nada."""
    fuente = _texto(GRAPH3D)
    assert "VISTAS_CON_EJE" in fuente
    cuerpo = _cuerpo_de(fuente, "function orientarParaLeer(ms)")
    assert "VISTAS_CON_EJE.has(view)" in cuerpo


def test_el_encuadre_espera_a_que_la_simulacion_pare():
    """Se hacia con un `setTimeout` de 700 ms puesto a ojo.

    Con `warmupTicks: 40` y `cooldownTicks: 320`, a los 700 ms la simulacion
    sigue reacomodando Y y Z: el encuadre se calculaba sobre posiciones a medio
    asentar y quedaba mal centrado justo despues de una accion deliberada.
    """
    fuente = _texto(GRAPH3D)
    assert ".onEngineStop(" in fuente, "el encuadre sigue yendo a ojo"
    assert "ajustePendiente" in fuente

    cuerpo = _cuerpo_de(_texto(APP), "function setView(name)")
    assert "setTimeout" not in cuerpo, "sigue habiendo un temporizador a ojo"


def test_el_encuadre_no_se_dispara_solo():
    """`onEngineStop` salta en CADA parada de la simulacion, y hay muchas: cada
    ingesta, cada filtro, cada expansion de vecinos. Sin la bandera, esto le
    movería la camara al analista mientras trabaja."""
    fuente = _texto(GRAPH3D)
    inicio = fuente.index(".onEngineStop(")
    bloque = fuente[inicio:inicio + 600]
    assert "if (!ajustePendiente) return;" in bloque
    assert "ajustePendiente = false;" in bloque, "sin desarmarla, encuadra siempre"


def test_el_boton_de_vista_contesta_enseguida():
    """Esperar SOLO a que pare la simulacion deja el boton mudo varios segundos.

    Con `cooldownTicks: 320` el encuadre definitivo tarda, y un control que no
    contesta parece roto. Por eso hay DOS encuadres: uno aproximado en cuanto la
    camara acaba de girar -en las vistas con eje, el X ya esta fijo, asi que
    acierta casi del todo- y el definitivo al parar.
    """
    cuerpo = _cuerpo_de(_texto(GRAPH3D), "export function setView(name)")
    assert "zoomToFit" in cuerpo, "sin encuadre inmediato el boton parece mudo"
    assert "ajustePendiente = true" in cuerpo, "y sin el definitivo queda mal centrado"
