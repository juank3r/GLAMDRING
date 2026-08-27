"""La cache del grafo construido.

build_graph() recorre todos los eventos y extrae nodos y aristas. Con 12.600
eventos son mas de seis segundos, y se ejecutaba entero en CADA peticion: cada
vez que el analista movia un filtro o cambiaba de vista. Medido contra el
servidor, 9,5 s por llamada, y la segunda costaba lo mismo que la primera.

Estos tests cubren lo unico que puede salir mal al cachear: que lo cacheado se
contamine entre llamadas, o que no caduque cuando debe.
"""

from __future__ import annotations

import pytest

from glamdring.graph.query import build_filtered, cache_clear, cache_info
from glamdring.store import EventStore


@pytest.fixture(autouse=True)
def cache_limpia():
    cache_clear()
    yield
    cache_clear()


@pytest.fixture
def store(all_events):
    almacen = EventStore()
    almacen.add(all_events, "test")
    return almacen


def _consulta(store, **kw):
    return build_filtered(store.events, version=store.version, **kw)


# --------------------------------------------------------------- resultados


def test_the_cached_answer_is_identical(store):
    """Lo unico innegociable: cachear no puede cambiar lo que se devuelve."""
    primera = _consulta(store)
    segunda = _consulta(store)

    assert [n.id for n in primera.nodes] == [n.id for n in segunda.nodes]
    assert [n.risk for n in primera.nodes] == [n.risk for n in segunda.nodes]
    assert [(n.props or {}).get("role") for n in primera.nodes] \
        == [(n.props or {}).get("role") for n in segunda.nodes]
    assert [l.id for l in primera.links] == [l.id for l in segunda.links]


def test_enrichment_does_not_leak_between_calls(store):
    """El fallo que la cache invita a cometer.

    enrich() escribe en node.props. Si se sirviera el objeto cacheado tal cual,
    el papel calculado para una consulta se quedaria pegado y contaminaria la
    siguiente, que puede tener otro subconjunto de nodos y por tanto otros
    papeles. Por eso se copia antes de enriquecer.
    """
    completo = _consulta(store)
    papeles_completo = {n.id: (n.props or {}).get("role") for n in completo.nodes}

    # Una consulta acotada: los papeles pueden salir distintos, y deben.
    _consulta(store, focus="host:wks-0421", hops=1)

    otra_vez = _consulta(store)
    assert {n.id: (n.props or {}).get("role") for n in otra_vez.nodes} == papeles_completo


def test_different_event_filters_do_not_share(store):
    """Dos filtros de evento distintos son dos grafos distintos."""
    todo = _consulta(store)
    graves = _consulta(store, min_severity=4)
    assert len(graves.nodes) < len(todo.nodes)


def test_graph_level_filters_reuse_the_same_build(store):
    """Los filtros que actuan sobre el grafo ya construido comparten cache.

    Son los que mas se tocan en la interfaz: los chips de tipo de entidad y de
    relacion. Que no obliguen a reconstruir es la mitad de la ganancia.
    """
    _consulta(store)
    entradas = cache_info()["entries"]
    _consulta(store, entity_types=["host"])
    _consulta(store, relation_types=["executed"])
    _consulta(store, focus="host:wks-0421", hops=2)
    assert cache_info()["entries"] == entradas, "no deberian haber creado entradas nuevas"


# ------------------------------------------------------------- invalidacion


def test_new_events_invalidate(store, all_events):
    """Si entran datos nuevos, lo cacheado deja de valer."""
    antes = _consulta(store)
    version_antes = store.version

    # Con actor y proceso, para que genere aristas: prune descarta los nodos
    # aislados de bajo riesgo, asi que un evento suelto no anadiria nada.
    from glamdring.models import ActorRef, HostRef, NormalizedEvent, ProcRef
    from datetime import datetime, timezone
    store.add([NormalizedEvent(
        uid="cache-nuevo-1",
        time=datetime(2026, 8, 19, 11, 0, tzinfo=timezone.utc),
        class_name="Process Activity", activity="launch",
        actor=ActorRef(user="recien-llegada"),
        device=HostRef(hostname="maquina-que-no-estaba"),
        process=ProcRef(name="algo.exe"),
    )], "nuevos")

    assert store.version > version_antes
    despues = _consulta(store)
    assert len(despues.nodes) > len(antes.nodes)
    assert any(n.id == "host:maquina-que-no-estaba" for n in despues.nodes)


def test_duplicates_do_not_invalidate(store, all_events):
    """Reingerir lo mismo no cambia el grafo: tirar la cache seria gratuito."""
    version = store.version
    store.add(list(all_events), "otra vez")
    assert store.version == version


def test_clearing_the_store_invalidates(store):
    _consulta(store)
    version = store.version
    store.clear()
    assert store.version > version
    assert _consulta(store).nodes == []


def test_without_version_there_is_no_cache(store):
    """Sin version no se cachea: es como lo llaman los tests y las herramientas."""
    cache_clear()
    build_filtered(store.events)
    build_filtered(store.events)
    assert cache_info()["entries"] == 0


def test_the_cache_does_not_grow_without_limit(store):
    """Cada grafo grande ocupa decenas de MB: hay que poner un techo."""
    for severidad in range(6):
        _consulta(store, min_severity=severidad)
    for texto in ("powershell", "certutil", "mimikatz", "rclone"):
        _consulta(store, text=texto)
    assert cache_info()["entries"] <= cache_info()["max"]


# --------------------------------------------- lo que faltaba en la clave


def test_cambiar_los_pesos_de_riesgo_invalida_lo_cacheado(all_events):
    """EL RIESGO SE CALCULA DENTRO DE LO QUE SE CACHEA.

    build_graph llama a enrich.score(), que lee el global _risk_weights, y ese
    global lo cambia el panel de administrador. Sin los pesos en la clave,
    cambiarlos no invalidaba nada: el panel confirmaba el cambio y el grafo
    seguia enseñando la puntuacion vieja.

    Medido antes del arreglo, dividiendo los pesos entre cuatro sobre el
    incidente minimo: el mismo nodo salia con riesgo 79 desde la cache y con 18
    al vaciarla a mano. Es peor que un fallo visible porque el numero que se
    queda en pantalla es plausible, y nadie sospecha de un riesgo 79.
    """
    from glamdring.graph.enrich import risk_weights, set_risk_weights

    cache_clear()
    almacen = EventStore()
    almacen.add(list(all_events), "test")

    def riesgos():
        grafo = build_filtered(almacen.events, version=almacen.version,
                               store_id=almacen.store_id)
        return {n.id: n.risk for n in grafo.nodes}

    originales = dict(risk_weights())
    try:
        antes = riesgos()
        assert antes, "hacen falta nodos para que la prueba diga algo"

        set_risk_weights({k: max(0, int(v) // 4) for k, v in originales.items()})
        despues = riesgos()

        cambiados = [k for k in antes if antes[k] != despues.get(k)]
        assert cambiados, (
            "los pesos cambiaron y el grafo cacheado sigue con la puntuacion vieja")
    finally:
        set_risk_weights(originales)
        cache_clear()


def test_dos_almacenes_distintos_no_se_pisan_en_la_cache(all_events):
    """`version` empieza en 0 en CADA almacen.

    Asi que dos incidentes recien cargados estan los dos en la version 1 y, sin
    filtros, producian la MISMA clave: se devolvia el grafo del otro incidente.
    No fallaba y no avisaba, y ademas era verosimil, que es lo peor que puede
    pasarle a una herramienta forense.

    Este test no existia, y por eso la suite no habria detectado la regresion:
    los tests que ya habia crean varios EventStore pero los cargan todos con los
    MISMOS eventos, asi que el grafo cacheado coincidia por casualidad.
    """
    cache_clear()

    uno = EventStore()
    uno.add(list(all_events), "uno")

    otro = EventStore()
    otro.add(list(all_events)[:3], "otro")

    assert uno.version == otro.version, "la premisa del fallo: misma version"
    assert uno.store_id != otro.store_id

    grafo_uno = build_filtered(uno.events, version=uno.version, store_id=uno.store_id)
    grafo_otro = build_filtered(otro.events, version=otro.version, store_id=otro.store_id)

    assert len(grafo_uno.nodes) != len(grafo_otro.nodes), (
        "el segundo almacen recibio el grafo del primero")

    # Y volver a pedir el primero sigue dando el primero.
    otra_vez = build_filtered(uno.events, version=uno.version, store_id=uno.store_id)
    assert len(otra_vez.nodes) == len(grafo_uno.nodes)
    cache_clear()
