"""El recorrido de una entidad: que hizo, en que orden y por que arista.

El grafo ensena el estado final de un incidente. Estos tests cubren la otra
mitad: poder contarlo en el orden en que paso.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from glamdring.graph import story
from glamdring.graph.query import build_filtered
from glamdring.main import app


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def loaded(client):
    client.post("/api/demo")
    return client


@pytest.fixture
def jlopez(all_events):
    graph = build_filtered(all_events, focus="user:jlopez", hops=1, max_nodes=0)
    return story.build(graph, all_events, "user:jlopez")


# ------------------------------------------------------------------ estructura


def test_the_story_is_chronological(jlopez):
    """Un recorrido que salta hacia atras en el tiempo no se entiende."""
    times = [step["time"] for step in jlopez["steps"]]
    assert times == sorted(times)


def test_every_step_names_its_link(jlopez):
    """Sin la arista, la camara no sabe a donde volar ni que iluminar."""
    assert jlopez["steps"]
    for step in jlopez["steps"]:
        assert step["linkId"]
        assert step["fromId"] and step["toId"]


def test_every_step_touches_the_entity(jlopez):
    """Es SU historia: una arista entre otros dos no pinta nada aqui."""
    for step in jlopez["steps"]:
        assert "user:jlopez" in (step["fromId"], step["toId"])


def test_the_other_end_is_the_counterpart(jlopez):
    """`otherId` es a donde mira la camara: nunca puede ser uno mismo."""
    for step in jlopez["steps"]:
        assert step["otherId"] != "user:jlopez"
        assert step["otherId"] in (step["fromId"], step["toId"])


def test_direction_is_explicit(jlopez):
    """Que lo hizo el o se lo hicieron a el cambia la lectura del paso."""
    for step in jlopez["steps"]:
        assert step["outbound"] == (step["fromId"] == "user:jlopez")


def test_every_step_can_open_its_log(jlopez):
    """Un paso del que no se puede volver al log crudo no es defendible."""
    for step in jlopez["steps"]:
        assert step["uids"]
        assert len(step["uids"]) == step["count"]


# ------------------------------------------------------------------- contenido


def test_the_story_is_in_spanish_and_says_something(jlopez):
    """Las frases salen de report.narrative: las mismas que el informe."""
    blob = " ".join(step["text"] for step in jlopez["steps"]).lower()
    assert "powershell.exe" in blob
    assert "jlopez" in blob


def test_repeats_collapse_into_one_stop(all_events):
    """Catorce fallos identicos son un hecho, no catorce paradas de camara."""
    graph = build_filtered(all_events, focus="user:administrator", hops=1, max_nodes=0)
    result = story.build(graph, all_events, "user:administrator")
    if not result["steps"]:
        pytest.skip("la demo no trae repeticiones para este usuario")
    for step in result["steps"]:
        assert step["count"] == len(step["uids"])
        if step["count"] > 1:
            assert step["until"] is not None
            assert step["until"] >= step["time"]


def test_the_story_is_deterministic(all_events):
    """Dos llamadas iguales tienen que dar el mismo recorrido, paso a paso."""
    graph = build_filtered(all_events, focus="user:jlopez", hops=1, max_nodes=0)
    first = story.build(graph, all_events, "user:jlopez")["steps"]
    second = story.build(graph, all_events, "user:jlopez")["steps"]
    assert [s["linkId"] for s in first] == [s["linkId"] for s in second]
    assert [s["text"] for s in first] == [s["text"] for s in second]


def test_a_node_with_no_events_is_not_a_crash(all_events):
    graph = build_filtered(all_events, focus="user:jlopez", hops=1, max_nodes=0)
    result = story.build(graph, all_events, "host:no-existe-esta-maquina")
    assert result["found"] is False
    assert result["steps"] == []


def test_long_stories_are_trimmed_but_stay_in_order(all_events):
    graph = build_filtered(all_events, focus="host:wks-0421", hops=1, max_nodes=0)
    result = story.build(graph, all_events, "host:wks-0421", limit=3)
    assert len(result["steps"]) <= 3
    times = [step["time"] for step in result["steps"]]
    assert times == sorted(times), "recortar por gravedad no puede desordenar el tiempo"


# ------------------------------------------------------------------------ API


def test_endpoint_returns_story_and_subgraph(loaded):
    """Las dos cosas en una llamada: lo que se queda en pantalla y el recorrido.

    Pedirlas por separado abriria la puerta a que no cuadren entre si.
    """
    payload = loaded.get("/api/graph/story", params={"node": "user:jlopez"}).json()
    assert payload["steps"]
    assert payload["graph"]["nodes"]
    ids = {node["id"] for node in payload["graph"]["nodes"]}
    for step in payload["steps"]:
        assert step["otherId"] in ids, "la camara no puede volar a un nodo que no esta"


def test_endpoint_isolates_the_neighbourhood(loaded):
    """Lo que devuelve tiene que ser MENOS que el grafo entero: de eso se trata."""
    whole = loaded.get("/api/graph").json()
    focused = loaded.get("/api/graph/story", params={"node": "user:jlopez"}).json()
    assert len(focused["graph"]["nodes"]) < len(whole["nodes"])


def test_endpoint_404_for_an_unknown_node(loaded):
    response = loaded.get("/api/graph/story", params={"node": "host:no-existe"})
    assert response.status_code == 404


def test_endpoint_without_data_is_404(client):
    client.post("/api/reset")
    assert client.get("/api/graph/story",
                      params={"node": "user:jlopez"}).status_code == 404
