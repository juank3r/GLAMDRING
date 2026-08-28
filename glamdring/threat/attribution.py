"""Atribucion por solape de herramientas: que grupos encajan con lo observado.

AVISO QUE NO ES DECORATIVO
--------------------------
Esto produce una **hipotesis**, nunca un veredicto. Los grupos de ransomware
comparten afiliados, compran los mismos accesos y usan las mismas cuatro
utilidades: PsExec, AnyDesk, Rclone y Mimikatz aparecen en casi todos los
perfiles. Un solape de herramientas dice "esto se parece a", no "esto es".

Por eso el modulo hace tres cosas a proposito:

1. **Pesa por rareza.** Una herramienta que usan quince de diecisiete grupos no
   distingue nada; una que usan dos, si. Es la idea del IDF.
2. **Normaliza por tamano del perfil.** Sin esto, el grupo con noventa y seis
   herramientas documentadas ganaria siempre, no por parecerse mas sino por
   tener el perfil mas largo.
3. **Devuelve siempre el nivel de confianza y el aviso**, y separa la evidencia
   decisiva (una nota de rescate) de la circunstancial (un PsExec).

Lo que si es util de verdad: orientar la busqueda. Si el candidato es Akira,
merece la pena ir a buscar las otras cosas que hace Akira.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Set

from .catalog import Catalog, catalog
from .detect import Findings

# Cuantas herramientas discriminantes hacen falta para cada nivel de confianza.
CONFIDENCE_THRESHOLDS = [
    (4, "media"),
    (2, "baja"),
]

# Una herramienta que usan mas de esta fraccion de los grupos conocidos no
# aporta nada a la atribucion. Se sigue contando como evidencia de intrusion,
# pero no suma puntos para senalar a nadie.
UBIQUITY_CUTOFF = 0.6


@dataclass
class Candidate:
    group: str
    score: float
    matched: List[str] = field(default_factory=list)
    discriminating: List[str] = field(default_factory=list)
    note_match: List[str] = field(default_factory=list)
    note_strength: float = 0.0
    coverage: float = 0.0            # que fraccion del perfil del grupo se ha visto
    confidence: str = "no concluyente"
    description: str = ""
    sources: List[Dict[str, str]] = field(default_factory=list)

    def as_dict(self) -> Dict[str, Any]:
        return {
            "group": self.group,
            "score": round(self.score, 3),
            "confidence": self.confidence,
            "matched": self.matched,
            "discriminating": self.discriminating,
            "noteMatch": self.note_match,
            "noteStrength": round(self.note_strength, 2),
            "coverage": round(self.coverage, 3),
            "description": self.description,
            "sources": self.sources,
        }


# Cuantos grupos pueden compartir un nombre de nota antes de que ese nombre deje
# de servir para atribuir. 'README.txt' lo usan decenas de familias; el nombre por
# si solo no senala a nadie.
NOTE_UNIQUE = 1        # una sola familia -> evidencia decisiva
NOTE_USEFUL = 3        # hasta tres -> orienta, no concluye


def _note_strength(groups_for_note: int) -> float:
    """Cuanto vale como prueba encontrar esta nota concreta.

    Una nota que solo usa una familia practicamente cierra la atribucion. Una
    que comparten veinte no dice nada mas que "esto es ransomware", que ya lo
    sabiamos por el resto de senales.
    """
    if groups_for_note <= NOTE_UNIQUE:
        return 10.0
    if groups_for_note <= NOTE_USEFUL:
        return 3.0
    if groups_for_note <= 8:
        return 0.8
    return 0.1


def _confidence(discriminantes: int, nota_fuerza: float) -> str:
    """Nivel de confianza, exigiendo que la nota sea especifica de verdad.

    Antes bastaba con encontrar CUALQUIER nota para dar confianza alta, y eso
    colocaba arriba a grupos que solo compartian el nombre de fichero
    'README.txt' sin una sola herramienta en comun. Una atribucion asi es peor
    que no atribuir: manda al analista a buscar el arsenal equivocado.
    """
    if nota_fuerza >= 10.0:
        return "alta"
    if nota_fuerza >= 3.0 and discriminantes >= 1:
        return "media"
    for minimo, etiqueta in CONFIDENCE_THRESHOLDS:
        if discriminantes >= minimo:
            return etiqueta
    return "no concluyente"


def attribute(findings: Findings, kb: Optional[Catalog] = None,
              limit: int = 6) -> List[Candidate]:
    """Ordena los grupos conocidos por su encaje con lo observado."""
    kb = kb or catalog()
    if not kb.available or not kb.groups:
        return []

    observadas: Set[str] = findings.tool_names()

    # Grupos senalados por una nota de rescate reconocida. Se guarda tambien
    # CUANTOS grupos comparten esa nota, porque de eso depende lo que vale.
    grupos_por_nota: Dict[str, Dict[str, float]] = {}
    for note in findings.notes:
        if not note.known or not note.groups:
            continue
        fuerza = _note_strength(len(note.groups))
        for grupo in note.groups:
            # Deduplicado: la misma nota en ocho equipos es una sola prueba.
            entrada = grupos_por_nota.setdefault(grupo, {})
            entrada[note.filename] = max(entrada.get(note.filename, 0.0), fuerza)

    # Se comparan en minusculas porque los nombres vienen de dos fuentes
    # distintas y no siempre coinciden en mayusculas ni en espacios.
    nota_lower = {nombre.lower().replace(" ", ""): ficheros
                  for nombre, ficheros in grupos_por_nota.items()}

    if not observadas and not nota_lower:
        return []

    candidatos: List[Candidate] = []
    umbral_ubicuidad = kb.group_count * UBIQUITY_CUTOFF

    for nombre, grupo in kb.groups.items():
        del_grupo: Set[str] = set(grupo.get("tools", []))
        if not del_grupo:
            continue

        coincidentes = sorted(observadas & del_grupo)
        clave = nombre.lower().replace(" ", "")
        notas_grupo = nota_lower.get(clave, {})
        ficheros_nota = sorted(notas_grupo)
        fuerza_nota = max(notas_grupo.values(), default=0.0)

        if not coincidentes and not ficheros_nota:
            continue

        # Puntuacion: suma de pesos de lo coincidente, normalizada por la raiz
        # del peso total del perfil. La raiz y no el total: penalizar linealmente
        # por tamano castigaria demasiado a los grupos bien documentados.
        peso_coincidente = sum(kb.discriminating_weight(t) for t in coincidentes)
        peso_perfil = sum(kb.discriminating_weight(t) for t in del_grupo) or 1.0
        score = peso_coincidente / math.sqrt(peso_perfil)

        # DOS EJES, no uno. Que la usen pocos grupos de ransomware dice si
        # distingue a un grupo DE OTRO GRUPO; que la use gente legitima dice si
        # distingue un ataque DE UN MARTES CUALQUIERA.
        #
        # Solo se miraba el primero, y con eso AnyDesk (8 de 17 grupos) contaba
        # como pista discriminante. Esta instalado en medio departamento de
        # sistemas del mundo.
        discriminantes = [
            t for t in coincidentes
            if kb.tool_group_count.get(t, 0) <= umbral_ubicuidad
            and not kb.is_dual_use(t)
        ]

        # La nota suma segun lo especifica que sea, no por el mero hecho de
        # existir. Una nota unica de la familia domina el ranking; un
        # 'README.txt' compartido por veinte familias apenas mueve la aguja.
        score += fuerza_nota

        candidatos.append(Candidate(
            group=nombre,
            score=score,
            matched=coincidentes,
            discriminating=discriminantes,
            note_match=ficheros_nota,
            note_strength=fuerza_nota,
            coverage=len(coincidentes) / len(del_grupo),
            confidence=_confidence(len(discriminantes), fuerza_nota),
            description=grupo.get("description", "")[:400],
            sources=grupo.get("sources", [])[:3],
        ))

    candidatos.sort(key=lambda c: (-c.score, -len(c.discriminating), c.group))
    return candidatos[:limit]


def assess(findings: Findings, kb: Optional[Catalog] = None) -> Dict[str, Any]:
    """Valoracion completa, lista para la API y el informe."""
    kb = kb or catalog()
    candidatos = attribute(findings, kb)

    # Herramientas vistas que NO sirven para atribuir, porque las usa casi todo
    # el mundo. Se listan aparte para que quede claro por que no puntuan.
    umbral = kb.group_count * UBIQUITY_CUTOFF
    ubicuas = sorted(
        t for t in findings.tool_names()
        if kb.tool_group_count.get(t, 0) > umbral or kb.is_dual_use(t)
    )
    # Y las que no aparecen en ningun perfil conocido: pueden ser lo mas
    # interesante del incidente, porque nadie las ha documentado todavia.
    sin_perfil = sorted(
        t for t in findings.tool_names()
        if kb.tool_group_count.get(t, 0) == 0
    )

    mejor = candidatos[0] if candidatos else None
    return {
        "candidates": [c.as_dict() for c in candidatos],
        "best": mejor.as_dict() if mejor else None,
        "confidence": mejor.confidence if mejor else "no concluyente",
        "ubiquitousTools": ubicuas,
        "undocumentedTools": sin_perfil,
        "caveat": kb.meta.get("caveat", ""),
        "sources": kb.meta.get("sources", []),
        "catalog": {
            "tools": len(kb.tools),
            "groups": len(kb.groups),
            "ransomNotes": len(kb.notes),
            "generated": kb.meta.get("generated"),
        },
    }


def explain(candidate: Candidate, kb: Optional[Catalog] = None) -> str:
    """Frase para el informe, honesta con el nivel de confianza."""
    kb = kb or catalog()

    if candidate.note_match and candidate.note_strength < 3.0:
        notas = ", ".join(candidate.note_match[:3])
        return (
            f"Se ha encontrado la nota «{notas}», pero ese nombre de fichero lo "
            f"comparten muchas familias, asi que no senala a {candidate.group} "
            f"mas que a cualquier otra. Confirma que es ransomware; no dice cual."
        )

    if candidate.note_match:
        notas = ", ".join(candidate.note_match[:3])
        return (
            f"Se ha encontrado la nota de rescate «{notas}», que en el indice de "
            f"ransomware.live esta asociada a {candidate.group}. Junto con "
            f"{len(candidate.matched)} herramienta(s) de su perfil documentado, "
            f"es la atribucion mas solida disponible; aun asi, conviene "
            f"confirmarla con el binario cifrador y con la infraestructura de pago."
        )

    if candidate.confidence == "media":
        raras = ", ".join(candidate.discriminating[:4])
        return (
            f"El conjunto de herramientas observado encaja con {candidate.group}. "
            f"Pesan sobre todo {raras}, que aparecen en pocos perfiles conocidos. "
            f"Es una hipotesis razonable para orientar la busqueda, no una "
            f"identificacion."
        )

    if candidate.confidence == "baja":
        return (
            f"Hay un solape parcial con el perfil de {candidate.group} "
            f"({len(candidate.matched)} herramientas). Es demasiado poco para "
            f"atribuir: sirve para saber que buscar a continuacion."
        )

    return (
        f"El solape con {candidate.group} se explica por herramientas de uso "
        f"generalizado. No permite atribuir nada."
    )
