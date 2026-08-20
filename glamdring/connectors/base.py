"""Contrato comun de los conectores a SIEM.

Un conector solo tiene una responsabilidad: devolver registros crudos. No
normaliza, no construye grafo, no filtra por severidad. Asi cada SIEM nuevo se
anade escribiendo unas 60 lineas y nada mas del sistema cambia.
"""

from __future__ import annotations

import abc
from datetime import datetime
from typing import Any, Dict, List, Optional


class ConnectorError(RuntimeError):
    """Fallo al hablar con el SIEM.

    Se traduce a un 502 con mensaje legible: el analista tiene que poder
    distinguir "mi consulta esta mal" de "el SIEM no responde".
    """

    def __init__(self, connector: str, message: str, status: Optional[int] = None) -> None:
        super().__init__(f"[{connector}] {message}")
        self.connector = connector
        self.message = message
        self.status = status


class Connector(abc.ABC):
    """Fuente de registros crudos."""

    name: str = "base"
    query_language: str = ""
    example_query: str = ""

    @property
    @abc.abstractmethod
    def configured(self) -> bool:
        """True si hay credenciales suficientes para intentar la consulta."""

    @abc.abstractmethod
    async def fetch(
        self,
        query: str,
        time_from: Optional[datetime] = None,
        time_to: Optional[datetime] = None,
        limit: int = 10_000,
    ) -> List[Dict[str, Any]]:
        """Ejecuta la consulta y devuelve los registros tal cual llegan."""

    def describe(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "configured": self.configured,
            "queryLanguage": self.query_language,
            "exampleQuery": self.example_query,
        }
