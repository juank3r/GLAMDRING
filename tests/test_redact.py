"""Que los secretos no lleguen al inspector, esten donde esten.

El log crudo se ensena tal cual, y los logs de autenticacion arrastran
credenciales. Antes solo se tachaba por NOMBRE de clave, lo que dejaba pasar el
caso mas frecuente: el secreto dentro de una cadena. El campo se llama `cmdline`
o `message`, no `password`.
"""

from __future__ import annotations

import pytest

from glamdring.store import REDACTED, redact

JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVPmB92K27uhbUJU1p1r"


# ---------------------------------------------------------- por nombre de clave


def test_secret_fields_are_redacted_by_name():
    crudo = {"user": "ana", "password": "Sup3rSecreta", "api_key": "abc123", "host": "srv-1"}
    limpio = redact(crudo)
    assert limpio["password"] == REDACTED
    assert limpio["api_key"] == REDACTED
    assert limpio["user"] == "ana", "lo que no es secreto no se toca"
    assert limpio["host"] == "srv-1"


# ------------------------------------------------------------ por forma del valor


@pytest.mark.parametrize("texto,fuga", [
    (f'curl -H "Authorization: Bearer {JWT}" https://api.corp', JWT),
    (f"token recibido {JWT} y guardado", JWT),
    ("sqlcmd -S srv -U sa -P Sup3rSecreta123", "Sup3rSecreta123"),
    ("mysql --password=Contrasena123 -h db", "Contrasena123"),
    ("https://usuario:Clave123@interno.corp/api", "Clave123"),
    ("conn: password=MiClave; server=db1", "MiClave"),
])
def test_secrets_inside_free_text_are_redacted(texto, fuga):
    """El caso que la lista de nombres no veia: el secreto dentro de la cadena."""
    limpio = redact({"cmdline": texto})["cmdline"]
    assert fuga not in limpio, f"se escapo el secreto: {limpio}"
    assert REDACTED in limpio


def test_the_rest_of_the_line_survives():
    """La linea de comandos es evidencia: se tacha el secreto, no el hallazgo.

    Borrarla entera protegeria la credencial a costa de perder el indicio, que
    es justo por lo que se esta mirando el log.
    """
    limpio = redact({"cmdline": "mysql --password=Contrasena123 -h db-produccion"})["cmdline"]
    assert "mysql" in limpio and "db-produccion" in limpio
    assert "Contrasena123" not in limpio


def test_an_innocent_command_line_is_left_alone():
    """Sin falsos positivos: una linea sospechosa pero sin credencial se conserva."""
    original = "powershell.exe -nop -w hidden -enc SQBFAFgAKABOAGUAdwA"
    assert redact({"cmdline": original})["cmdline"] == original


# ------------------------------------------------------------------ estructura


def test_nesting_does_not_smuggle_secrets_out():
    """Pasado el fondo se poda, no se devuelve el original.

    Antes `if depth > 6: return value` devolvia la rama entera sin tocar: bastaba
    con anidar siete niveles para sacar el secreto intacto.
    """
    hondo = {"password": "arriba"}
    for _ in range(9):
        hondo = {"nivel": hondo}
    texto = str(redact(hondo))
    assert "arriba" not in texto


def test_lists_are_walked_too():
    limpio = redact({"args": ["--user", "ana", "--password=Secreta123"]})
    assert "Secreta123" not in str(limpio)
