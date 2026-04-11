"""
Habla DSL — Clase base abstracta para todos los backends de generacion de codigo.

Cada backend (Python, Go, Rust, C) hereda de HablaBackend y define:
  - generate(ast) -> str       : convierte el AST a codigo fuente del target
  - file_extension() -> str    : extension del archivo generado (.py, .go, .rs, .c)
  - compile_command(path) -> str | None : comando para compilar (None si interpretado)

La arquitectura multi-target funciona asi:
  .habla -> Lexer -> Parser -> AST (compartido) -> Backend especifico -> codigo target
"""

from __future__ import annotations
from abc import ABC, abstractmethod
from typing import Optional

from ..ast_nodes import Program


class HablaBackend(ABC):
    """
    Interfaz abstracta que deben implementar todos los backends de Habla.

    El AST es identico para todos los targets — solo el backend de generacion
    de codigo cambia. Esto permite escribir codigo Habla una vez y compilarlo
    a Python, Go, Rust o C sin modificaciones.
    """

    @abstractmethod
    def generate(self, ast: Program) -> str:
        """
        Recibe el AST de un programa Habla y devuelve codigo fuente
        en el lenguaje target como string.

        Args:
            ast: raiz del AST (nodo Program)

        Returns:
            Codigo fuente listo para escribir a disco o ejecutar
        """
        ...

    @abstractmethod
    def file_extension(self) -> str:
        """
        Extension del archivo generado.

        Returns:
            ".py" | ".go" | ".rs" | ".c"
        """
        ...

    @abstractmethod
    def compile_command(self, source_path: str) -> Optional[str]:
        """
        Comando para compilar el archivo generado, si el target lo requiere.
        Devuelve None si el lenguaje es interpretado (como Python).

        Args:
            source_path: ruta al archivo fuente generado

        Returns:
            Comando de compilacion como string, o None si no aplica.

        Ejemplos:
            Python  -> None
            Go      -> "go build {source_path}"
            Rust    -> "rustc {source_path}" o "cargo build"
            C       -> "gcc -o output {source_path} -lpcap -lssl"
        """
        ...

    @abstractmethod
    def status(self) -> str:
        """
        Estado de implementacion de este backend.

        Returns:
            "funcional" | "stub" | "experimental"
        """
        ...

    @abstractmethod
    def description(self) -> str:
        """Descripcion de casos de uso para este target."""
        ...


# ─── Registry de backends disponibles ────────────────────────────────────────

_BACKEND_REGISTRY: dict[str, dict] = {
    "python": {
        "version": "0.1",
        "status": "funcional",
        "description": "Scripting, OSINT, automatizacion",
        "module": "habla.backends.python_transpiler",
        "class": "PythonTranspiler",
        "extension": ".py",
        "compile_cmd": None,
    },
    "go": {
        "version": "0.1",
        "status": "stub",
        "description": "Scanners concurrentes, binarios standalone",
        "module": "habla.backends.go_backend",
        "class": "GoBackend",
        "extension": ".go",
        "compile_cmd": "go build {path}",
    },
    "rust": {
        "version": "0.1",
        "status": "stub",
        "description": "Fuzzing, parsers, memory-safe tools",
        "module": "habla.backends.rust_transpiler",
        "class": "RustTranspiler",
        "extension": ".rs",
        "compile_cmd": "rustc {path}",
    },
    "c": {
        "version": "0.1",
        "status": "funcional",
        "description": "Exploits, shellcode, kernel modules",
        "module": "habla.backends.c_transpiler",
        "class": "CTranspiler",
        "extension": ".c",
        "compile_cmd": "gcc -o output {path}",
    },
}


def list_backends() -> dict[str, dict]:
    """Devuelve el registry de todos los backends disponibles."""
    return _BACKEND_REGISTRY


__all__ = ["HablaBackend", "list_backends"]
