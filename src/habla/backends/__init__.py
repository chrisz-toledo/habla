"""
Habla DSL — Factory de backends de transpilacion.

Backends disponibles:
  python  [funcional]  Scripting, OSINT, automatizacion
  go      [stub]       Scanners concurrentes, binarios standalone
  rust    [stub]       Fuzzing, parsers, memory-safe tools
  c       [funcional]  Exploits, shellcode, kernel modules
"""

from __future__ import annotations
from ..transpiler import BaseTranspiler
from ..ast_nodes import Program


TARGETS = {
    "python": {
        "version": "0.1",
        "status": "funcional",
        "description": "Scripting, OSINT, automatizacion",
        "extension": ".py",
    },
    "go": {
        "version": "0.1",
        "status": "stub",
        "description": "Scanners concurrentes, binarios standalone",
        "extension": ".go",
    },
    "rust": {
        "version": "0.1",
        "status": "stub",
        "description": "Fuzzing, parsers, memory-safe tools",
        "extension": ".rs",
    },
    "c": {
        "version": "0.1",
        "status": "funcional",
        "description": "Exploits, shellcode, kernel modules",
        "extension": ".c",
    },
}


def get_backend(target: str, ast: Program) -> BaseTranspiler:
    """
    Retorna el transpiler correcto segun el target.

    Args:
        target: "python" | "go" | "rust" | "c"
        ast: AST del programa Habla

    Returns:
        Instancia del transpiler para ese target
    """
    target = target.lower()
    if target == "python":
        from .python_transpiler import PythonTranspiler
        return PythonTranspiler(ast)
    elif target == "go":
        from .go_backend import GoBackend
        return GoBackend(ast)
    elif target == "rust":
        from .rust_transpiler import RustTranspiler
        return RustTranspiler(ast)
    elif target == "c":
        from .c_transpiler import CTranspiler
        return CTranspiler(ast)
    else:
        valid = ", ".join(TARGETS.keys())
        raise ValueError(f"Target desconocido: '{target}'. Opciones: {valid}")


__all__ = ["get_backend", "TARGETS"]
