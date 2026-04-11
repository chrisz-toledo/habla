"""
Habla DSL — Factory de backends de transpilacion.
"""

from __future__ import annotations
from ..transpiler import BaseTranspiler
from ..ast_nodes import Program


def get_backend(target: str, ast: Program) -> BaseTranspiler:
    """
    Retorna el transpiler correcto segun el target.

    Args:
        target: "python", "c", "rust"
        ast: AST del programa Habla

    Returns:
        Instancia del transpiler para ese target
    """
    target = target.lower()
    if target == "python":
        from .python_transpiler import PythonTranspiler
        return PythonTranspiler(ast)
    elif target == "c":
        from .c_transpiler import CTranspiler
        return CTranspiler(ast)
    elif target == "rust":
        from .rust_transpiler import RustTranspiler
        return RustTranspiler(ast)
    else:
        raise ValueError(f"Target desconocido: '{target}'. Opciones: python, c, rust")


__all__ = ["get_backend"]
