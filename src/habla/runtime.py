"""
Habla DSL — Runtime.
Orquesta el pipeline completo: normalizar -> lexer -> parser -> transpiler -> exec.
"""

from __future__ import annotations
import sys
import traceback
from pathlib import Path
from typing import Optional

from .normalizer import normalize
from .lexer import Lexer
from .parser import Parser
from .backends import get_backend
from .errors import HablaError, IncompleteError


def compile_to_source(source_or_path: str, target: str = "python", filename: str = "<input>") -> str:
    """
    Compila codigo Habla a codigo del target especificado.

    Args:
        source_or_path: codigo Habla como string
        target: "python", "c", "rust"
        filename: nombre del archivo (para mensajes de error)

    Returns:
        Codigo fuente generado como string
    """
    normalized = normalize(source_or_path)
    lexer = Lexer(normalized, filename=filename)
    tokens = lexer.tokenize()
    parser = Parser(tokens, filename=filename)
    ast = parser.parse()
    backend = get_backend(target, ast)
    return backend.emit()


def run_source(source: str, filename: str = "<input>", namespace: Optional[dict] = None) -> dict:
    """
    Compila y ejecuta codigo Habla.

    Args:
        source: codigo Habla como string
        filename: nombre del archivo
        namespace: namespace donde ejecutar; se crea uno nuevo si es None

    Returns:
        El namespace despues de ejecucion
    """
    python_code = compile_to_source(source, target="python", filename=filename)
    if namespace is None:
        namespace = {}
    exec(compile(python_code, filename, "exec"), namespace)
    return namespace


def run(filepath: str, target: str = "python") -> None:
    """
    Ejecuta un archivo .habla.
    Para targets C/Rust, imprime el codigo generado (no compila nativamente en v0.1).
    """
    path = Path(filepath)
    if not path.exists():
        print(f"habla: archivo no encontrado: {filepath}", file=sys.stderr)
        sys.exit(1)

    source = path.read_text(encoding="utf-8")

    if target == "python":
        try:
            run_source(source, filename=str(path))
        except HablaError as e:
            print(f"habla: {e}", file=sys.stderr)
            sys.exit(1)
        except SystemExit:
            raise
        except Exception as e:
            print(f"habla: error de ejecucion: {e}", file=sys.stderr)
            if "--debug" in sys.argv:
                traceback.print_exc()
            sys.exit(1)
    else:
        # Para C y Rust: generar y mostrar codigo
        try:
            code = compile_to_source(source, target=target, filename=str(path))
            print(code)
        except HablaError as e:
            print(f"habla: {e}", file=sys.stderr)
            sys.exit(1)


def repl(target: str = "python") -> None:
    """REPL interactivo de Habla."""
    print(f"Habla v0.1.0 — target: {target}")
    print('Escribe codigo Habla. "salir" para terminar, "ayuda" para ver comandos.')
    print()

    namespace: dict = {}
    buffer: list = []

    while True:
        try:
            prompt = "habla> " if not buffer else "    .. "
            try:
                line = input(prompt)
            except EOFError:
                print()
                break

            if line.strip() in ("salir", "exit", "quit"):
                break

            if line.strip() == "ayuda":
                _print_repl_help()
                continue

            if line.strip() == "limpiar":
                namespace = {}
                buffer = []
                print("(namespace limpiado)")
                continue

            buffer.append(line)
            source = "\n".join(buffer)

            # Intentar ejecutar
            try:
                run_source(source, filename="<repl>", namespace=namespace)
                buffer = []
            except IncompleteError:
                # Necesita mas input
                continue
            except HablaError as e:
                print(f"Error: {e}")
                buffer = []
            except Exception as e:
                print(f"Error de ejecucion: {e}")
                buffer = []

        except KeyboardInterrupt:
            print()
            buffer = []
            continue


def _print_repl_help():
    print("""
Comandos del REPL:
  salir         — salir del REPL
  limpiar       — limpiar el namespace y el buffer
  ayuda         — mostrar esta ayuda

Ejemplos:
  muestra "Hola mundo"
  x = 42
  muestra x
  escanea target "127.0.0.1" en ports [22, 80]
""")
