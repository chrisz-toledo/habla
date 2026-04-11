"""
Habla DSL — CLI principal.

Uso:
  habla run script.habla                    # ejecuta con Python (default)
  habla run script.habla --target go        # muestra codigo Go generado
  habla compile script.habla                # transpila a Python (imprime)
  habla compile script.habla --target rust  # transpila a Rust
  habla compile script.habla --target go    # transpila a Go
  habla compile script.habla --target c     # transpila a C
  habla repl                                # REPL interactivo (Python)
  habla targets                             # lista backends disponibles
  habla --version                           # version actual
"""

from __future__ import annotations
import sys
import click

from . import __version__
from . import runtime


_VALID_TARGETS = ["python", "go", "rust", "c"]


@click.group()
@click.version_option(version=__version__, prog_name="habla")
def main():
    """Habla — A cybersecurity DSL for AI-native code generation.

    \b
    Spanish verbs. English nouns. Zero boilerplate.
    Transpiles to Python, Go, Rust, and C.
    """
    pass


@main.command()
@click.argument("file")
@click.option(
    "--target",
    type=click.Choice(_VALID_TARGETS, case_sensitive=False),
    default="python",
    show_default=True,
    help="Lenguaje de destino para la ejecucion/transpilacion",
)
@click.option("--debug", is_flag=True, help="Mostrar traceback completo en errores")
def run(file: str, target: str, debug: bool):
    """Ejecuta un archivo .habla.

    Para el target Python: compila y ejecuta directamente.
    Para otros targets (go, rust, c): genera y muestra el codigo equivalente.
    """
    from pathlib import Path
    from .errors import HablaError

    path = Path(file)
    if not path.exists():
        click.echo(f"habla: archivo no encontrado: {file}", err=True)
        sys.exit(1)

    if target == "python":
        if debug:
            sys.argv.append("--debug")
        runtime.run(str(path), target="python")
    else:
        # Para targets no-Python: mostrar el codigo generado
        source = path.read_text(encoding="utf-8")
        try:
            code = runtime.compile_to_source(source, target=target, filename=str(path))
            click.echo(f"// Codigo generado para target: {target}")
            click.echo(code)
        except HablaError as e:
            click.echo(f"habla: {e}", err=True)
            if debug:
                import traceback
                traceback.print_exc()
            sys.exit(1)


@main.command()
@click.argument("file")
@click.option(
    "--target",
    type=click.Choice(_VALID_TARGETS, case_sensitive=False),
    default="python",
    show_default=True,
    help="Lenguaje de destino",
)
@click.option("--out", "-o", default=None, help="Archivo de salida (default: stdout)")
def compile(file: str, target: str, out: str):
    """Transpila un archivo .habla y muestra (o guarda) el codigo generado."""
    from pathlib import Path
    from .errors import HablaError

    path = Path(file)
    if not path.exists():
        click.echo(f"habla: archivo no encontrado: {file}", err=True)
        sys.exit(1)

    source = path.read_text(encoding="utf-8")
    try:
        code = runtime.compile_to_source(source, target=target, filename=str(path))
        if out:
            Path(out).write_text(code, encoding="utf-8")
            click.echo(f"habla: codigo {target} guardado en: {out}")
        else:
            click.echo(code)
    except HablaError as e:
        click.echo(f"habla: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option(
    "--target",
    type=click.Choice(_VALID_TARGETS, case_sensitive=False),
    default="python",
    show_default=True,
    help="Lenguaje de destino del REPL",
)
def repl(target: str):
    """Inicia el REPL interactivo de Habla (Python backend)."""
    runtime.repl(target=target)


@main.command()
def targets():
    """Lista todos los backends de transpilacion disponibles y su estado."""
    from .backends import TARGETS

    click.echo("")
    click.echo("  Backends disponibles en Habla v" + __version__ + ":")
    click.echo("")

    status_color = {
        "funcional": "green",
        "stub": "yellow",
        "experimental": "cyan",
    }

    for name, info in TARGETS.items():
        status = info["status"]
        color = status_color.get(status, "white")
        status_styled = click.style(f"[{status}]", fg=color)
        desc = info["description"]
        ver = info["version"]
        ext = info["extension"]
        click.echo(f"  {name:<8} v{ver}  {status_styled:<22}  {desc}  (ext: {ext})")

    click.echo("")
    click.echo("  Uso:")
    click.echo("    habla run script.habla                   # Python (default)")
    click.echo("    habla run script.habla --target go        # Go")
    click.echo("    habla compile script.habla --target rust  # Rust")
    click.echo("    habla compile script.habla --target c     # C")
    click.echo("")


if __name__ == "__main__":
    main()
