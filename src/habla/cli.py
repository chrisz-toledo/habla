"""
Habla DSL — CLI principal.
Uso: habla run script.habla
     habla compile [--target python|c|rust] script.habla
     habla repl [--target python]
     habla --version
"""

import sys
import click

from . import __version__
from . import runtime


@click.group()
@click.version_option(version=__version__, prog_name="habla")
def main():
    """Habla — A cybersecurity DSL for AI-native code generation."""
    pass


@main.command()
@click.argument("file")
@click.option("--debug", is_flag=True, help="Mostrar traceback completo en errores")
def run(file: str, debug: bool):
    """Ejecuta un archivo .habla."""
    if debug:
        sys.argv.append("--debug")
    runtime.run(file, target="python")


@main.command()
@click.argument("file")
@click.option(
    "--target",
    type=click.Choice(["python", "c", "rust"], case_sensitive=False),
    default="python",
    show_default=True,
    help="Lenguaje de destino",
)
def compile(file: str, target: str):
    """Transpila un archivo .habla y muestra el codigo generado."""
    from pathlib import Path
    from .errors import HablaError

    path = Path(file)
    if not path.exists():
        click.echo(f"habla: archivo no encontrado: {file}", err=True)
        sys.exit(1)

    source = path.read_text(encoding="utf-8")
    try:
        code = runtime.compile_to_source(source, target=target, filename=str(path))
        click.echo(code)
    except HablaError as e:
        click.echo(f"habla: {e}", err=True)
        sys.exit(1)


@main.command()
@click.option(
    "--target",
    type=click.Choice(["python", "c", "rust"], case_sensitive=False),
    default="python",
    show_default=True,
    help="Lenguaje de destino del REPL",
)
def repl(target: str):
    """Inicia el REPL interactivo de Habla."""
    runtime.repl(target=target)


if __name__ == "__main__":
    main()
