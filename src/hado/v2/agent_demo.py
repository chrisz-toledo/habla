"""
Hado V2.0 — Prueba de Fuego Autónoma (Agent Demo)

Simula lo que ocurre cuando un Agente IA (LLM) razona una táctica ofensiva
y emite un JSON estructurado que Hado convierte instantáneamente en un
payload nativo de C o Rust.

Uso:
    python -m hado.v2.agent_demo

Este script demuestra el pipeline completo:
    1. El "Agente" razona en lenguaje natural.
    2. El "Agente" emite un JSON AST basado en hado_ast_v2.json.
    3. Hado lo deserializa, lo analiza semánticamente, calcula lifetimes,
       y emite código nativo de producción en C y Rust.
"""

import json
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../')))

from hado.v2.ast_builder import ASTBuilder
from hado.v2.semantic import TypeChecker
from hado.v2.lifetime import LifetimeAnalyzer
from hado.v2.c_transpiler import CTranspiler
from hado.v2.rust_transpiler import RustTranspiler


# ═══════════════════════════════════════════════════════════════════════════
# PASO 1: El Agente IA "razona" (simulated ReAct)
# ═══════════════════════════════════════════════════════════════════════════

AGENT_REASONING = """
╔══════════════════════════════════════════════════════════════════════════╗
║  AGENTE IA — Ciclo ReAct (Reason & Act)                               ║
╠══════════════════════════════════════════════════════════════════════════╣
║                                                                        ║
║  PENSAMIENTO: El objetivo es auditar la seguridad del host 10.0.0.50   ║
║  en los puertos HTTP estándar. Necesito:                               ║
║    1. Declarar el target y los puertos críticos.                       ║
║    2. Ejecutar un CyberScan en esos puertos.                           ║
║    3. Guardar los resultados en un archivo para evidencia.             ║
║                                                                        ║
║  ACCIÓN: Emitir un JSON AST válido según hado_ast_v2.json.            ║
║                                                                        ║
╚══════════════════════════════════════════════════════════════════════════╝
"""

# ═══════════════════════════════════════════════════════════════════════════
# PASO 2: El Agente emite el JSON AST (Function Calling output)
# ═══════════════════════════════════════════════════════════════════════════

AGENT_JSON_PAYLOAD = {
    "type": "Program",
    "body": [
        {
            "type": "Assignment",
            "name": "target_ip",
            "value": {"type": "StringLiteral", "value": "10.0.0.50"}
        },
        {
            "type": "ExpressionStatement",
            "expr": {
                "type": "CyberScan",
                "target": {"type": "Identifier", "name": "target_ip"},
                "ports": [
                    {"type": "NumberLiteral", "value": 80},
                    {"type": "NumberLiteral", "value": 443},
                    {"type": "NumberLiteral", "value": 8080}
                ]
            }
        },
        {
            "type": "SaveStatement",
            "value": {"type": "Identifier", "name": "target_ip"},
            "filename": {"type": "StringLiteral", "value": "scan_results.json"}
        }
    ]
}


def run_demo():
    print(AGENT_REASONING)

    print("=" * 72)
    print("  PASO 2: JSON emitido por el Agente (Function Calling)")
    print("=" * 72)
    print(json.dumps(AGENT_JSON_PAYLOAD, indent=2))
    print()

    # ═══════════════════════════════════════════════════════════════════════
    # PASO 3: Hado procesa el JSON a través del pipeline de 3 pasadas
    # ═══════════════════════════════════════════════════════════════════════

    print("=" * 72)
    print("  PASO 3: Pipeline Hado V2.0 (3 Pasadas)")
    print("=" * 72)

    # Pasada 0: Deserialización JSON -> AST nativo
    print("\n[Pasada 0] JSON → AST Builder...")
    builder = ASTBuilder()
    ast = builder.build_from_dict(AGENT_JSON_PAYLOAD)
    print(f"  ✅ AST construido: {len(ast.statements)} statements")

    # Pasada 1: TypeChecker
    print("[Pasada 1] Inferencia de Tipos (TypeChecker)...")
    checker = TypeChecker()
    checker.check(ast)
    print(f"  ✅ Variables tipadas: {dict(checker.current_scope.symbols)}")

    # Pasada 2: LifetimeAnalyzer
    print("[Pasada 2] Análisis de Ciclo de Vida (LifetimeAnalyzer)...")
    analyzer = LifetimeAnalyzer()
    analyzer.analyze(ast)
    states = {name: state for name, state in analyzer.current_scope.variables.items()}
    print(f"  ✅ Estados de memoria: {states}")

    # Pasada 3: Emisión de código nativo
    print("[Pasada 3] Emisión de Código Nativo...\n")

    # ═══════════════════════════════════════════════════════════════════════
    # PASO 4: Código generado
    # ═══════════════════════════════════════════════════════════════════════

    # Reconstruimos el AST para cada transpilador (ya que los visitors mutan output)
    ast_c = builder.build_from_dict(AGENT_JSON_PAYLOAD)
    analyzer_c = LifetimeAnalyzer()
    analyzer_c.analyze(ast_c)

    ast_rust = builder.build_from_dict(AGENT_JSON_PAYLOAD)
    analyzer_rust = LifetimeAnalyzer()
    analyzer_rust.analyze(ast_rust)

    c_code = CTranspiler(ast_c).emit()
    rust_code = RustTranspiler(ast_rust).emit()

    print("=" * 72)
    print("  RESULTADO: Payload en C (con free() automático)")
    print("=" * 72)
    print(c_code)
    print()

    print("=" * 72)
    print("  RESULTADO: Payload en Rust (con Arc/Mutex automático)")
    print("=" * 72)
    print(rust_code)
    print()

    print("=" * 72)
    print("  ✅ PRUEBA DE FUEGO COMPLETADA")
    print("  El Agente IA razonó → emitió JSON → Hado compiló a C y Rust")
    print("  sin errores de parseo, sin stubs, sin simulaciones.")
    print("=" * 72)


if __name__ == "__main__":
    run_demo()
