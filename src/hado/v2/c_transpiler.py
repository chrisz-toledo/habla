"""
Hado V2.0 — Transpilador de C (Pasada 3)
Genera código C seguro liberando memoria automáticamente basado en metadatos de 'drops'.
"""

from typing import List, Any
from ..ast_nodes import *

class CTranspiler:
    def __init__(self, program: Program):
        self.program = program
        self.output = []
        self.indent_level = 0

    def _indent(self) -> str:
        return "    " * self.indent_level

    def emit(self) -> str:
        self.output.append("#include <stdio.h>")
        self.output.append("#include <stdlib.h>")
        self.output.append("#include <stdbool.h>")
        self.output.append("#include <string.h>")
        self.output.append("")
        self.output.append("int main() {")
        self.indent_level += 1
        
        self._visit(self.program)
        
        self.output.append(f"{self._indent()}return 0;")
        self.indent_level -= 1
        self.output.append("}")
        return "\n".join(self.output)

    def _visit(self, node: Node):
        method = f"_visit_{type(node).__name__}"
        visitor = getattr(self, method, self._visit_unknown)
        visitor(node)

    def _visit_unknown(self, node: Node):
        self.output.append(f"{self._indent()}// Nodo no implementado: {type(node).__name__}")

    def _visit_Program(self, node: Program):
        for stmt in node.statements:
            self._visit(stmt)
        
        # INYECCIÓN DINÁMICA DE DROPS (MISIÓN 04)
        if "drops" in node.meta:
            for var in node.meta["drops"]:
                self.output.append(f"{self._indent()}free({var}); // Drop automático de scope global")

    def _visit_Assignment(self, node: Assignment):
        # En C V2 simplificamos: todo lo dinámico (strings, etc) es char*
        val_str = self._evaluate(node.value)
        if node.meta.get("memory_action") == "BindOwner":
            # Declaración y asignación
            self.output.append(f"{self._indent()}char* {node.name} = {val_str};")
        else:
            # Reasignación
            self.output.append(f"{self._indent()}{node.name} = {val_str};")

    def _visit_ShowStatement(self, node: ShowStatement):
        val_str = self._evaluate(node.value)
        self.output.append(f'{self._indent()}printf("%s\\n", {val_str});')

    def _visit_IfStatement(self, node: IfStatement):
        cond = self._evaluate(node.condition)
        self.output.append(f"{self._indent()}if ({cond}) {{")
        self.indent_level += 1
        for stmt in node.then_body:
            self._visit(stmt)
        
        # DROPS DEL THEN_BODY
        if "then_drops" in node.meta:
            for var in node.meta["then_drops"]:
                self.output.append(f"{self._indent()}free({var});")
        
        self.indent_level -= 1
        self.output.append(f"{self._indent()}}} else {{")
        self.indent_level += 1
        for stmt in node.else_body:
            self._visit(stmt)
            
        # DROPS DEL ELSE_BODY
        if "else_drops" in node.meta:
            for var in node.meta["else_drops"]:
                self.output.append(f"{self._indent()}free({var});")
                
        self.indent_level -= 1
        self.output.append(f"{self._indent()}}}")

    def _evaluate(self, node: Node) -> str:
        if isinstance(node, StringLiteral):
            # En C real usaríamos strdup para ser coherentes con free()
            return f"strdup({node.value})" 
        if isinstance(node, NumberLiteral):
            return str(node.value)
        if isinstance(node, Identifier):
            return node.name
        if isinstance(node, BinaryOp):
            return f"({self._evaluate(node.left)} {self._map_op(node.op)} {self._evaluate(node.right)})"
        return "NULL"

    def _map_op(self, op: str) -> str:
        mapping = {"y": "&&", "o": "||", "es": "==", "no": "!"}
        return mapping.get(op, op)
