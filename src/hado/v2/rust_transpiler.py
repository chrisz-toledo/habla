"""
Hado V2.0 — Transpilador de Rust (Pasada 3)
Genera código Rust asíncrono y gestiona concurrencia segura mediante Arc/Mutex.
"""

from typing import List, Any
from ..ast_nodes import *

class RustTranspiler:
    def __init__(self, program: Program):
        self.program = program
        self.output = []
        self.indent_level = 0

    def _indent(self) -> str:
        return "    " * self.indent_level

    def emit(self) -> str:
        self.output.append("use std::sync::{Arc, Mutex};")
        self.output.append("use tokio;")
        self.output.append("")
        self.output.append("#[tokio::main]")
        self.output.append("async fn main() {")
        self.indent_level += 1
        self.output.append(f"{self._indent()}let mut _handles = vec![];")
        self.output.append("")
        
        self._visit(self.program)
        
        self.output.append("")
        self.output.append(f"{self._indent()}for h in _handles {{ h.await.unwrap(); }}")
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

    def _visit_Assignment(self, node: Assignment):
        val_str = self._evaluate(node.value)
        
        # REGLA DE CONCURRENCIA (MISIÓN 04)
        # Si el LifetimeAnalyzer promovió esto a ArcMutex, envolvemos la declaración
        if node.value.meta.get("lifetime") == "ArcMutex":
             self.output.append(f"{self._indent()}let {node.name} = Arc::new(Mutex::new({val_str}));")
        elif node.meta.get("memory_action") == "BindOwner":
            self.output.append(f"{self._indent()}let mut {node.name} = {val_str};")
        else:
            self.output.append(f"{self._indent()}{node.name} = {val_str};")

    def _visit_ShowStatement(self, node: ShowStatement):
        val_str = self._evaluate(node.value)
        self.output.append(f'{self._indent()}println!("{{:?}}", {val_str});')

    def _visit_CyberScan(self, node: CyberScan):
        # CyberScan en Rust V2 usa tareas asíncronas coleccionadas
        target = self._evaluate(node.target)
        self.output.append(f"{self._indent()}_handles.push(tokio::spawn(async move {{")
        self.indent_level += 1
        self.output.append(f"{self._indent()}println!(\"Escaneando {{:?}}...\", {target});")
        self.indent_level -= 1
        self.output.append(f"{self._indent()}}}));")

    def _evaluate(self, node: Node) -> str:
        if isinstance(node, StringLiteral):
            return f'{node.value}.to_string()'
        if isinstance(node, NumberLiteral):
            return str(node.value)
        if isinstance(node, Identifier):
            # REGLA DE BORROWING DE CONCURRENCIA (MISIÓN 04)
            if node.meta.get("lifetime") == "ArcMutex_Borrow":
                return f"{node.name}.lock().unwrap()"
            return node.name
        if isinstance(node, BinaryOp):
            return f"({self._evaluate(node.left)} {self._map_op(node.op)} {self._evaluate(node.right)})"
        return "()"

    def _map_op(self, op: str) -> str:
        mapping = {"y": "&&", "o": "||", "es": "==", "no": "!"}
        return mapping.get(op, op)
