"""
Hado DSL — Backend Solidity (Ecosistema Blockchain).
Genera codigo Solidity para Smart Contracts EVM.
"""

from __future__ import annotations
from typing import List

from ..transpiler import BaseTranspiler
from ..ast_nodes import *

class SolidityTranspiler(BaseTranspiler):
    def emit(self) -> str:
        lines = [
            "// SPDX-License-Identifier: MIT",
            "pragma solidity ^0.8.0;",
            "",
            "contract HadoAgent {",
            "    event LogMessage(string message);",
            "    event LogUint(uint256 value);",
            "    event OracleCyberRequest(string action, string target, string payload);",
            "",
            "    function execute() public {"
        ]
        
        self._indent = 2
        for stmt in self.ast.statements:
            result = self._visit(stmt)
            if result:
                lines.append(result)
        
        lines.append("    }")
        lines.append("}")
        return "\n".join(lines) + "\n"

    def _ind(self) -> str:
        return "    " * self._indent

    def _visit(self, node: Node) -> str:
        method = f"_visit_{type(node).__name__}"
        visitor = getattr(self, method, self._visit_unknown)
        return visitor(node)

    def _visit_unknown(self, node: Node) -> str:
        raise NotImplementedError(f"Node not implemented in Solidity backend: {type(node).__name__}")

    def _visit_Assignment(self, node: Assignment) -> str:
        val = self._visit(node.value) if node.value else '""'
        # Tipado naivo: asume string memory a menos que parezca numero o booleano
        type_str = "string memory"
        if isinstance(node.value, NumberLiteral):
            type_str = "uint256"
        elif isinstance(node.value, BooleanLiteral):
            type_str = "bool"
        elif isinstance(node.value, BinaryOp):
            # Simplificacion
            type_str = "uint256"
            
        return f"{self._ind()}{type_str} {node.name} = {val};"

    def _visit_ShowStatement(self, node: ShowStatement) -> str:
        if not node.values and node.value is None:
            return f"{self._ind()}emit LogMessage(\"pipe_val\");"
        
        # En solidity solo logueamos el primero para simplificar
        val = self._visit(node.value) if node.value else self._visit(node.values[0])
        # Check tipo por el ast node original
        orig_node = node.value if node.value else node.values[0]
        if isinstance(orig_node, NumberLiteral):
            return f"{self._ind()}emit LogUint({val});"
        return f"{self._ind()}emit LogMessage(string(abi.encodePacked({val})));"

    def _visit_IfStatement(self, node: IfStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}if ({cond}) {{"]
        self._indent += 1
        for stmt in node.then_body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        if node.else_body:
            lines.append(f"{self._ind()}}} else {{")
            self._indent += 1
            for stmt in node.else_body:
                lines.append(self._visit(stmt))
            self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_WhileStatement(self, node: WhileStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}while ({cond}) {{"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_ForStatement(self, node: ForStatement) -> str:
        iterable = self._visit(node.iterable)
        lines = [
            f"{self._ind()}// Solidity no soporta for..in iterators nativos sin tipos complejos.",
            f"{self._ind()}// Mock loop para array",
            f"{self._ind()}for (uint256 _i = 0; _i < {iterable}.length; _i++) {{"
        ]
        self._indent += 1
        # var declaracion omitida por simplicidad
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_FunctionDef(self, node: FunctionDef) -> str:
        # En solidity es mejor no nestear funciones, emitimos un warning o la metemos in-line
        return f"{self._ind()}// Función anidada '{node.name}' omitida en Solidity (requiere nivel contrato)"

    def _visit_ReturnStatement(self, node: ReturnStatement) -> str:
        if node.value:
            val = self._visit(node.value)
            return f"{self._ind()}return {val};"
        return f"{self._ind()}return;"

    def _visit_SaveStatement(self, node: SaveStatement) -> str:
        fname = self._visit(node.filename) if node.filename else '"out.txt"'
        val = self._visit(node.value) if node.value else '"pipe_val"'
        return f"{self._ind()}emit OracleCyberRequest(\"SAVE\", {fname}, string(abi.encodePacked({val})));"

    # ─── Cyber ────────────────────────────────────────────────────────────────

    def _visit_CyberScan(self, node: CyberScan) -> str:
        target = self._visit(node.target) if node.target else '"127.0.0.1"'
        ports = self._visit_ListLiteral(ListLiteral(node.ports)) if node.ports else '""'
        return f'{self._ind()}emit OracleCyberRequest("SCAN", {target}, {ports});'

    def _visit_CyberRecon(self, node: CyberRecon) -> str:
        domain = self._visit(node.domain) if node.domain else '"example.com"'
        return f'{self._ind()}emit OracleCyberRequest("RECON", {domain}, "");'

    def _visit_CyberAttack(self, node: CyberAttack) -> str:
        target = self._visit(node.target) if node.target else '"127.0.0.1"'
        username = self._visit(node.username) if node.username else '"admin"'
        return f'{self._ind()}emit OracleCyberRequest("ATTACK_BRUTE", {target}, {username});'

    def _visit_CyberCapture(self, node: CyberCapture) -> str:
        iface = self._visit(node.interface) if node.interface else '"eth0"'
        return f'{self._ind()}emit OracleCyberRequest("CAPTURE", {iface}, "");'

    def _visit_CyberEnumerate(self, node: CyberEnumerate) -> str:
        target = self._visit(node.target) if node.target else '"http://127.0.0.1"'
        wordlist = self._visit(node.wordlist) if node.wordlist else '"default"'
        return f'{self._ind()}emit OracleCyberRequest("ENUMERATE", {target}, {wordlist});'

    def _visit_CyberAnalyze(self, node: CyberAnalyze) -> str:
        target = self._visit(node.source) if node.source else '"http://127.0.0.1"'
        return f'{self._ind()}emit OracleCyberRequest("ANALYZE", {target}, "");'

    def _visit_CyberFindVulns(self, node: CyberFindVulns) -> str:
        target = self._visit(node.target) if node.target else '"target"'
        return f'{self._ind()}emit OracleCyberRequest("FINDVULNS", {target}, "");'

    def _visit_GenerateReport(self, node: GenerateReport) -> str:
        data = self._visit(node.data) if node.data else '""'
        fname = f'"{node.output_file}"' if hasattr(node, 'output_file') and node.output_file else '"report.json"'
        return f'{self._ind()}emit OracleCyberRequest("REPORT", {fname}, string(abi.encodePacked({data})));'

    def _visit_HttpGet(self, node: HttpGet) -> str:
        url = self._visit(node.url) if node.url else '""'
        return f'"" /* HttpGet off-chain Oracle call a {url} no es síncrono en Solidity */'

    def _visit_HttpPost(self, node: HttpPost) -> str:
        url = self._visit(node.url) if node.url else '""'
        return f'"" /* HttpPost off-chain Oracle call a {url} no es síncrono */'

    def _visit_ExpressionStatement(self, node: ExpressionStatement) -> str:
        return f"{self._ind()}{self._visit(node.expr)};"

    # ─── Expresiones ─────────────────────────────────────────────────────────

    def _visit_BinaryOp(self, node: BinaryOp) -> str:
        left = self._visit(node.left)
        right = self._visit(node.right)
        op_map = {"y": "&&", "o": "||", "no": "!", "es": "==", "==": "==", "!=": "!=", ">=": ">=", "<=": "<=", ">": ">", "<": "<", "+": "+", "-": "-", "*": "*", "/": "/", "%": "%"}
        op = op_map.get(node.op, node.op)
        return f'({left} {op} {right})'

    def _visit_UnaryOp(self, node: UnaryOp) -> str:
        op = "!" if node.op == "no" else "-"
        return f"({op}{self._visit(node.operand)})"

    def _visit_NumberLiteral(self, node: NumberLiteral) -> str:
        return str(node.value)

    def _visit_StringLiteral(self, node: StringLiteral) -> str:
        return node.value

    def _visit_BooleanLiteral(self, node: BooleanLiteral) -> str:
        return "true" if node.value else "false"

    def _visit_NullLiteral(self, node: NullLiteral) -> str:
        return '""'

    def _visit_Identifier(self, node: Identifier) -> str:
        return node.name

    def _visit_ListLiteral(self, node: ListLiteral) -> str:
        return '"[List]"'

    def _visit_DictLiteral(self, node: DictLiteral) -> str:
        return '"{Dict}"'

    def _visit_PropertyAccess(self, node: PropertyAccess) -> str:
        return f'"{node.prop}"'

    def _visit_IndexAccess(self, node: IndexAccess) -> str:
        return f"{self._visit(node.obj)}[{self._visit(node.index)}]"

    def _visit_FunctionCall(self, node: FunctionCall) -> str:
        args = ", ".join(self._visit(a) for a in node.args)
        return f"{node.func}({args})"

    def _visit_PipeExpression(self, node: PipeExpression) -> str:
        return '"" /* Pipes no soportados en Solidity */'

    def _visit_FilterExpression(self, node: FilterExpression) -> str:
        return '"" /* Filter no soportado en Solidity */'

    def _visit_SortExpression(self, node: SortExpression) -> str:
        return '"" /* Sort no soportado en Solidity */'

    def _visit_CountExpression(self, node: CountExpression) -> str:
        return f'{self._visit(node.source)}.length'
