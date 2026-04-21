"""
Habla DSL — Backend Go. [STUB v0.1 -> v1.0]

Genera codigo Go a partir del AST de Habla.
En v0.1 implementa lo basico (variables, si/sino, para, fn, muestra).
Las operaciones cybersec generan codigo Go con imports de librerias nativas.
"""

from __future__ import annotations
from typing import List, Optional, Set

from ..transpiler import BaseTranspiler
from ..ast_nodes import (
    Program, Node, Assignment, IfStatement, WhileStatement, ForStatement,
    FunctionDef, ReturnStatement, ShowStatement, SaveStatement,
    ExpressionStatement, NumberLiteral, StringLiteral, BooleanLiteral,
    NullLiteral, ListLiteral, DictLiteral, Identifier, BinaryOp, UnaryOp,
    PipeExpression, PropertyAccess, IndexAccess, FunctionCall,
    CyberScan, CyberRecon, CyberCapture, CyberAttack, CyberFindVulns,
    CyberAnalyze, GenerateReport, HttpGet, FilterExpression,
    SortExpression, CountExpression,
)
from .base import HablaBackend


_OP_MAP_GO = {
    "y": "&&", "o": "||", "no": "!", "es": "==", "==": "==", "!=": "!=",
    ">=": ">=", "<=": "<=", ">": ">", "<": "<", "+": "+", "-": "-",
    "*": "*", "/": "/", "%": "%",
}

_CYBER_IMPORTS = {
    "scan":          "// github.com/Ullaakut/nmap/v3",
    "subdomains":    "// github.com/projectdiscovery/subfinder/v2/pkg/runner",
    "vulns":         "// github.com/projectdiscovery/nuclei/v3/pkg/...",
    "capture":       "// github.com/google/gopacket/pcap",
    "attack_ssh":    "// golang.org/x/crypto/ssh",
}


class GoBackend(BaseTranspiler, HablaBackend):
    """
    Backend Go — implementacion concurrente.
    """

    def __init__(self, ast: Program):
        super().__init__(ast)
        self._has_main = False
        self._go_imports: Set[str] = set()
        self._go_imports.add('"fmt"')

    def generate(self, ast: Program) -> str:
        self.ast = ast
        return self.emit()

    def file_extension(self) -> str:
        return ".go"

    def compile_command(self, source_path: str) -> Optional[str]:
        return f"go build {source_path}"

    def status(self) -> str:
        return "funcional"

    def description(self) -> str:
        return "Scanners concurrentes, binarios standalone, herramientas de red"

    def emit(self) -> str:
        body_lines = self._visit_program_go(self.ast)
        body = "\n".join(line for line in body_lines if line is not None)

        imports_block = self._build_imports()

        if self._has_main:
            return f"package main\n\n{imports_block}\n\n{body}"
        else:
            return (
                f"package main\n\n"
                f"{imports_block}\n\n"
                f"func main() {{\n"
                f"{body}\n"
                f"}}"
            )

    def _build_imports(self) -> str:
        if not self._go_imports:
            return ""
        sorted_imports = sorted(self._go_imports)
        return "import (\n" + "\n".join(f"\t{i}" for i in sorted_imports) + "\n)"

    def _visit_program_go(self, node: Program) -> List[str]:
        lines = []
        for stmt in node.statements:
            result = self._visit(stmt)
            if result:
                lines.append(result)
        return lines

    def _visit(self, node: Node) -> str:
        method = f"_visit_{type(node).__name__}"
        visitor = getattr(self, method, self._visit_stub)
        return visitor(node)

    def _visit_stub(self, node: Node) -> str:
        node_type = type(node).__name__
        return f'{self._ind()}// TODO Go v0.3: implementar {node_type}'

    def _visit_Assignment(self, node: Assignment) -> str:
        value = self._visit(node.value) if node.value else "nil"
        return f"{self._ind()}{node.name} := {value}"

    def _visit_IfStatement(self, node: IfStatement) -> str:
        cond = self._visit(node.condition)
        lines = [f"{self._ind()}if {cond} {{"]
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
        lines = [f"{self._ind()}for {cond} {{"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_ForStatement(self, node: ForStatement) -> str:
        iterable = self._visit(node.iterable)
        lines = [f"{self._ind()}for _, {node.var} := range {iterable} {{"]
        self._indent += 1
        for stmt in node.body:
            lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_FunctionDef(self, node: FunctionDef) -> str:
        if node.name == "main":
            self._has_main = True
        params = ", ".join(f"{p} interface{{}}" for p in node.params)
        lines = [f"{self._ind()}func {node.name}({params}) interface{{}} {{"]
        self._indent += 1
        if not node.body:
            lines.append(f"{self._ind()}return nil")
        else:
            for stmt in node.body:
                lines.append(self._visit(stmt))
        self._indent -= 1
        lines.append(f"{self._ind()}}}")
        return "\n".join(lines)

    def _visit_ReturnStatement(self, node: ReturnStatement) -> str:
        val = self._visit(node.value) if node.value else ""
        return f"{self._ind()}return {val}".rstrip()

    def _visit_ShowStatement(self, node: ShowStatement) -> str:
        self._go_imports.add('"fmt"')
        val = self._visit(node.value) if node.value else "_habla_pipe_input"
        return f"{self._ind()}fmt.Println({val})"

    def _visit_SaveStatement(self, node: SaveStatement) -> str:
        self._go_imports.add('"os"')
        fname = self._visit(node.filename) if node.filename else '"output.txt"'
        val = self._visit(node.value) if node.value else "_habla_pipe_input"
        return f'{self._ind()}os.WriteFile({fname}, []byte(fmt.Sprintf("%v", {val})), 0644)'

    def _visit_ExpressionStatement(self, node: ExpressionStatement) -> str:
        if isinstance(node.expr, PipeExpression):
            return self._emit_pipe_chain_go(node.expr.steps)
        return f"{self._ind()}{self._visit(node.expr)}"

    # ─── Cybersec con Goroutines Inyectadas ──────────────────────────────────────────

    def _visit_CyberScan(self, node: CyberScan) -> str:
        self._go_imports.update(['"net"', '"sync"', '"time"', '"strconv"'])
        
        target = self._visit(node.target) if node.target else '"127.0.0.1"'
        ports_list = ", ".join(self._visit(p) for p in node.ports)
        
        lines = [
            f"func() map[string]interface{{}} {{",
            f"    var wg sync.WaitGroup",
            f"    var mu sync.Mutex",
            f"    openPorts := []int{{}}",
            f"    closedPorts := []int{{}}",
            f"    ports := []int{{{ports_list}}}",
            f"    ",
            f"    for _, p := range ports {{",
            f"        wg.Add(1)",
            f"        go func(port int) {{",
            f"            defer wg.Done()",
            f"            address := {target} + \":\" + strconv.Itoa(port)",
            f"            conn, err := net.DialTimeout(\"tcp\", address, 2*time.Second)",
            f"            ",
            f"            mu.Lock()",
            f"            defer mu.Unlock()",
            f"            if err == nil {{",
            f"                conn.Close()",
            f"                openPorts = append(openPorts, port)",
            f"            }} else {{",
            f"                closedPorts = append(closedPorts, port)",
            f"            }}",
            f"        }}(p)",
            f"    }}",
            f"    wg.Wait()",
            f"    ",
            f"    return map[string]interface{{}}{{",
            f"        \"target\": {target},",
            f"        \"open_ports\": openPorts,",
            f"        \"closed_ports\": closedPorts,",
            f"        \"method\": \"goroutines (stdlib)\",",
            f"    }}",
            f"}}()"
        ]
        
        return "\n".join(f"{self._ind()}{line}" if i > 0 else line for i, line in enumerate(lines))

    def _visit_CyberRecon(self, node: CyberRecon) -> str:
        domain = self._visit(node.domain) if node.domain else '""'
        return (
            f"{self._ind()}// Go v0.3: buscar subdominios de {domain}\n"
            f"{self._ind()}// import: {_CYBER_IMPORTS['subdomains']}\n"
            f"{self._ind()}// runner, _ := subfinder.NewRunner(opts); runner.EnumerateSingleDomainWithCtx(ctx, {domain}, ...)"
        )

    def _visit_CyberCapture(self, node: CyberCapture) -> str:
        iface = self._visit(node.interface) if node.interface else '"eth0"'
        return (
            f"{self._ind()}// Go v0.3: capturar packets en {iface}\n"
            f"{self._ind()}// import: {_CYBER_IMPORTS['capture']}\n"
            f"{self._ind()}// handle, _ := pcap.OpenLive({iface}, 1600, true, pcap.BlockForever)"
        )

    def _visit_CyberAttack(self, node: CyberAttack) -> str:
        service = self._visit(node.service) if node.service else '"ssh"'
        target = self._visit(node.target) if node.target else '""'
        return (
            f"{self._ind()}// Go v0.3: ataque de fuerza bruta a {service} en {target}\n"
            f"{self._ind()}// import: {_CYBER_IMPORTS['attack_ssh']}\n"
            f"{self._ind()}// Usar goroutines para concurrencia automatica"
        )

    def _visit_CyberFindVulns(self, node: CyberFindVulns) -> str:
        target = self._visit(node.target) if node.target else 'nil'
        return (
            f"{self._ind()}// Go v0.3: buscar vulns en {target}\n"
            f"{self._ind()}// import: {_CYBER_IMPORTS['vulns']}\n"
            f"{self._ind()}// nuclei.RunTemplate({target}, templates)"
        )

    def _visit_GenerateReport(self, node: GenerateReport) -> str:
        data = self._visit(node.data) if node.data else "nil"
        return (
            f"{self._ind()}// Go v0.3: generar reporte con {data}\n"
            f"{self._ind()}// Usar html/template o text/template de la stdlib"
        )

    def _visit_HttpGet(self, node: HttpGet) -> str:
        self._go_imports.add('"net/http"')
        url = self._visit(node.url) if node.url else '""'
        return f'{self._ind()}http.Get({url}) // TODO Go v0.3: decode JSON response'

    def _visit_NumberLiteral(self, node: NumberLiteral) -> str:
        return str(node.value)

    def _visit_StringLiteral(self, node: StringLiteral) -> str:
        return node.value

    def _visit_BooleanLiteral(self, node: BooleanLiteral) -> str:
        return "true" if node.value else "false"

    def _visit_NullLiteral(self, node: NullLiteral) -> str:
        return "nil"

    def _visit_ListLiteral(self, node: ListLiteral) -> str:
        elements = ", ".join(self._visit(e) for e in node.elements)
        return f"[]interface{{{{}}}}{{{elements}}}"

    def _visit_DictLiteral(self, node: DictLiteral) -> str:
        pairs = ", ".join(f"{self._visit(k)}: {self._visit(v)}" for k, v in node.pairs)
        return "{" + pairs + "}"

    def _visit_Identifier(self, node: Identifier) -> str:
        return node.name

    def _visit_BinaryOp(self, node: BinaryOp) -> str:
        left = self._visit(node.left)
        right = self._visit(node.right)
        op = _OP_MAP_GO.get(node.op, node.op)
        return f"{left} {op} {right}"

    def _visit_UnaryOp(self, node: UnaryOp) -> str:
        operand = self._visit(node.operand)
        op = _OP_MAP_GO.get(node.op, node.op)
        if op == "!":
            return f"!{operand}"
        return f"{op}{operand}"

    def _visit_PropertyAccess(self, node: PropertyAccess) -> str:
        obj = self._visit(node.obj)
        return f'{obj}["{node.prop}"]'

    def _visit_IndexAccess(self, node: IndexAccess) -> str:
        obj = self._visit(node.obj)
        idx = self._visit(node.index)
        return f"{obj}[{idx}]"

    def _visit_FunctionCall(self, node: FunctionCall) -> str:
        args = [self._visit(a) for a in node.args]
        all_args = ", ".join(args)
        return f"{node.func}({all_args})"

    def _visit_FilterExpression(self, node: FilterExpression) -> str:
        src = self._visit(node.iterable) if node.iterable else "_habla_pipe_input"
        cond = self._visit(node.condition)
        var = node.var
        lines = [
            f"{self._ind()}// Go v0.3: filter — for range + if",
            f"{self._ind()}var _filtered []interface{{}}",
            f"{self._ind()}for _, {var} := range {src} {{",
            f"{self._ind()}    if {cond} {{",
            f"{self._ind()}        _filtered = append(_filtered, {var})",
            f"{self._ind()}    }}",
            f"{self._ind()}}}",
        ]
        return "\n".join(lines)

    def _visit_CountExpression(self, node: CountExpression) -> str:
        src = self._visit(node.source) if node.source else "_habla_pipe_input"
        return f"len({src})"

    def _emit_pipe_chain_go(self, steps: List[Node], target_var: Optional[str] = None) -> str:
        lines = []
        prev_var: Optional[str] = None

        for i, step in enumerate(steps):
            is_last = (i == len(steps) - 1)

            if i == 0:
                if isinstance(step, Identifier):
                    prev_var = step.name
                    continue
                else:
                    out_var = target_var if is_last else self._next_pipe_var()
                    lines.append(f"{self._ind()}{out_var} := {self._visit(step)}")
                    prev_var = out_var
                    continue

            out_var = target_var if is_last else self._next_pipe_var()
            if isinstance(step, ShowStatement):
                self._go_imports.add('"fmt"')
                lines.append(f"{self._ind()}fmt.Println({prev_var})")
            elif isinstance(step, SaveStatement):
                self._go_imports.add('"os"')
                fname = self._visit(step.filename) if step.filename else '"output.txt"'
                lines.append(f'{self._ind()}os.WriteFile({fname}, []byte(fmt.Sprintf("%v", {prev_var})), 0644)')
            elif isinstance(step, CountExpression):
                lines.append(f"{self._ind()}{out_var} := len({prev_var})")
                prev_var = out_var
            else:
                lines.append(f"{self._ind()}// Go v0.3: pipe step {type(step).__name__}")
                lines.append(f"{self._ind()}{out_var} := {prev_var}")
                prev_var = out_var

        return "\n".join(lines)
