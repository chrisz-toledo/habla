"""
AST JSON Builder API
Recibe un JSON estructurado (basado en hado_ast_v2.json) y devuelve el árbol de objetos Node interno de Hado.
"""

from typing import Any, Dict, List
import json
from ..ast_nodes import *

class ASTBuilder:
    def build_from_json(self, json_data: str) -> Program:
        """Parse a JSON string into a Program AST node."""
        data = json.loads(json_data)
        return self._build_node(data)

    def build_from_dict(self, data: Dict[str, Any]) -> Program:
        """Parse a dictionary into a Program AST node."""
        if data.get("type") != "Program":
            raise ValueError(f"Root node must be Program, got {data.get('type')}")
        return self._build_node(data)

    def _build_node(self, data: Dict[str, Any]) -> Any:
        node_type = data.get("type")
        if not node_type:
            raise ValueError("Node is missing 'type' field")
            
        builder_method = getattr(self, f"_build_{node_type}", None)
        if builder_method:
            return builder_method(data)
        
        raise NotImplementedError(f"Builder for node type '{node_type}' not implemented")

    # -- Program --
    def _build_Program(self, data: Dict[str, Any]) -> Program:
        body = [self._build_node(stmt) for stmt in data.get("body", [])]
        return Program(statements=body)

    # -- Statements --
    def _build_Assignment(self, data: Dict[str, Any]) -> Assignment:
        return Assignment(
            name=data["name"],
            value=self._build_node(data["value"])
        )

    def _build_ExpressionStatement(self, data: Dict[str, Any]) -> ExpressionStatement:
        return ExpressionStatement(expr=self._build_node(data["expr"]))

    def _build_SaveStatement(self, data: Dict[str, Any]) -> SaveStatement:
        return SaveStatement(
            value=self._build_node(data["value"]),
            filename=self._build_node(data["filename"])
        )

    def _build_ShowStatement(self, data: Dict[str, Any]) -> ShowStatement:
        return ShowStatement(value=self._build_node(data["value"]))

    def _build_IfStatement(self, data: Dict[str, Any]) -> IfStatement:
        return IfStatement(
            condition=self._build_node(data["condition"]),
            then_body=[self._build_node(stmt) for stmt in data.get("then_body", [])],
            else_body=[self._build_node(stmt) for stmt in data.get("else_body", [])]
        )

    def _build_WhileStatement(self, data: Dict[str, Any]) -> WhileStatement:
        return WhileStatement(
            condition=self._build_node(data["condition"]),
            body=[self._build_node(stmt) for stmt in data.get("body", [])]
        )

    def _build_ForStatement(self, data: Dict[str, Any]) -> ForStatement:
        return ForStatement(
            var=data["var"],
            iterable=self._build_node(data["iterable"]),
            body=[self._build_node(stmt) for stmt in data.get("body", [])]
        )

    # -- Literals & Expressions --
    def _build_Identifier(self, data: Dict[str, Any]) -> Identifier:
        return Identifier(name=data["name"])

    def _build_StringLiteral(self, data: Dict[str, Any]) -> StringLiteral:
        return StringLiteral(value=f'"{data["value"]}"')

    def _build_NumberLiteral(self, data: Dict[str, Any]) -> NumberLiteral:
        return NumberLiteral(value=data["value"])

    def _build_BooleanLiteral(self, data: Dict[str, Any]) -> BooleanLiteral:
        return BooleanLiteral(value=data["value"])

    def _build_NullLiteral(self, data: Dict[str, Any]) -> NullLiteral:
        return NullLiteral()

    def _build_ListLiteral(self, data: Dict[str, Any]) -> ListLiteral:
        elements = [self._build_node(el) for el in data.get("elements", [])]
        return ListLiteral(elements=elements)

    def _build_DictLiteral(self, data: Dict[str, Any]) -> DictLiteral:
        pairs = []
        for pair in data.get("pairs", []):
            k = self._build_node(pair["key"])
            v = self._build_node(pair["value"])
            pairs.append((k, v))
        return DictLiteral(pairs=pairs)

    def _build_BinaryOp(self, data: Dict[str, Any]) -> BinaryOp:
        return BinaryOp(
            op=data["op"],
            left=self._build_node(data["left"]),
            right=self._build_node(data["right"])
        )

    def _build_FunctionCall(self, data: Dict[str, Any]) -> FunctionCall:
        return FunctionCall(
            func=data["func"],
            args=[self._build_node(arg) for arg in data.get("args", [])]
        )

    def _build_PipeExpression(self, data: Dict[str, Any]) -> PipeExpression:
        return PipeExpression(
            steps=[self._build_node(step) for step in data.get("steps", [])]
        )

    # -- Cyber Operations --
    def _build_CyberScan(self, data: Dict[str, Any]) -> CyberScan:
        return CyberScan(
            target=self._build_node(data["target"]),
            ports=[self._build_node(p) for p in data.get("ports", [])]
        )

    def _build_CyberAttack(self, data: Dict[str, Any]) -> CyberAttack:
        return CyberAttack(
            target=self._build_node(data["target"]),
            wordlist=self._build_node(data["wordlist"]),
            username=self._build_node(data["username"])
        )

    def _build_CyberRecon(self, data: Dict[str, Any]) -> CyberRecon:
        return CyberRecon(
            domain=self._build_node(data["domain"])
        )
