import pytest
import json
from hado.v2.ast_builder import ASTBuilder
from hado.ast_nodes import *

def test_ast_builder_simple_assignment():
    json_payload = """
    {
      "type": "Program",
      "body": [
        {
          "type": "Assignment",
          "name": "target_ip",
          "value": {
            "type": "StringLiteral",
            "value": "192.168.1.1"
          }
        }
      ]
    }
    """
    builder = ASTBuilder()
    ast = builder.build_from_json(json_payload)
    
    assert isinstance(ast, Program)
    assert len(ast.statements) == 1
    stmt = ast.statements[0]
    assert isinstance(stmt, Assignment)
    assert stmt.name == "target_ip"
    assert isinstance(stmt.value, StringLiteral)
    assert stmt.value.value == '"192.168.1.1"'

def test_ast_builder_cyber_scan():
    json_payload = """
    {
      "type": "Program",
      "body": [
        {
          "type": "ExpressionStatement",
          "expr": {
            "type": "CyberScan",
            "target": {
              "type": "StringLiteral",
              "value": "10.0.0.1"
            },
            "ports": [
              { "type": "NumberLiteral", "value": 80 },
              { "type": "NumberLiteral", "value": 443 }
            ]
          }
        }
      ]
    }
    """
    builder = ASTBuilder()
    ast = builder.build_from_json(json_payload)
    
    assert len(ast.statements) == 1
    stmt = ast.statements[0]
    assert isinstance(stmt, ExpressionStatement)
    assert isinstance(stmt.expr, CyberScan)
    assert isinstance(stmt.expr.target, StringLiteral)
    assert stmt.expr.target.value == '"10.0.0.1"'
    assert len(stmt.expr.ports) == 2
    assert stmt.expr.ports[0].value == 80
    assert stmt.expr.ports[1].value == 443

def test_ast_builder_complex_malformed():
    # Test APE (Abrazar el Error): Pasamos JSON malformado o nodos faltantes
    json_payload = """
    {
      "type": "Program",
      "body": [
        {
          "type": "Assignment",
          "name": "x"
          // FALTA "value" intencionalmente
        }
      ]
    }
    """
    builder = ASTBuilder()
    with pytest.raises(json.decoder.JSONDecodeError):
        builder.build_from_json(json_payload)

def test_ast_builder_missing_type():
    # Test APE: Falta el campo type interno
    json_payload = """
    {
      "type": "Program",
      "body": [
        {
          "type": "ExpressionStatement",
          "expr": {
            "value": "Soy_Un_Nodo_Sin_Tipo"
          }
        }
      ]
    }
    """
    builder = ASTBuilder()
    with pytest.raises(ValueError, match="Node is missing 'type' field"):
        builder.build_from_json(json_payload)
