import pytest
from hado.ast_nodes import *
from hado.v2.c_transpiler import CTranspiler
from hado.v2.rust_transpiler import RustTranspiler

def test_c_transpiler_memory_drops():
    """Verifica que el transpilador de C inyecte free() basado en meta['drops']."""
    # AST manual simulando la salida de la Pasada 2
    stmt = IfStatement(
        condition=BooleanLiteral(value=True),
        then_body=[Assignment(name="temp_data", value=StringLiteral(value='"secret"'))]
    )
    # Inyectamos el drop manualmente para el test
    stmt.meta["then_drops"] = ["temp_data"]
    stmt.then_body[0].meta["memory_action"] = "BindOwner"
    
    prog = Program(statements=[stmt])
    transpiler = CTranspiler(prog)
    code = transpiler.emit()
    
    print(code)
    assert "free(temp_data);" in code
    assert "strdup(\"secret\")" in code

def test_rust_transpiler_arc_mutex():
    """Verifica que el transpilador de Rust inyecte Arc<Mutex<...>> y lock()."""
    # 1. Declaración con meta ArcMutex
    val = StringLiteral(value='"10.0.0.1"')
    val.meta["lifetime"] = "ArcMutex"
    
    assign = Assignment(name="target", value=val)
    assign.meta["memory_action"] = "BindOwner"
    
    # 2. Uso con meta ArcMutex_Borrow
    target_id = Identifier(name="target")
    target_id.meta["lifetime"] = "ArcMutex_Borrow"
    
    scan = CyberScan(target=target_id, ports=[NumberLiteral(value=80)])
    
    prog = Program(statements=[assign, scan])
    transpiler = RustTranspiler(prog)
    code = transpiler.emit()
    
    print(code)
    assert "Arc::new(Mutex::new(" in code
    assert "target.lock().unwrap()" in code
    assert "tokio::spawn" in code
