import pytest
from hado.ast_nodes import *
from hado.v2.c_transpiler import CTranspiler
from hado.v2.rust_transpiler import RustTranspiler

def test_c_transpiler_memory_drops():
    """Verifica que el transpilador de C inyecte free() basado en meta['drops']."""
    stmt = IfStatement(
        condition=BooleanLiteral(value=True),
        then_body=[Assignment(name="temp_data", value=StringLiteral(value='"secret"'))]
    )
    stmt.meta["then_drops"] = ["temp_data"]
    stmt.then_body[0].meta["memory_action"] = "BindOwner"
    
    prog = Program(statements=[stmt])
    transpiler = CTranspiler(prog)
    code = transpiler.emit()
    assert "free(temp_data);" in code
    assert "strdup(\"secret\")" in code

def test_c_transpiler_loop_drops():
    """Verifica que el transpilador de C inyecte free() dentro de los bucles."""
    stmt = WhileStatement(
        condition=BooleanLiteral(value=True),
        body=[Assignment(name="loop_var", value=StringLiteral(value='"data"'))]
    )
    stmt.meta["drops"] = ["loop_var"]
    stmt.body[0].meta["memory_action"] = "BindOwner"
    
    prog = Program(statements=[stmt])
    transpiler = CTranspiler(prog)
    code = transpiler.emit()
    assert "while (true) {" in code
    assert "free(loop_var);" in code

def test_rust_transpiler_arc_mutex():
    """Verifica que el transpilador de Rust inyecte Arc<Mutex<...>> y lock()."""
    val = StringLiteral(value='"10.0.0.1"')
    val.meta["lifetime"] = "ArcMutex"
    assign = Assignment(name="target", value=val)
    assign.meta["memory_action"] = "BindOwner"
    
    target_id = Identifier(name="target")
    target_id.meta["lifetime"] = "ArcMutex_Borrow"
    scan = CyberScan(target=target_id, ports=[NumberLiteral(value=80)])
    
    prog = Program(statements=[assign, scan])
    transpiler = RustTranspiler(prog)
    code = transpiler.emit()
    assert "Arc::new(Mutex::new(" in code
    assert "target.lock().unwrap()" in code

def test_rust_transpiler_task_handles():
    """Verifica que Rust coleccione handles de tokio::spawn y los espere al final."""
    scan = CyberScan(target=StringLiteral(value='"10.0.0.1"'), ports=[NumberLiteral(value=80)])
    prog = Program(statements=[scan])
    transpiler = RustTranspiler(prog)
    code = transpiler.emit()
    assert "let mut _handles = vec![];" in code
    assert "_handles.push(tokio::spawn" in code
    assert "for h in _handles { h.await.unwrap(); }" in code
