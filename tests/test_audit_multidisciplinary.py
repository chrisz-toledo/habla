import pytest
from hado.normalizer import normalize
from hado.lexer import Lexer
from hado.parser import Parser
from hado.backends import get_backend, list_backends

TORTURE_SCRIPT = '''
# Variables y Estructuras Complejas
lista_numeros = [1, 2, 3, 4, 5]
dicc_config = {"target": "10.0.0.1", "port": 80}
contador = 0
flag = no falso
valor_nulo = nulo

# Matematicas y Logica (Algebra Booleana)
resultado_math = (10 + 5 * 2) % 3
logica = (flag y verdadero) o no (contador == 0)

# Funciones y Control de Flujo
fn test_func(a, b)
    si a > b
        devuelve a
    sino
        devuelve b

mientras contador < 5
    contador = contador + 1

para item en lista_numeros
    si item % 2 == 0
        muestra item

# Operaciones Cyber (Red/Ecosistema)
escanea "10.0.0.1" en ports [80, 443]
busca subdomains de "example.com"
datos = desde "http://127.0.0.1"
envia {"user": "test"} a "http://127.0.0.1/login"
ataca "10.0.0.1" en target con wordlist "pass.txt" y username "admin"
enumera directories en "10.0.0.1" con wordlist "dirs.txt"
busca vulns en "10.0.0.1"
captura packets en "eth0"
analiza headers de "10.0.0.1"

# Pipelines y Transformacion de Datos (Calculo)
datos_filtrados = lista_numeros -> filtra donde x > 2
genera reporte con datos_filtrados
guarda datos_filtrados en "salida.txt"
'''

def get_torture_ast():
    tokens = Lexer(normalize(TORTURE_SCRIPT)).tokenize()
    return Parser(tokens).parse()

def test_linguistics_and_parser():
    ast = get_torture_ast()
    assert len(ast.statements) > 0, "AST deberia tener statements"

@pytest.mark.parametrize("lang", list_backends().keys())
def test_cross_transpilation_safety(lang):
    ast = get_torture_ast()
    t = get_backend(lang, ast)
    out = t.emit()
    
    # Pruebas de Calidad Estructural (Cero deuda)
    assert 'TODO' not in out.upper(), f"Backend {lang} contiene TODOs"
    assert 'STUB' not in out.upper(), f"Backend {lang} contiene STUBs"
    assert 'MOCK' not in out.upper(), f"Backend {lang} contiene MOCKs"
    assert 'NotImplementedError' not in out, f"Backend {lang} tiene nodos sin implementar"
    assert len(out.strip()) > 0, f"Backend {lang} generó código vacío"
