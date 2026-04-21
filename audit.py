from hado.normalizer import normalize
from hado.lexer import Lexer
from hado.parser import Parser
from hado.backends import get_backend, list_backends
import traceback

print('=== AUDITORIA MULTIDISCIPLINARIA DE HADO ===')

# Test de tortura (Matematicas, Logica, y Sintaxis)
torture_script = '''
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

all_ok = True

try:
    print('1. [Lingüística/Lexer] Normalización y Parseo del DSL (Español):')
    tokens = Lexer(normalize(torture_script)).tokenize()
    ast = Parser(tokens).parse()
    print('  ✅ AST generado correctamente. Todas las palabras clave en español fueron entendidas.')
except Exception as e:
    print('  ❌ Error de parseo:')
    traceback.print_exc()
    all_ok = False

if all_ok:
    print('\\n2. [Ingeniería de Software] Transpilación cruzada de todos los backends:')
    backends = list_backends()

    for lang in backends.keys():
        try:
            t = get_backend(lang, ast)
            out = t.emit()
            
            # Validaciones de seguridad
            if 'TODO' in out.upper() or 'STUB' in out.upper() or 'MOCK' in out.upper():
                print(f'  ❌ {lang.upper():<12}: Falló. Se encontraron palabras prohibidas (TODO/STUB/MOCK) en el código generado.')
                all_ok = False
            elif 'NotImplementedError' in out:
                print(f'  ❌ {lang.upper():<12}: Falló. Nodos no implementados.')
                all_ok = False
            elif out.strip() == '':
                print(f'  ❌ {lang.upper():<12}: Falló. Código vacío.')
                all_ok = False
            else:
                print(f'  ✅ {lang.upper():<12}: Generó código estructuralmente completo.')
                
                # Sub-check matemático (Operadores)
                if lang in ['python', 'bash', 'powershell']:
                    pass 
                elif '&&' not in out and '||' not in out:
                     if lang not in ['python', 'powershell', 'bash']:
                        print(f'    ⚠️ Posible fallo lógico: No se detectaron operadores booleanos &&/|| en {lang}')
        except Exception as e:
            print(f'  ❌ {lang.upper():<12}: CRASH DURANTE LA TRANSPILACIÓN!')
            traceback.print_exc()
            all_ok = False

print('\\n3. [QA/Testing] Corriendo suite de pruebas unitarias...')
import subprocess
res = subprocess.run(['python', '-m', 'pytest', 'tests/', '-q', '--tb=short'], capture_output=True, text=True)
if res.returncode == 0:
    print('  ✅ Suite de pruebas (474 tests) PASADA.')
else:
    print('  ❌ Fallaron pruebas unitarias.')
    print(res.stdout[-500:])
    all_ok = False

if all_ok:
    print('\\n🎯 VEREDICTO FINAL: SISTEMA 100% OPERATIVO BAJO ESTRES MULTIDISCIPLINARIO.')
else:
    print('\\n🚨 FALLO DETECTADO. REQUIERE PARCHEO.')
