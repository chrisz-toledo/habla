import time
import os
import sys


# Add src to path so we can run directly
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../src')))

from hado.normalizer import normalize
from hado.lexer import Lexer
from hado.parser import Parser
from hado.backends import get_backend, list_backends

# Script de prueba realista (mezcla de logica y red)
BENCHMARK_SCRIPT = '''
# Configuración inicial
target_ip = "192.168.1.100"
puertos_criticos = [21, 22, 80, 443, 3389, 8080]
timeout_ms = 500
modo_sigiloso = cierto

# Función de decisión táctica
fn evaluar_objetivo(ip, sigiloso)
    si sigiloso
        muestra "Modo sigiloso activo. Omitiendo escaneo ruidoso."
        devuelve falso
    sino
        muestra "Iniciando escaneo agresivo..."
        devuelve cierto

# Ciclo principal de reconocimiento
para puerto en puertos_criticos
    si puerto == 80 o puerto == 443
        analiza headers de target_ip
        busca vulns en target_ip
    sino
        escanea target_ip en ports [puerto]

# Fase de Explotación
resultado_eval = evaluar_objetivo(target_ip, modo_sigiloso)
si resultado_eval == cierto
    ataca target_ip en target con wordlist "rockyou.txt" y username "admin"
    enumera directories en target_ip con wordlist "common.txt"

# Transformación de datos
datos_crudos = [10, 20, 30, 40, 50]
datos_procesados = datos_crudos -> filtra donde x > 25 -> cuenta

# Reporte Final
genera reporte con datos_procesados
guarda datos_procesados en "reporte_tactico.json"
'''

def run_benchmarks(iterations=100):
    print(f"=== HADO BENCHMARK SUITE ===")
    print(f"Midiendo rendimiento sobre {iterations} iteraciones del pipeline completo.")
    
    # 1. Lexing & Parsing Benchmark
    t0 = time.perf_counter()
    for _ in range(iterations):
        tokens = Lexer(normalize(BENCHMARK_SCRIPT)).tokenize()
        ast = Parser(tokens).parse()
    t1 = time.perf_counter()
    parse_time_ms = ((t1 - t0) / iterations) * 1000
    print(f"\\n[Pipeline Frontend]")
    print(f"Lexer + Parser Avg Time: {parse_time_ms:.3f} ms")
    
    # Pre-parse ast for backend testing
    tokens = Lexer(normalize(BENCHMARK_SCRIPT)).tokenize()
    ast = Parser(tokens).parse()
    
    # 2. Transpilation Benchmark
    backends = list_backends()
    
    print(f"\\n[Pipeline Backend - Generación de Código]")
    print(f"{'Backend':<12} | {'Avg Transpile Time (ms)':<25} | {'Output Size (bytes)':<20} | {'Lines of Code':<15}")
    print("-" * 80)
    
    for lang in backends.keys():
        t0 = time.perf_counter()
        out = ""
        for _ in range(iterations):
            t = get_backend(lang, ast)
            out = t.emit()
        t1 = time.perf_counter()
        
        transpile_time_ms = ((t1 - t0) / iterations) * 1000
        size_bytes = len(out.encode('utf-8'))
        lines = len(out.splitlines())
        
        print(f"{lang.upper():<12} | {transpile_time_ms:<25.3f} | {size_bytes:<20} | {lines:<15}")
    
if __name__ == "__main__":
    run_benchmarks()
