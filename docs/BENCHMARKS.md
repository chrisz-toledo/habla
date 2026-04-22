# Hado Benchmark Suite

Hado está diseñado para ser extremadamente rápido en su pipeline de transpilación, permitiendo que el DSL sea parseado y compilado en milisegundos hacia cualquiera de sus targets. Esto es crucial para su integración futura con Agentes de Inteligencia Artificial (Fase 2.0) donde la inferencia en tiempo real de tácticas de ciberseguridad requiere latencia cercana a cero.

## Metodología
Las pruebas se ejecutan sobre un script representativo (`benchmark.py`) de reconocimiento táctico que incluye lógicas condicionales, algebra booleana, diccionarios, y verbos agresivos (`CyberScan`, `CyberAttack`, `CyberAnalyze`, etc.). 
Los resultados mostrados representan el **promedio de 100 iteraciones**.

## 1. Pipeline Frontend (Lexer + Parser)
*   **Tiempo Promedio:** `0.315 ms`
*   *Nota:* El motor Frontend de Hado procesa texto en español en menos de medio milisegundo por iteración.

## 2. Pipeline Backend (Generación de Código)
Tiempo que tarda cada backend en consumir el AST (Abstract Syntax Tree) pre-parseado y emitir código fuente nativo idiomático.

| Backend      | Avg Transpile Time (ms) | Output Size (bytes) | Lines of Code |
| :---         | :---                    | :---                | :---          |
| **PYTHON**   | 0.032                   | 1435                | 39            |
| **GO**       | 0.030                   | 4695                | 144           |
| **RUST**     | 0.037                   | 6903                | 169           |
| **C**        | 0.043                   | 5717                | 150           |
| **BASH**     | 0.030                   | 1840                | 56            |
| **POWERSHELL**| 0.031                  | 2830                | 70            |
| **JAVASCRIPT**| 0.029                  | 2668                | 74            |
| **SOLIDITY** | 0.022                   | 1814                | 39            |
| **ARDUINO**  | 0.022                   | 2229                | 70            |

## Conclusiones
- **Rapidez Absoluta**: La generación de código backend toma una fracción mínima de milisegundo en Python `(~0.03 ms)`. Hado puede transpilar *miles* de payloads por segundo de forma síncrona.
- **Eficiencia Solidity/Arduino**: Al ser targets con restricciones estructurales rígidas (y no requerir frameworks asíncronos complejos como Tokio en Rust), logran el tiempo de transpilación más bajo de la suite (`0.022 ms`).
- **Rust y C**: Como era de esperarse, son los motores que emiten mayor volumen de código fuente (`~6.9KB / 169 líneas` para Rust) debido a las garantías de memoria estricta, manejo de punteros, y configuración del runtime asíncrono (`Tokio`). A pesar de la robustez generada, el motor sólo tarda `0.037 ms`.
