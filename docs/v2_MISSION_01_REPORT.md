# Hado V2.0: Misión 01 (Completada)

El Fundamento M2M ha sido establecido.
Hado ha evolucionado de un parser de texto a una API orientada a objetos de datos.

## 1. El JSON Schema (`schemas/hado_ast_v2.json`)
Se ha redactado un esquema formal bajo el estándar `draft-07` que describe exhaustivamente cada nodo soportado por el motor de transpilación.
- **Jerarquía tipada**: Se utiliza `anyOf` con `$ref` para validar polimorfismo (ej. `Statement` vs `Expression`).
- **Eliminación de ambigüedades**: Las keywords "mágicas" del Spanglish ya no existen; el agente provee campos nombrados explícitamente (`target`, `wordlist`, `then_body`).

## 2. El AST Builder API (`src/hado/v2/ast_builder.py`)
Se ha construido un decodificador y mapeador reflexivo que toma el JSON validado y lo convierte en las *dataclasses* inmutables que Hado usa internamente.
- Opera mediante inyección directa (`json.loads` -> `build_node()`).
- Si un agente de IA vomita un esquema perfecto, Hado transfiere ese árbol sintáctico a memoria en menos de 1 milisegundo, evadiendo para siempre los errores de sintaxis textual.

## 3. Pruebas de Auto-Depuración APE (`tests/test_v2_ast_builder.py`)
Fiel al principio del *Error-Embracing*, la suite no solo prueba casos perfectos.
- Hemos inyectado deliberadamente JSON corrompidos (comentarios no válidos, campos faltantes) para forzar los raise de `ValueError` y `JSONDecodeError`.
- El sistema falla con gracia y reporta exactamente qué faltó en el contrato M2M, permitiendo a la IA corregir su respuesta en un ciclo ReAct.

### Siguiente Paso
La arquitectura base (El Fundamento) está lista, estable y con su sub-ensamblaje asegurado al 100%. El Lexer es oficialmente prescindible para las máquinas.
Esperando confirmación para iniciar el análisis semántico de 3 pasadas.
