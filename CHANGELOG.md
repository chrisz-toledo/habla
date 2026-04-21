# Changelog

All notable changes to Hado will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [Unreleased]

### In Progress
- Rust backend funcional — memory safety, ownership model

---

## [0.5.0] - 2026-04-21

### Added
- Rust transpiler PoC (`rust_transpiler.py`) — esqueleto funcional con tipos básicos
- `python -m hado` como punto de entrada alternativo al CLI
- `hado check` — comando de verificación de sintaxis sin ejecutar
- Backend registry dinámico: `hado targets` lista estado de cada backend

### Changed
- Robustez del compilador: manejo de errores mejorado en lexer y parser
- CLI refactorizado en `src/hado/cli.py` con mejor UX de errores
- Módulo `src/hado/backends/base.py` como clase base compartida para todos los backends

### Fixed
- `genera report` ahora auto-guarda el JSON a disco automáticamente (`hado_report.json`)
- `muestra` agrupa múltiples argumentos en un solo `print()` — fix del bug de prints fragmentados (Operación Leviatán)

---

## [0.4.0] - 2026-04-14

### Added
- **Go backend funcional** (`go_backend.py`) — v1.0 de producción
  - `escanea` genera goroutines reales con `sync.WaitGroup` + `net.DialTimeout`
  - Solo stdlib de Go — cero dependencias externas
  - 188 tests pasando para el backend Go
- `concurrent_scanner_go.ho` — ejemplo de scanner concurrente en Go
- `stdlib/` en formato `.ho`: `red`, `archivo`, `texto`, `crypto`

### Changed
- El mismo código `.ho` compila a Python (secuencial) y Go (concurrente automáticamente)
- `hado compile --target go script.ho` genera código listo para `go build`

---

## [0.3.0] - 2026-04-13

### Added
- Python backend completo
  - Módulo `capture.py` — captura de paquetes con scapy/tcpdump
  - Módulo `attack.py` con alias `brute_force` — brute force SSH/HTTP/FTP
  - Módulo `fuzzer.py` — fuzzing de directorios y endpoints
- `enumera directories en target` — keyword para directory busting
- Operación Leviatán como script de ejemplo (`operacion_leviatan.ho`)
- 6/6 capacidades de Fase 3 verificadas

### Fixed
- Sintaxis de bloques: `retorna` como keyword
- Expresión ternaria funcional
- `escanea en target` funciona dentro de bloques `para cada`

---

## [0.2.0] - 2026-04-12

### Added
- Lexer/parser robusto con INDENT/DEDENT completo
- Módulos cybersec reales (no stubs):
  - `scanner.py` — port scan con socket real
  - `recon.py` — subdomain enumeration
  - `analysis.py` — análisis de headers HTTP (grade A–F, 9 headers)
  - `report.py` — generación de reportes en markdown, HTML, JSON, texto
  - `crypto.py` — hash MD5/SHA1/SHA256/SHA512, base64, tokens
- Pipes: `->` conecta verbos cyber en cadena
- 7 ejemplos funcionales en `examples/`
- Evidencia de ejecución en producción real: `docs/evidence/v0.2-proof-of-concept.md`

### Fixed
- Parsing de bloques multi-línea
- Auto-coerción string + no-string en `BinaryOp`
- Headers de seguridad HTTP con modo correcto en `analiza headers`

---

## [0.1.0] - 2026-04-11

### Added
- Initial release of Hado DSL
- Lexer with full INDENT/DEDENT support
- Recursive descent parser
- Three compilation backends: Python, C, Rust (stubs)
- Cybersecurity modules (stubs): scanner, recon, capture, attack, analysis, report
- CLI: `hado run`, `hado compile --target [python|c|rust]`, `hado repl`
- ASCII normalizer for Spanish diacritics
- 7 example programs in `.ho` format
- Full test suite
- Documentation: spec, tutorial, cybersec cookbook, LLM guide, design decisions
- Standard library stubs: red, archivo, texto, crypto
