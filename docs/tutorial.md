# Habla Tutorial — Building a Port Scanner

This tutorial walks you through Habla by building a real port scanner, step by step.

## Prerequisites

```bash
pip install habla-lang
```

## Step 1: Hello World

Create `hello.habla`:

```habla
muestra "Hola desde Habla!"
```

Run it:

```bash
habla run hello.habla
```

Output:
```
Hola desde Habla!
```

## Step 2: Variables

```habla
target = "127.0.0.1"
ports = [22, 80, 443, 8080]

muestra "Escaneando: " + target
muestra "Puertos: " + ports
```

No type annotations. No `let`, `var`, or `const`. Just assign and go.

## Step 3: Your first scan

```habla
target = "127.0.0.1"
escanea target en ports [22, 80, 443]
```

This generates Python that uses `socket.connect_ex` (or `nmap` if available). The output shows which ports are open or closed.

## Step 4: Conditionals

```habla
puerto = 80
objetivo = "127.0.0.1"

si puerto == 80
  muestra "Escaneando puerto HTTP"
sino
  muestra "Escaneando otro puerto"

escanea objetivo en ports [puerto]
```

## Step 5: Loops

```habla
targets = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]

para cada t en targets
  muestra "Escaneando: " + t
  escanea t en ports [22, 80, 443]
```

## Step 6: Functions

```habla
fn escanear_target(ip)
  muestra "Iniciando escaneo de " + ip
  resultado = escanea ip en ports [22, 80, 443, 3306, 5432]
  devuelve resultado

resultado1 = escanear_target("192.168.1.1")
resultado2 = escanear_target("192.168.1.2")
```

## Step 7: HTTP requests

```habla
url = "https://httpbin.org/json"
datos = desde url
muestra datos
```

`desde` makes a GET request and returns the JSON response.

## Step 8: Pipe chains

The real power of Habla:

```habla
// Buscar subdominios, filtrar los que responden, mostrar resultados
busca subdomains de "example.com" -> filtra alive -> muestra
```

Each `->` passes the result of the previous step to the next.

## Step 9: Save results

```habla
subs = busca subdomains de "example.com"
guarda subs en "subdomains.txt"
```

## Step 10: Full scanner

```habla
fn scan_completo(dominio)
  muestra "=== Iniciando assessment de " + dominio + " ==="

  // Recon
  muestra "Fase 1: Subdominios"
  subs = busca subdomains de dominio
  muestra "Encontrados: " + cuenta subs

  // Scan
  muestra "Fase 2: Escaneo de puertos"
  para cada sub en subs
    escanea sub en ports [80, 443, 8080, 8443]

  // Reporte
  muestra "Fase 3: Reporte"
  genera reporte con subs -> guarda "report.md"
  muestra "Assessment completado."

scan_completo("example.com")
```

## What just happened?

Each `habla run script.habla` goes through this pipeline:

```
.habla → normalizer → lexer → parser → AST → Python transpiler → exec()
```

No compilation step. No waiting. The Python is generated and executed in memory.

## See the generated Python

```bash
habla compile scanner.habla
```

This shows you the Python that Habla generates — useful for debugging and for understanding what the transpiler does.

## Generate C or Rust

```bash
habla compile --target c scanner.habla
habla compile --target rust scanner.habla
```

The C and Rust outputs are self-contained and can be compiled natively.

## Next steps

- Read the [language specification](spec.md) for a complete reference
- Browse the [cybersec cookbook](cybersec-cookbook.md) for more examples
- Read the [LLM guide](llm-guide.md) if you want to integrate Habla with an AI system
