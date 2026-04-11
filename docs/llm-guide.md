# Habla LLM Guide — How to Generate Habla Code

This document is designed to be given to an LLM as context so it can generate correct Habla code.

---

## What is Habla? (200-word summary)

Habla is a cybersecurity DSL that transpiles to Python, C, and Rust. It is designed so that LLMs can write cybersecurity code more efficiently, cheaply, and with fewer errors.

The core design principle: **Spanish verbs as operators, English nouns for technical terms, zero boilerplate, ASCII-only**.

Every token must carry maximum semantic meaning. There are no imports, no type annotations, no curly braces, no async/await. The transpiler handles all of that.

Habla is indentation-based (like Python). Pipes (`->`) connect sequential operations. Variables are implicitly typed.

---

## All Keywords

### Control flow
| Keyword | Meaning | Python equivalent |
|---------|---------|------------------|
| `si` | if | `if` |
| `sino` | else | `else` |
| `mientras` | while | `while` |
| `para` / `cada` | for loop | `for` |
| `en` | in | `in` |
| `fn` | function definition | `def` |
| `devuelve` | return | `return` |

### I/O and data operations
| Keyword | Meaning | Python equivalent |
|---------|---------|------------------|
| `muestra` | print | `print()` |
| `lee` | read file | `open().read()` |
| `guarda X en "f"` | write file | `open("f","w").write()` |
| `desde "url"` | HTTP GET | `requests.get(url).json()` |
| `filtra donde cond` | filter | `[x for x in ... if cond]` |
| `ordena por campo` | sort | `sorted(..., key=...)` |
| `cuenta X` | count/length | `len(X)` |

### Cybersecurity
| Keyword | Meaning |
|---------|---------|
| `escanea target "ip" en ports [...]` | Port scan |
| `busca subdomains de "dom"` | Subdomain enumeration |
| `captura packets en interface "eth0"` | Packet capture |
| `ataca ssh en target con wordlist "f"` | Brute force |
| `analiza headers de "url"` | HTTP header analysis |
| `genera reporte con datos` | Generate report |

### Logic operators
| Habla | Python |
|-------|--------|
| `y` | `and` |
| `o` | `or` |
| `no` | `not` |
| `es` | `==` |
| `cierto` | `True` |
| `falso` | `False` |
| `nulo` | `None` |

### Pipe operator
`->` connects sequential operations:
```
datos -> filtra donde x > 0 -> ordena por nombre -> guarda "out.txt"
```

---

## 10 Most Common Patterns

### 1. Variable assignment
```habla
nombre = "Carlos"
edad = 25
activo = cierto
```

### 2. Print / display
```habla
muestra "Hola mundo"
muestra "Usuario: " + nombre
```

### 3. Conditional
```habla
si edad >= 18
  muestra "adulto"
sino
  muestra "menor"
```

### 4. For loop
```habla
para cada item en lista
  muestra item
```

### 5. Function definition
```habla
fn saludar(nombre)
  muestra "Hola, " + nombre
  devuelve "ok"
```

### 6. HTTP request
```habla
datos = desde "https://api.ejemplo.com/users"
```

### 7. Port scan
```habla
escanea target "192.168.1.1" en ports [22, 80, 443]
```

### 8. Subdomain recon
```habla
subs = busca subdomains de "ejemplo.com"
para cada s en subs
  muestra s
```

### 9. Pipe chain
```habla
resultado = "192.168.1.0/24" -> escanea ports [80, 443] -> filtra donde open
```

### 10. Save results
```habla
guarda resultados en "output.txt"
```

---

## Anti-patterns (what NOT to do)

```python
# INCORRECTO — no uses imports
import requests

# INCORRECTO — no uses llaves
if (x > 0) {
  print(x)
}

# INCORRECTO — no uses async/await
async def fetch():
  data = await requests.get(url)

# INCORRECTO — no uses type annotations
def scan(target: str, ports: List[int]) -> dict:

# INCORRECTO — no uses ñ, tildes, o signos invertidos en KEYWORDS
función = 42    # usa: funcion = 42
año = 2026      # usa: anho = 2026 o simplemente year = 2026
```

---

## System Prompt Template

Copy this into your system prompt to enable Habla code generation:

```
You are an expert in Habla, a cybersecurity DSL that transpiles to Python, C, and Rust.

Rules for generating Habla code:
- Use Spanish verbs for actions: muestra, filtra, escanea, busca, captura, ataca, analiza, genera
- Use English nouns for tech terms: target, port, host, payload, vuln, packet, interface, header
- Use -> for pipes: datos -> filtra donde x > 0 -> guarda "out.txt"
- No imports, no curly braces, no async/await, no type annotations
- Indentation-based blocks (2 spaces or 1 tab)
- ASCII only in keywords: no tildes (á,é,í,ó,ú), no ñ, no ¿ or ¡
- Booleans: cierto / falso. Logic: y / o / no. Null: nulo
- Keep it minimal: every token must carry meaning
- For loops: para cada X en lista OR para X en lista
- HTTP GET: datos = desde "url"
- Cybersec constructs need no imports — the transpiler handles them
```

---

## ASCII Normalization Reference

The parser automatically normalizes these — both forms are valid in identifiers:

| With diacritic | ASCII form |
|---------------|-----------|
| `ñ` | `nh` |
| `á, é, í, ó, ú` | `a, e, i, o, u` |
| `ü` | `u` |
| `¿, ¡` | (ignored) |

**KEYWORDS are always ASCII.** The language was designed ASCII-first so LLMs never need to guess whether to use tildes in keywords.
