# Habla Language Specification v0.1.0

## 1. Lexical structure

### 1.1 Character set

Habla source files are UTF-8 encoded. The normalizer converts Spanish diacritics to ASCII before lexing. Keywords are always ASCII.

### 1.2 Comments

```habla
// This is a comment — everything to end of line is ignored
```

### 1.3 Indentation

Habla uses significant whitespace (Python-style). Blocks are defined by consistent indentation. Either spaces or tabs may be used, but not mixed. Tabs count as 4 spaces.

### 1.4 Keywords

```
si  sino  mientras  para  cada  en  fn  devuelve
muestra  lee  guarda  abre
filtra  ordena  agrupa  cuenta  suma
crea  borra  actualiza  envia
escanea  busca  captura  ataca  intercepta  analiza  genera
cuando  listos  espera  lanza  atrapa
cierto  falso  nulo  vacio
es  no  y  o  de  con  sin  como  donde  desde
target  ports  subdomains  alive  packets  interface
headers  severity  wordlist  vulns  reporte
por  a  al
```

### 1.5 Operators

```
->    # pipe
==  !=  >=  <=  >  <    # comparison
+  -  *  /  %            # arithmetic
=                         # assignment
.                         # property access
```

## 2. Types

Habla uses implicit typing. The transpiler infers types from context.

| Habla literal | Python type | C type | Rust type |
|--------------|-------------|--------|-----------|
| `42` | `int` | `int` | `i64` |
| `3.14` | `float` | `double` | `f64` |
| `"texto"` | `str` | `const char*` | `&str` |
| `cierto` | `True` | `1` | `true` |
| `falso` | `False` | `0` | `false` |
| `nulo` | `None` | `NULL` | `None` |
| `[1, 2]` | `list` | array | `Vec<_>` |
| `{"k": v}` | `dict` | struct | `HashMap` |

## 3. Statements

### 3.1 Assignment
```habla
variable = expresion
```

### 3.2 Conditional
```habla
si condicion
  bloque_verdadero
sino
  bloque_falso
```

### 3.3 While loop
```habla
mientras condicion
  bloque
```

### 3.4 For loop
```habla
para variable en iterable
  bloque

cada variable en iterable
  bloque
```

Both `para` and `cada` are identical — use whichever reads better.

### 3.5 Function definition
```habla
fn nombre(param1 param2)
  bloque
  devuelve valor
```

Parameters are space-separated OR comma-separated:
```habla
fn suma(a, b)
  devuelve a + b

fn mult a b
  devuelve a * b
```

### 3.6 Display
```habla
muestra expresion
```

### 3.7 File I/O
```habla
contenido = lee "archivo.txt"
guarda datos en "output.txt"
```

### 3.8 HTTP
```habla
datos = desde "https://api.com/endpoint"
datos = desde "https://api.com" con headers {"Authorization": token}
```

## 4. Expressions

### 4.1 Pipe operator
```habla
expresion -> paso1 -> paso2 -> paso3
```

Each step receives the output of the previous step as its implicit input.

Built-in pipe steps:
- `filtra donde condicion` — filter by condition
- `filtra alive` — filter truthy values
- `ordena por campo` — sort by field
- `cuenta` — count elements
- `muestra` — print (terminal step)
- `guarda "archivo"` — write to file (terminal step)
- `genera reporte` — generate report (terminal step)

### 4.2 Comparison operators
```habla
x == y    # igual
x != y    # distinto
x >= y    # mayor o igual
x <= y    # menor o igual
x > y     # mayor que
x < y     # menor que
x es y    # igual (alternativa)
x en L    # pertenece a la lista
```

### 4.3 Logical operators
```habla
a y b     # and
a o b     # or
no a      # not
```

### 4.4 String concatenation
```habla
"Hola " + nombre
```

### 4.5 Property access
```habla
respuesta.status
resultado.open_ports
```

### 4.6 Index access
```habla
lista[0]
diccionario["clave"]
```

## 5. Cybersecurity constructs

### 5.1 Port scan
```habla
escanea target "ip" en ports [22, 80, 443]
resultado = escanea target "192.168.1.1" en ports [22, 80]
```

### 5.2 Subdomain recon
```habla
subs = busca subdomains de "ejemplo.com"
```

### 5.3 Vulnerability search
```habla
busca vulns en target donde severity >= HIGH
```

### 5.4 Packet capture
```habla
captura packets en interface "eth0" donde "tcp port 443"
```

### 5.5 Brute force
```habla
ataca "ssh" en target con wordlist "rockyou.txt"
ataca "http" en "https://login.ejemplo.com" con usuario "admin" y wordlist "passwords.txt"
```

### 5.6 Report generation
```habla
genera reporte con resultados
genera reporte con datos -> guarda "report.md"
```

## 6. ASCII normalization

Applied to identifiers and keywords only, not to string literals:

| Input | Normalized |
|-------|-----------|
| `ñ` | `nh` |
| `á` | `a` |
| `é` | `e` |
| `í` | `i` |
| `ó` | `o` |
| `ú` | `u` |
| `ü` | `u` |
| `¿`, `¡` | (removed) |

## 7. Multi-target transpilation

```bash
habla compile script.habla              # Python (default)
habla compile --target c script.habla   # C
habla compile --target rust script.habla # Rust
habla run script.habla                  # Execute via Python
```

Generated C code requires GCC or Clang. Generated Rust code requires the Rust toolchain and may require Cargo dependencies (printed as a comment at the top of the file).
