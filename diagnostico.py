
from habla import compile_to_source

PASS = "OK  "
FAIL = "FAIL"

results = []

def test(name, code, expect_in=None, expect_not_in=None, expect_error=False):
    try:
        out = compile_to_source(code, target="python")
        if expect_error:
            results.append((FAIL, name, "Expected error but compiled"))
            return
        ok = True
        reason = ""
        if expect_in and expect_in not in out:
            ok = False
            reason = f'Falta: "{expect_in}"'
        if expect_not_in and expect_not_in in out:
            ok = False
            reason = f'No deberia tener: "{expect_not_in}"'
        results.append((PASS if ok else FAIL, name, reason))
    except Exception as e:
        if expect_error:
            results.append((PASS, name, ""))
        else:
            results.append((FAIL, name, str(e)[:100]))

# ─── LEXER ────────────────────────────────────────────────────────────────
print("--- LEXER ---")
test("# comment",         '# comentario\nmuestra "ok"',       expect_in='print("ok")')
test("// comment",        '// comentario\nmuestra "ok"',      expect_in='print("ok")')
test("| pipe token",      "x = [1,2]\nx | muestra",           expect_in="print(")
test("-> pipe token",     "x = [1,2]\nx -> muestra",          expect_in="print(")
test("string dobles",     'x = "hello"',                      expect_in='"hello"')
test("string simples",    "x = 'hello'",                      expect_in="'hello'")
test("int literal",       "x = 42",                           expect_in="42")
test("float literal",     "x = 3.14",                         expect_in="3.14")
test("cierto → True",     "x = cierto",                       expect_in="True")
test("falso → False",     "x = falso",                        expect_in="False")
test("nulo → None",       "x = nulo",                         expect_in="None")

# ─── ASIGNACIONES ─────────────────────────────────────────────────────────
print()
print("--- ASIGNACIONES ---")
test("x = 5",             "x = 5",                            expect_in="x = 5")
test('x = "str"',         'x = "hola"',                       expect_in='x = "hola"')
test("x = a + b",         "x = 1 + 2",                        expect_in="1 + 2")
test("lista literal",     "x = [1, 2, 3]",                    expect_in="[1, 2, 3]")
test("dict literal",      'x = {"a": 1}',                     expect_in='{"a": 1}')
test("concat str+var",    'muestra "hola: " + nombre',        expect_in="str(nombre)")

# ─── CONTROL DE FLUJO ─────────────────────────────────────────────────────
print()
print("--- CONTROL DE FLUJO ---")
test("si basico",         'si x > 0\n  muestra "pos"',        expect_in="if x > 0")
test("si/sino",           'si x > 0\n  muestra "p"\nsino\n  muestra "n"', expect_in="else:")
test("mientras",          "mientras x < 10\n  x = x + 1",    expect_in="while x < 10")
test("para en",           "para i en lista\n  muestra i",     expect_in="for i in lista")
test("fn definicion",     "fn suma(a, b)\n  devuelve a + b",  expect_in="def suma")
test("fn llamada",        "fn f(x)\n  devuelve x\nresult = f(5)", expect_in="result = f(5)")

# ─── CYBER VERBS ──────────────────────────────────────────────────────────
print()
print("--- CYBER VERBS ---")
test("escanea ports list",  'escanea target "x" en ports [80, 443]', expect_in="_habla_scan")
test("escanea ports de",    "escanea ports de objetivo",             expect_in="_habla_scan")
test("escanea var en",      "escanea host en ports [22]",            expect_in="_habla_scan")
test("busca subdomains",    'busca subdomains de "dom.com"',         expect_in="_habla_find_subdomains")
test("busca vulns",         "busca vulns en target",                 expect_in="_habla_analyze")
test("analiza headers",     'analiza headers de "target.com"',       expect_in="_habla_analyze_headers")
test("analiza sin modo",    "analiza datos",                         expect_in="_habla_analyze")
test("genera reporte",      "genera reporte con datos",              expect_in="_habla_report")
test("genera report (en)",  "genera report con datos",               expect_in="_habla_report")
test("genera multi-arg",    "genera report con a, b, c",             expect_in="[a, b, c]")
test("captura packets",     'captura packets en interface "eth0"',   expect_in="_habla_capture")
test("ataca ssh",           "ataca ssh en target con wordlist lista",     expect_in="_habla_attack")

# ─── PIPES ────────────────────────────────────────────────────────────────
print()
print("--- PIPES ---")
test("pipe var->muestra",   "x = [1,2]\nx -> muestra",                        expect_in="print(x)")
test("pipe var|muestra",    "x = [1,2]\nx | muestra",                         expect_in="print(x)")
test("pipe 3 pasos (->)",   "busca subdomains de d -> filtra alive -> muestra", expect_in="print(")
test("pipe 3 pasos (|)",    "busca subdomains de d | filtra alive | muestra",   expect_in="print(")
test("pipe guarda",         'x = [1,2]\nx -> guarda "out.txt"',               expect_in="open(")
test("pipe en asignacion",  "y = busca subdomains de d",                       expect_in="_habla_find_subdomains")

# ─── OPERADORES ───────────────────────────────────────────────────────────
print()
print("--- OPERADORES ---")
test("comparacion >",      "si x > 5\n  muestra x",   expect_in="if x > 5")
test("comparacion ==",     "si x == 5\n  muestra x",  expect_in="if x == 5")
test("comparacion !=",     "si x != 5\n  muestra x",  expect_in="if x != 5")
test("logico y",           "si a y b\n  muestra a",   expect_in="if a and b")
test("logico o",           "si a o b\n  muestra a",   expect_in="if a or b")
test("logico no",          "si no x\n  muestra x",    expect_in="not x")
test("suma",               "x = a + b",               expect_in="a + b")
test("resta",              "x = a - b",               expect_in="a - b")
test("multiplicacion",     "x = a * b",               expect_in="a * b")
test("division",           "x = a / b",               expect_in="a / b")

# ─── RESUMEN ──────────────────────────────────────────────────────────────
print()
passed = sum(1 for r in results if r[0] == PASS)
failed = sum(1 for r in results if r[0] == FAIL)
total  = len(results)
pct    = int(passed/total*100)

print(f"RESULTADO FINAL: {passed}/{total} ({pct}%) ---- {failed} fallos")
print()
if failed:
    print("FALLOS DETALLADOS:")
    for status, name, detail in results:
        if status == FAIL:
            print(f"  [{name}]")
            print(f"    {detail}")
else:
    print("  Sin fallos de compilacion.")
