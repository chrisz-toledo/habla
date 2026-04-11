# Habla — Design Decisions

This document explains the "why" behind every major design decision in Habla.

---

## 1. Why a DSL and not a general-purpose language?

A DSL lets us make strong assumptions about the problem domain. Cybersecurity has a very well-defined vocabulary, a set of common patterns, and a clear "shape" of programs: recon → scan → analyze → report.

A general-purpose language must handle every possible use case, which forces it to be more abstract and verbose. Habla can hardwire the patterns that appear 90% of the time in cybersecurity code and compress them into first-class constructs.

The tradeoff: Habla is not good for writing web servers or data science pipelines. It doesn't need to be.

---

## 2. Why transpile to Python/C/Rust instead of compiling natively?

**Python** was the obvious first target: the entire cybersecurity tooling ecosystem (nmap, scapy, requests, paramiko, dnspython) is in Python. Transpiling to Python means Habla code can use this entire ecosystem without re-implementing anything.

**C** was added for performance-critical use cases: packet crafting, low-level socket operations, embedded/IoT security research. C code can be compiled to a standalone binary with no Python dependency.

**Rust** was added for memory-safe low-level code: network tools, exploit development tooling, and anything where you want C-level performance with memory safety guarantees.

Transpiling is faster to implement than native compilation, allows leveraging existing tooling, and keeps the feedback loop short. We can add native compilation later (via LLVM) without changing the language.

---

## 3. Why bilingual (Spanish verbs + English nouns) and not 100% Spanish?

Cybersecurity is an English-dominated domain. CVEs, protocol names, tool names, and technical concepts are all in English. Translating them would:

1. Confuse practitioners who think in English technical terms
2. Make the code harder to read alongside documentation (which is always in English)
3. Force LLMs to translate concepts they already know in English

The insight: the **operators** of the language (what you do) benefit from being in Spanish because they're extremely common words that LLMs generate confidently and cheaply. The **nouns** (what you do it to) should stay in English because that's the natural language of the domain.

This is how practitioners actually talk: "vamos a **escanear** los **ports** del **target**" (spanglish).

---

## 4. Why ASCII-only, and how does the normalization work?

Three problems with Spanish diacritics in a programming language:

1. **Keyboard accessibility**: ñ, á, é, í, ó, ú are not on most keyboards worldwide. A security researcher in Asia or Eastern Europe would need to configure their keyboard differently.

2. **LLM tokenization cost**: Most LLMs tokenize `ñ` as 2-3 tokens instead of 1. Diacritics increase token count, which increases API costs.

3. **LLM generation errors**: LLMs frequently "forget" diacritics. If `función` is a keyword and an LLM writes `funcion`, you'd get a syntax error. This is a reliability problem.

**Solution**: Keywords are designed ASCII-first and never contain diacritics. For user-defined identifiers, the normalizer applies replacements before lexing. Both `año` and `anho` are the same identifier. This way, LLM errors become non-errors.

The normalization is applied **only to code**, not to string literal contents. `muestra "Año nuevo"` preserves the string exactly as written.

---

## 5. Why pipes (`->`) as the central operator?

Cybersecurity workflows are naturally sequential pipelines:

```
target → recon → scan → analyze → report
```

This matches how practitioners think and how LLMs generate code (step by step). The pipe operator makes this structure explicit and readable.

Pipes also reduce variable naming burden. Instead of:

```python
subdomains = find_subdomains(domain)
alive = filter(lambda x: resolves(x), subdomains)
scan_results = [scan(s, [80, 443]) for s in alive]
report = generate_report(scan_results)
```

You write:

```habla
busca subdomains de "domain.com" -> filtra alive -> escanea ports [80, 443] -> genera reporte
```

Each `->` is a token. The Python equivalent is ~15 tokens per line, ~60 total. The Habla version is 12 tokens total.

---

## 6. Why indentation instead of braces?

Braces (`{`, `}`) are:
- 2 tokens per block (open + close)
- Often generate "off by one" errors in LLM output (missing closing brace)
- Not needed when indentation is enforced consistently

Indentation-based blocks (Python-style) are:
- Zero tokens for block delimiters
- Visually clearer
- Already familiar to the Python ecosystem

The tradeoff: copy-pasting code between contexts can lose indentation. This is a known limitation of indentation-based languages (Python has it too), and it's acceptable given the benefits.

---

## 7. Why zero imports, and how are dependencies resolved?

Imports are pure boilerplate. Every Habla program that uses `desde` needs `import requests`. Every program that uses `escanea` needs socket imports. Making the user write these is:

1. Wasted tokens for the LLM
2. An error-prone step (wrong module name, missing dependency)
3. A readability problem (imports at the top of a short script add noise)

The transpiler tracks which constructs are used during AST traversal and injects the necessary imports at the top of the generated Python. This is deterministic — there's no ambiguity about which imports are needed.

For C and Rust, the same principle applies: the transpiler injects the right `#include` directives and `use` statements.

---

## 8. Why are error messages in Spanish?

The primary users of Habla are Spanish-speaking practitioners. Error messages in the same language as the code reduce the cognitive load of context-switching.

Additionally, LLMs that are given Spanish error messages can explain them to Spanish-speaking users without translation errors.

The error messages are also designed to be actionable, not just descriptive. Instead of "SyntaxError: unexpected token", you get "no esperaba 'x' en linea 5. Quizas quisiste escribir 'y'?".

---

## 9. Why cybersecurity as the first domain?

Several reasons:

1. **AI-native use case**: Security researchers are early adopters of LLMs. They regularly ask ChatGPT/Claude to write recon scripts, scan tools, and exploit PoCs.

2. **High boilerplate ratio**: Cybersecurity Python scripts have enormous boilerplate (imports, error handling, output formatting). The compression ratio of Habla is highest here.

3. **Domain vocabulary is well-defined**: The nouns (target, port, vuln, payload) and the verbs (scan, recon, exploit, analyze) are universally understood. This makes LLM generation more reliable.

4. **Ethical dual-use**: Cybersecurity tools are inherently dual-use. By making offensive capabilities easy to express, we also make defensive automation equally accessible. This democratizes security research.

5. **Personal motivation**: The creator of Habla works in cybersecurity and wanted a tool that matched how they actually think about problems.
