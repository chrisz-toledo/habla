# Habla Cybersecurity Cookbook

Common cybersecurity recipes in Habla. All examples require authorization on the target systems.

---

## Reconnaissance

### Subdomain enumeration
```habla
subs = busca subdomains de "target.com"
muestra "Subdominios encontrados: " + cuenta subs
para cada s en subs
  muestra s
guarda subs en "subs.txt"
```

### Quick port scan
```habla
escanea target "192.168.1.1" en ports [21, 22, 23, 25, 80, 443, 3306, 5432, 8080, 8443]
```

### Full OSINT pipeline
```habla
dominio = "target.com"

// Fase 1: Subdominios vivos
subs = busca subdomains de dominio -> filtra alive

// Fase 2: Puertos en cada subdominio
para cada sub en subs
  muestra "Escaneando " + sub
  escanea sub en ports [80, 443, 8080, 8443, 8888]

// Reporte
genera reporte con subs -> guarda "osint-report.md"
```

---

## Web Application Testing

### Analizar headers de seguridad
```habla
url = "https://target.com"
respuesta = desde url
muestra "Status: " + respuesta
```

### Fuzzing de parametros HTTP
```habla
payloads = ["' OR 1=1--", "<script>alert(1)</script>", "../../../etc/passwd"]
base_url = "https://target.com/search?q="

para cada payload en payloads
  url = base_url + payload
  muestra "Probando: " + url
```

---

## Network Analysis

### Captura de trafico HTTP
```habla
captura packets en interface "eth0" donde "tcp port 80"
```

### Captura de trafico HTTPS
```habla
captura packets en interface "en0" donde "tcp port 443"
```

---

## Credential Testing

### Brute force SSH
```habla
// SOLO en entornos autorizados
ataca "ssh" en "192.168.1.100" con wordlist "rockyou.txt"
```

### Brute force HTTP login
```habla
// SOLO en entornos autorizados
ataca "http" en "https://target.com/login" con usuario "admin" y wordlist "passwords.txt"
```

---

## Reporting

### Reporte simple
```habla
genera reporte con resultados
```

### Reporte con output a archivo
```habla
genera reporte con resultados -> guarda "security-report.md"
```

### Reporte de assessment completo
```habla
fn assessment(target_domain)
  subs = busca subdomains de target_domain
  muestra "Subdominios: " + cuenta subs

  para cada sub en subs
    escanea sub en ports [80, 443, 22, 3306]

  genera reporte con subs -> guarda target_domain + "-report.md"
  muestra "Assessment completado para " + target_domain

assessment("target.com")
```

---

## Multi-target scripts

### Scan de red local
```habla
// Escanear rango de IPs comunes en red local
prefijos = ["192.168.1.1", "192.168.1.2", "192.168.1.254", "10.0.0.1"]

para cada ip en prefijos
  muestra "Escaneando " + ip
  escanea ip en ports [22, 80, 443, 3389, 8080]
```

### Procesamiento de lista de targets
```habla
targets = lee "targets.txt"
muestra "Procesando " + cuenta targets + " targets"

para cada t en targets
  muestra "-> " + t
  escanea t en ports [80, 443]
```
