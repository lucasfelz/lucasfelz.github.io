---
title: "Simple Port Scanner"
description: "Scanner TCP multi-porta em Python com banner grabbing e identificação de serviços."
date: 2025-11-01
tags: ["python", "pentest", "recon", "scripting", "ferramentas"]
---

Scanner TCP leve e multi-threaded construído com a biblioteca padrão do Python. Sem dependências externas.

---

## Funcionalidades

- Escaneamento dos top 1000 portas mais comuns (padrão Nmap)
- Banner grabbing com identificação de serviços
- Multi-threaded — 100 threads por padrão, configurável
- Timeout ajustável para redes lentas ou distantes
- Output em JSON salvo automaticamente em `reports/`
- Ordem de portas randomizada

---

## Uso básico
```bash
# Scan top 1000 portas (padrão)
./pscan.py 192.168.1.1

# Range customizado
./pscan.py 192.168.1.1 -p 1-1024

# Portas específicas
./pscan.py 192.168.1.1 -p 22,80,443,3306

# Scan agressivo em rede local
./pscan.py 192.168.1.1 -p 1-65535 -t 1000 --timeout 0.2
```

---

## Output
```
Starting Port Scan... Please, wait.
192.168.1.1
Start Time: 2026-01-25 14:30:22

22/TCP  (ssh)   OPEN > SSH-2.0-OpenSSH_8.2p1
80/TCP  (http)  OPEN > HTTP/1.1 200 OK
443/TCP (https) OPEN
3306/TCP (mysql) OPEN > 5.7.40-0ubuntu0.18.04.1

Open Ports Found: 4
Scan performed in 12.45 seconds
```

Resultado salvo automaticamente em `reports/portscan-YYYYMMDD-HHMMSS.json`.

---

## Por que construir quando existe o Nmap?

Entender como um scanner funciona internamente muda como você interpreta os resultados em campo. Saber o que acontece abaixo do Nmap — handshake TCP, estados de porta, timeouts, thread contention — é parte da formação ofensiva.

Além disso: ambientes restritos nem sempre permitem ferramentas externas. Saber escrever o seu próprio é uma vantagem real.

---

> ⚠️ Use apenas em sistemas que você possui ou tem autorização explícita para testar.

{{< button href="https://github.com/lucasfelz/simple-portscanner" target="_blank" >}}
Ver repositório completo
{{< /button >}}
