---
title: "Wazuh Docker Secure"
description: "Automação de deploy seguro do Wazuh SIEM com Docker — hardening, geração de certificados e gestão de credenciais."
date: 2026-01-01
tags: ["siem", "wazuh", "docker", "hardening", "bash", "infra"]
---

Automação completa para deploy do Wazuh SIEM via Docker com foco em segurança — elimina senhas padrão, gera certificados SSL e aplica hardening na stack inteira.

---

## O problema

O deploy padrão do Wazuh Docker usa credenciais default em todos os componentes. Em ambientes reais — mesmo de lab — isso é inaceitável. O projeto automatiza o que deveria ser manual: troca de todas as senhas, geração de certificados e aplicação de boas práticas de segurança.

---

## O que faz

### Setup completo (`wazuhDockerFullSetup.sh`)
- Clona o repositório oficial do Wazuh Docker
- Gera certificados SSL para toda a stack
- Substitui **todas** as senhas padrão por senhas aleatórias seguras
- Sobe o ambiente com `docker compose`
- Exibe as credenciais geradas de forma organizada

### Reset de senhas (`wazuhResetPassword.sh`)
- Lista todos os usuários do Wazuh instalado
- Gera novas senhas seguras por tipo de usuário
- Atualiza arquivos de configuração automaticamente
- Reinicia os serviços para aplicar as mudanças

---

## Uso

```bash
# Setup completo (fresh install)
sudo bash -c "$(wget -qLO - https://raw.githubusercontent.com/lucasfelz/wazuh-docker-secure-for-multi-node/main/wazuhDockerFullSetup.sh)"

# Reset de senhas (instalação existente)
sudo bash -c "$(wget -qLO - https://raw.githubusercontent.com/lucasfelz/wazuh-docker-secure-for-multi-node/main/wazuhResetPassword.sh)"
```

**Requisitos:** Docker com Compose V2, Git, acesso sudo, internet.

---

## Por que isso importa

SIEM com credenciais padrão não é SIEM — é mais um vetor de ataque. Automatizar o hardening desde o primeiro deploy é prática de segurança básica que falta na documentação oficial.

---

> ⚠️ Scripts destinados a ambientes autorizados. Teste em lab antes de usar em produção.

{{< button href="https://github.com/lucasfelz/wazuh-docker-secure-for-multi-node" target="_blank" >}}
Ver repositório completo
{{< /button >}}
