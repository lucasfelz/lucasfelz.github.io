---
title: "GOAD Homelab"
description: "Lab ofensivo de Active Directory — Proxmox + pfSense + Cisco SF300. Not a tutorial lab. A working offensive infrastructure."
date: 2026-01-01
tags: ["homelab", "active-directory", "proxmox", "pfsense", "kali", "pentest", "vlan"]
_build:
  list: never
  render: always
---

Production-grade offensive security homelab construído para pesquisa em ataques de Active Directory e prática de penetration testing.

Não é um lab de tutorial. É uma infraestrutura ofensiva funcional.

---

## Infraestrutura

| Componente | Descrição |
|---|---|
| Proxmox VE 8.4 | Host de virtualização — Xeon E5-2630 v4, 16GB RAM |
| pfSense | Firewall/roteador virtual com 5 interfaces e roteamento inter-VLAN |
| Cisco SF300-24 | Switch gerenciado com VLAN tagging — 24x 100Mbps + 4x Gigabit |
| GOAD Lab | 6 VMs Windows vulneráveis — DCs, servidores, workstations |
| Kali Linux | VM de ataque em VLAN dedicada e isolada |

---

## Segmentação de Rede

A separação de redes é o coração do lab — garante isolamento real entre ambiente de ataque, alvo e rede doméstica.

| VLAN | Função | Internet |
|---|---|---|
| 10 — LAN | Gerenciamento Proxmox, rede doméstica | ✅ |
| 20 — TARGETS | Ambiente AD vulnerável — completamente isolado | ❌ |
| 30 — ATTACK | Kali Linux — acesso limitado | ⚠️ |
| 99 — QUARENTENA | WiFi IoT/convidados — sem acesso à LAN | ⚠️ |

### Fluxos de tráfego

**Permitidos:**
- VLAN 30 → VLAN 20 (Kali ataca o AD)
- VLAN 10 → Internet
- VLAN 20 ↔ VLAN 20 (VMs GOAD entre si)

**Bloqueados:**
- VLAN 20 → Internet (AD completamente isolado)
- VLAN 20 → VLAN 10 (lab não acessa rede doméstica)
- VLAN 30 → VLAN 10 (Kali não acessa rede doméstica)

---

## O que pratico aqui

- Kerberoasting e AS-REP Roasting
- ACL Abuse e Delegation attacks
- Pass-the-Hash e Pass-the-Ticket
- Lateral Movement entre domínios
- BloodHound enumeration e path analysis
- Privilege Escalation em Windows

---

## Guias de implementação

A documentação completa cobre cada etapa da construção do lab:

1. [Instalação do Proxmox VE](https://github.com/lucasfelz/goad-homelab/blob/main/docs/01-proxmox-installation.md)
2. [Configuração de Rede do Proxmox](https://github.com/lucasfelz/goad-homelab/blob/main/docs/02-proxmox-network.md)
3. [Instalação e Configuração do pfSense](https://github.com/lucasfelz/goad-homelab/blob/main/docs/03-pfsense-setup.md)
4. [Criação de VLANs e Regras de Firewall](https://github.com/lucasfelz/goad-homelab/blob/main/docs/04-vlan-firewall-rules.md)
5. [Implantação do GOAD Lab](https://github.com/lucasfelz/goad-homelab/blob/main/docs/05-goad-deployment.md)
6. [Configuração do Kali Linux](https://github.com/lucasfelz/goad-homelab/blob/main/docs/06-kali-setup.md)
7. [Testes de Conectividade e Validação](https://github.com/lucasfelz/goad-homelab/blob/main/docs/07-testing-validation.md)

Também disponível: [Troubleshooting](https://github.com/lucasfelz/goad-homelab/blob/main/docs/TROUBLESHOOTING.md) e [Comandos úteis](https://github.com/lucasfelz/goad-homelab/blob/main/docs/USEFUL-COMMANDS.md).

---

## Roadmap

- [x] Infraestrutura de rede completa (Proxmox + pfSense + VLANs)
- [x] Switch gerenciado com VLAN tagging
- [x] VM Kali em rede ofensiva isolada
- [ ] Deploy do GOAD via Ansible
- [ ] Wazuh SIEM monitorando VLAN 20
- [ ] Security Onion para análise de tráfego
- [ ] Snapshots pré-exploração automatizados

---

> ⚠️ Laboratório destinado exclusivamente para fins educacionais. Nunca utilize as técnicas aqui documentadas em sistemas sem autorização explícita.

{{< button href="https://github.com/lucasfelz/goad-homelab" target="_blank" >}}
Ver repositório completo
{{< /button >}}
