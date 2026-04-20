---
title: "MikroTik CHR Lab"
description: "Lab MikroTik CHR no Proxmox — estudo de roteamento para uso no NOC e preparação para MTCNA."
date: 2026-03-01
tags: ["mikrotik", "proxmox", "networking", "roteamento", "noc", "mtcna"]
---

Lab de MikroTik CHR rodando no Proxmox — construído para estudo de roteamento aplicado ao dia a dia de NOC e preparação para a certificação MTCNA.

---

## Infraestrutura

| Componente | Detalhe |
|---|---|
| Proxmox 8.x | Host de virtualização — PC físico dedicado |
| MikroTik CHR 7.20.8 | VM no Proxmox — RouterOS completo sem restrições de throughput em lab |
| pfSense | Gateway da rede doméstica |
| Arch Linux | PC físico de administração |

---

## Topologia de rede

O CHR opera com duas interfaces isoladas:

| Interface | Bridge | Rede | Função |
|---|---|---|---|
| `ether1` | `vmbr2` | `192.168.10.0/24` | WAN — acesso WinBox e internet |
| `ether2` | `vmbr99` | `10.99.0.0/24` | LAN — rede de lab isolada, sem uplink |

Esse isolamento permite testar configurações de roteamento sem risco para a rede doméstica.

---

## O que estudo aqui

- Configuração de interfaces e bridges
- Roteamento estático e dinâmico (OSPF, BGP básico)
- Firewall e filter rules no RouterOS
- NAT, DHCP Server, DNS cache
- VLAN tagging e trunk ports
- Acesso remoto via WinBox e SSH

---

## Contexto NOC

MikroTik é amplamente usado em ISPs e ambientes corporativos no Brasil. Conhecer RouterOS na prática — não só teoria — faz diferença no suporte N2 quando o incidente envolve roteamento.

---

{{< button href="https://github.com/lucasfelz/mikrotik-lab" target="_blank" >}}
Ver repositório completo
{{< /button >}}
