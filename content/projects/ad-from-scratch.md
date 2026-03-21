---
title: "Active Directory from Scratch"
description: "Ambiente corporativo simulado com Windows Server 2019 — construído do zero com automação PowerShell."
date: 2025-12-01
tags: ["active-directory", "windows-server", "powershell", "homelab"]
---

Windows Server 2019 + Windows 10 lab simulating a corporate AD environment. Built to be broken.

## O que foi implementado

- Instalação e configuração de AD DS, DHCP e DNS
- Criação de Unidades Organizacionais e usuários via PowerShell
- Aplicação de Group Policy Objects (GPOs)
- Rede em NAT + rede interna isolada
- Base documentada para prática de exploração em AD

## Automação PowerShell

Todo o provisionamento de usuários e OUs foi automatizado via scripts PowerShell — replicando o que acontece em ambientes corporativos reais onde administradores criam dezenas de contas de uma vez.

## Relação com o GOAD Homelab

Este projeto é a base conceitual do GOAD Homelab — antes de atacar um AD complexo, é preciso entender como ele é construído. Montar um do zero é a melhor forma de aprender o que quebrar depois.

{{< button href="https://github.com/lucasfelz/ad-from-scratch" target="_blank" >}}
Ver repositório completo
{{< /button >}}
