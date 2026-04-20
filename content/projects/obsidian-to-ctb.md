---
title: "obsidian-to-ctb"
description: "Conversor de Obsidian vault para CherryTree .ctb — Python puro, sem dependências externas."
date: 2026-04-01
tags: ["python", "ferramentas", "obsidian", "cherrytree", "scripting"]
---

Ferramenta Python que converte um vault do Obsidian para o formato `.ctb` do CherryTree (SQLite). Zero dependências externas — só biblioteca padrão do Python 3.10+.

---

## Problema resolvido

CherryTree é amplamente usado para anotações em pentest (compatível com metodologias como PTES). Obsidian, por outro lado, é excelente para construção de conhecimento com Markdown. Este conversor permite manter notas no Obsidian e exportar para CherryTree quando necessário — sem perder estrutura.

---

## Uso

```bash
# Conversão básica
python3 obsidian_to_ctb.py ~/Documents/MyVault ~/output

# Nome de arquivo customizado
python3 obsidian_to_ctb.py ~/Documents/MyVault ~/output --output-name pentest.ctb

# Ignorar pastas específicas
python3 obsidian_to_ctb.py ~/Documents/MyVault ~/output --skip "Private" "Archive"
```

---

## Mapeamento de elementos

| Markdown (Obsidian) | CherryTree |
|---|---|
| `# H1` / `## H2` / `### H3` | Headings hierárquicos |
| `**negrito**` | Bold |
| `*itálico*` | Italic |
| `` `código` `` | Código inline |
| Blocos de código | Nó de código com syntax highlight |
| Listas e sublistas | Listas aninhadas |
| Links internos `[[nota]]` | Referência entre nós |

---

## Por que Python puro

Ferramentas de pentest precisam rodar em qualquer ambiente — sem `pip install`, sem virtualenv, sem surpresa. Depender só da stdlib garante portabilidade real.

---

{{< button href="https://github.com/lucasfelz/obsidian-to-ctb" target="_blank" >}}
Ver repositório completo
{{< /button >}}
