# ============================================
# PASSO 4: CONFIGURAR HUGO
# ============================================

# Editar config principal
cat > config/_default/config.toml << 'EOF'
baseURL = 'https://lucasfelz.github.io/'
languageCode = 'pt-br'
title = 'Lucas Felz - Pentest & Security'
theme = 'blowfish'
publishDir = 'docs'

[module]
  [module.hugoVersion]
    extended = true
    min = "0.87.0"
EOF

echo "✅ Config principal criado"

# Configurar idioma PT-BR
cat > config/_default/languages.pt-br.toml << 'EOF'
languageCode = "pt-br"
languageName = "Português (Brasil)"
weight = 1
title = "Lucas Felz"

[params]
  displayName = "PT-BR"
  isoCode = "pt-br"
  rtl = false
  dateFormat = "2 January 2006"
  description = "Pentester em formação | CTF Player | Writeups em Português"

[author]
  name = "Lucas Felz"
  image = "img/avatar.jpg"
  headline = "Pentester | CTF Player | Security Enthusiast"
  bio = "Pentester em treinamento com foco em infraestrutura e Active Directory. Compartilhando writeups de CTFs em português."
  
  links = [
    { github = "https://github.com/lucasfelz" }
  ]

[homepage]
  layout = "profile"
  showRecent = true
  cardView = true
EOF

echo "✅ Idioma configurado"

# ============================================
# PASSO 5: CRIAR ESTRUTURA DE CONTEÚDO
# ============================================

# Criar pastas
mkdir -p content/writeups
mkdir -p static/img

# Criar página sobre
cat > content/about.md << 'EOF'
---
title: "whoami"
date: 2025-11-24
draft: false
showDate: false
showReadingTime: false
---

# Lucas Felz

Pentester em treinamento, focado em infraestrutura e Active Directory.

## O que faço

- 💻 Estudante de Análise e Desenvolvimento de Sistemas 
- 🎯 CTF Player (HackTheBox, TryHackMe)
- 🔐 Estudando para certificação eJPT
- 💻 Trabalho em IT Support
- 🏠 Homelab com Proxmox
- 🏠 Pai de uma menina 
- 🏠Formado em psicologia, com 5 anos de experiência em psicologia clínica
- 💻Estusiasta de computadores, apaixonado por segurança da informação


## Contato

- **GitHub:** [@lucasfelz](https://github.com/lucasfelz)
- **Writeups em Português** 🇧🇷
EOF

echo "✅ Página Sobre criada"





# ============================================
# PASSO 6: CRIAR .gitignore
# ============================================

cat > .gitignore << 'EOF'
.hugo_build.lock
resources/
public/
.DS_Store
*.swp
*~
EOF

echo "✅ .gitignore criado"

# ============================================
# PASSO 7: TESTAR LOCALMENTE
# ============================================

echo ""
echo "🧪 TESTANDO SITE LOCALMENTE..."
echo "Pressione Ctrl+C para parar"
echo ""

hugo server -D

# Após testar (Ctrl+C), continue...

