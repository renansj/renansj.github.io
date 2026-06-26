---
title: "Inferência de Tipo é Superfície de Ataque: Quando o Runtime Decide pelo Atacante"
published: true
tags: [appsec, type-confusion, deserialization, web-security, pt-br]
---

## Por que isso importa

Tem uma pergunta que eu passei a fazer em todo code review, e ela mudou a forma como eu encontro vulnerabilidade: "qual tipo o sistema vai inferir aqui, e quem controla essa decisão?"

Parece abstrato, mas é o oposto disso. É a coisa mais concreta que existe. Toda vez que um sistema recebe um dado e decide sozinho o que aquilo "é", ele está tomando uma decisão no lugar do desenvolvedor. E se o atacante controla o dado, ele controla a decisão. Esse é o poço sem fundo de onde saem prototype pollution, type juggling, desserialização insegura, mass assignment e metade dos bypasses de autenticação que eu já vi.

Nos posts anteriores sobre [request smuggling](https://renansj.dev/http-request-smuggling), [web cache deception](https://renansj.dev/web-cache-deception) e [SSRF](https://renansj.dev/ssrf), o fio condutor era desacordo entre componentes ou confiança excessiva. Aqui o tema é outro, e é mais profundo: a conveniência da linguagem é a superfície de ataque. Quanto mais "esperto" o runtime é para adivinhar o que você quis dizer, mais espaço ele dá para o atacante dizer outra coisa.

Este artigo não é sobre uma vulnerabilidade. É sobre o padrão gerador de uma família inteira delas. Eu vou usar uma lente formal simples (lógica de Hoare) para mostrar que todas essas vulns são a mesma coisa vista de ângulos diferentes, e depois vou descer ao código concreto em JavaScript, PHP, Python, Java e .NET.

### Público-alvo

* Pentesters e profissionais de AppSec que querem parar de caçar padrão e começar a caçar a causa
* Desenvolvedores que querem entender por que "a linguagem ajudou" costuma ser o começo do problema
* Quem está estudando para OSWE, BSCP ou pesquisa de vulnerabilidade em geral
* Qualquer pessoa que já se perguntou por que as mesmas classes de bug reaparecem década após década

## A lente: toda vulnerabilidade é uma pré-condição quebrada

Antes do código, eu preciso de uma ferramenta mental. A mais útil que eu conheço é a **tripla de Hoare**, criada por Tony Hoare em 1969. A notação é simples:

```
{P} C {Q}
```

* `P` é a pré-condição: o que precisa ser verdade antes do comando `C` rodar
* `C` é o comando, o trecho de código
* `Q` é a pós-condição: o que fica verdade depois de `C` rodar

Lê-se: "se P é verdade antes de C, então Q é verdade depois". Um exemplo trivial:

```
{x == 5}  x = x + 1  {x == 6}
```

Se `x` valia 5 antes, depois de somar 1 ele vale 6. Óbvio. Mas o poder da notação não está no óbvio, está no que ela revela quando você aplica a código de verdade.

Pega um exemplo com cheiro de segurança:

```
{usuario.role == "admin"}  deletarConta(id)  {conta deletada}
```

A pré-condição diz que só um admin chega nesse comando. Agora a pergunta de pesquisa: **essa pré-condição é verificada no código, ou só assumida?** Se ela é apenas assumida, existe um caminho onde `deletarConta` roda com `usuario.role != "admin"`. Isso é broken authorization. Formalmente, a pré-condição não é garantida.

É isso que eu quero que fique gravado: **uma vulnerabilidade é uma tripla de Hoare cuja pré-condição o código não garante.** Toda vez. Sem exceção.

Olha como classes de bug que parecem não ter nada a ver caem todas no mesmo molde:

| Vulnerabilidade | Tripla quebrada |
|---|---|
| SQL Injection | `{input é dado, não comando}` query(input) `{só leitura/escrita pretendida}` |
| Buffer Overflow | `{len(input) <= tamanho_buffer}` copia(buf, input) `{memória intacta}` |
| IDOR | `{usuário é dono do recurso}` getRecurso(id) `{retorna dado autorizado}` |
| Desserialização | `{input é do tipo T esperado}` deserialize(input) `{objeto T válido}` |
| Type juggling | `{comparação compara o que eu acho que compara}` if (a == b) `{decisão correta}` |

A pré-condição é sempre algo que o desenvolvedor **achou** que era verdade. A vulnerabilidade é o caminho onde ela é falsa.

Agora vem o pulo do gato deste artigo: existe uma categoria de pré-condição que é **impossível de garantir por design**. E ela aparece exatamente quando o sistema infere tipo a partir de input controlável.

## O espectro da expressividade do input

Nem todo input é igual. A diferença que importa para segurança é: **quanto poder o formato dá ao atacante para descrever não apenas dados, mas estrutura e comportamento.**

Pensa nisso como um espectro:

```
DADOS PUROS  <-------------------------------------------->  CÓDIGO DISFARÇADO

JSON sem      Protobuf     JSON com tipo    YAML       Pickle      BinaryFormatter
type hints    (schema)     no campo         unsafe     (Python)    (.NET)
```

Na ponta esquerda, o input só pode dizer "meu nome é uma string igual a João, minha idade é o número 30". Ele não tem vocabulário para dizer mais nada. A pré-condição "isso é só dado" é verificável: basta validar contra um schema fixo.

Na ponta direita, o input pode dizer "instancie a classe `Runtime`, chame `exec` com este argumento". O formato dá ao atacante o vocabulário para descrever comportamento. A pré-condição "isso é só dado" deixa de ser verificável, porque o próprio formato permite expressar não-dados.

Esse é o ponto central. **A insegurança não é um bug de implementação na ponta direita. É uma propriedade do design.** Você entregou ao atacante uma linguagem de programação e pediu para ele se comportar.

## O coração: inferência de tipo como superfície de ataque

Aqui é onde a teoria vira código. Vou passar por cinco ambientes, do mais conhecido ao mais sutil.

### JavaScript: coerção que decide por você

JavaScript foi desenhado para nunca quebrar na cara do usuário. Em vez de dar erro quando você compara coisas de tipos diferentes, ele "conserta" para você. Esse conserto é a vulnerabilidade.

```javascript
// O clássico que todo mundo conhece
0 == "0"        // true  (string vira número)
0 == ""         // true  (string vazia vira 0)
0 == false      // true
"" == false     // true
[] == false     // true  (array vazio vira "" vira 0 vira false)
null == undefined // true

// O que isso faz com autenticação:
function verificarToken(tokenEnviado, tokenReal) {
  if (tokenEnviado == tokenReal) {  // == em vez de ===
    return true;
  }
  return false;
}
```

Parece inofensivo até você perceber o que acontece quando `tokenReal` é `0` (por exemplo, um índice, um ID que veio como número) e o atacante manda `tokenEnviado = false` ou `tokenEnviado = ""`. A coerção transforma a comparação em verdadeira.

Em termos de Hoare, o desenvolvedor escreveu:

```
{tokenEnviado é o token correto}  if (tokenEnviado == tokenReal)  {acesso autorizado}
```

Mas `==` não compara o que ele acha que compara. A pré-condição assume comparação estrita. O runtime entrega comparação após coerção. O gap entre as duas é a vulnerabilidade.

#### Prototype pollution: o caso mais bonito e mais perigoso

JavaScript leva a inferência a um extremo: todo objeto herda de um protótipo, e em muitos casos o atacante consegue alcançar esse protótipo via input. Observe:

```javascript
// Função "inofensiva" de merge, presente em milhares de libs
function merge(destino, fonte) {
  for (let chave in fonte) {
    if (typeof fonte[chave] === "object" && fonte[chave] !== null) {
      if (!destino[chave]) destino[chave] = {};
      merge(destino[chave], fonte[chave]);  // recursão
    } else {
      destino[chave] = fonte[chave];
    }
  }
  return destino;
}

// Uso normal e esperado
let config = {};
let entradaUsuario = JSON.parse('{"tema": "escuro"}');
merge(config, entradaUsuario);
// config = { tema: "escuro" }   tudo certo
```

Agora o atacante manda uma chave que o desenvolvedor nunca imaginou que seria interpretada de forma especial:

```javascript
let payload = JSON.parse('{"__proto__": {"isAdmin": true}}');
merge({}, payload);

// A partir de agora, QUALQUER objeto no programa:
let usuarioQualquer = {};
console.log(usuarioQualquer.isAdmin);  // true
```

O que aconteceu? A string `"__proto__"`, para o desenvolvedor, era só mais uma chave de dados. Para o runtime do JavaScript, ela é a referência ao protótipo do objeto. O sistema **inferiu** um significado especial a partir de um dado que o atacante controla. A pré-condição "as chaves do input são apenas nomes de propriedade comuns" é falsa, e o desenvolvedor nem sabia que essa era uma pré-condição.

A cadeia de impacto vai longe. Se mais adiante o código faz algo como:

```javascript
// Em algum ponto do servidor, montando opções para renderizar um template
let opcoes = {};
if (usuario.preferencias) {
  opcoes = usuario.preferencias;
}
// Se o protótipo foi poluído com uma propriedade que o template engine
// interpreta (por exemplo, configuração de compilação que aceita código),
// prototype pollution vira RCE.
```

Prototype pollution sozinho parece bobagem ("e daí que um objeto tem `isAdmin`?"). Encadeado com um sink que lê propriedades do protótipo (template engines como EJS, Pug e Handlebars, ou opções de `child_process`), vira RCE. Isso não é teoria: é a base de várias CVEs reais em pacotes do ecossistema Node.

### PHP: o reino do type juggling

PHP fez as mesmas escolhas de JavaScript e adicionou algumas próprias. O resultado é uma fábrica de bypass de autenticação.

```php
<?php
// Magic hashes: o problema dos hashes que "parecem" notação científica
var_dump("0e123" == "0e456");   // true
// Por que? PHP vê duas strings que parecem números em notação
// cientifica (0 elevado a algo = 0), entao compara 0 == 0.

// Onde isso explode:
$senhaHashArmazenada = "0e462097431906509019562988736854"; // md5 de uma senha
$hashTentativa = md5($senhaEnviada);

if ($hashTentativa == $senhaHashArmazenada) {  // == solto
    // Se md5($senhaEnviada) também começar com 0e seguido só de dígitos,
    // os dois viram 0 e a comparação passa, sem a senha bater.
    autenticar();
}
?>
```

Existem strings conhecidas cujo MD5 tem o formato `0e` seguido apenas de dígitos. Mandando uma delas, o atacante faz `0 == 0` e passa pela autenticação sem nunca acertar a senha.

A pré-condição que o desenvolvedor escreveu:

```
{hash da senha enviada == hash armazenado}  if (...)  {senha correta}
```

A pré-condição que o runtime entregou:

```
{interpretação numérica de um hash == interpretação numérica do outro}
```

São coisas diferentes, e a diferença é a chave de entrada.

PHP tem o mesmo veneno com arrays e comparações de string vindas de input:

```php
<?php
// strcmp esperando string, recebendo array
if (strcmp($_GET['senha'], $senhaReal) == 0) {
    autenticar();
}
// Atacante manda: ?senha[]=qualquercoisa
// strcmp(array, string) retorna NULL em versoes antigas
// NULL == 0 é true. Bypass.
?>
```

O atacante mudou o **tipo** do parâmetro (de string para array) e quebrou a suposição implícita de que `$_GET['senha']` seria uma string.

### Python: a desserialização que executa

Python tem tipagem forte (ele não vai dizer que `0 == "0"`), mas tem outro buraco: formatos de serialização que carregam comportamento.

```python
import pickle
import os

# Classe maliciosa que define o que acontece ao ser desserializada
class Exploit:
    def __reduce__(self):
        # __reduce__ diz ao pickle como reconstruir o objeto.
        # O atacante usa isso para reconstruir... um comando shell.
        return (os.system, ("id > /tmp/pwned",))

# Atacante serializa o objeto malicioso
payload = pickle.dumps(Exploit())

# Servidor desserializa input do atacante (ex: cookie, cache, fila)
pickle.loads(payload)  # executa "id > /tmp/pwned"
```

O `pickle.loads` recebe bytes e reconstrói um objeto. Mas "reconstruir um objeto" em Python pode significar "chamar uma função arbitrária", porque o formato pickle permite descrever isso. A pré-condição:

```
{input é a representação serializada de um objeto de dados confiável}
```

é impossível de garantir, porque o formato pickle não distingue "dado" de "instrução de reconstrução que chama os.system". O atacante tem o vocabulário para descrever execução.

O mesmo vale para YAML quando carregado sem cuidado:

```python
import yaml

# yaml.load (sem SafeLoader) infere tipos Python a partir de tags
payload = """
!!python/object/apply:os.system
args: ['id > /tmp/pwned']
"""

yaml.load(payload, Loader=yaml.Loader)  # executa o comando

# A versao segura recusa instanciar tipos arbitrarios:
yaml.safe_load(payload)  # levanta erro, nao executa nada
```

A tag `!!python/object/apply` é o YAML dando ao atacante a chave para dizer "instancie este tipo Python e aplique estes argumentos". `yaml.load` infere e obedece. `yaml.safe_load` se recusa a inferir tipos arbitrários, e por isso é seguro. A diferença entre os dois é exatamente a diferença entre "deixo o input escolher o tipo" e "fixo os tipos permitidos".

### Java: gadgets e o tipo que vem no stream

Java tem o caso mais estudado de todos. `ObjectInputStream` reconstrói objetos cujo tipo vem **dentro do próprio stream serializado**. O atacante escolhe o tipo.

```java
// Código vulnerável: desserializa bytes que vêm da rede
ObjectInputStream ois = new ObjectInputStream(inputDoAtacante);
Object obj = ois.readObject();  // o tipo de obj é escolhido pelo atacante
```

Sozinho, isso parece controlável. O problema é que o classpath de qualquer aplicação Java real tem dezenas de bibliotecas (Commons Collections, Spring, Groovy), e algumas delas têm classes cujos métodos de reconstrução (`readObject`, `readResolve`) executam comportamento. São os **gadgets**. Encadeando gadgets, ferramentas como o ysoserial montam um objeto que, ao ser desserializado, executa um comando.

A pré-condição:

```
{input é a forma serializada de um tipo seguro e esperado}
```

é, de novo, impossível de garantir. Provar que **nenhuma** combinação de tipos disponíveis no classpath leva a um side-effect perigoso é equivalente a resolver um problema indecidível. Por isso pesquisadores acham gadget chains novas anos depois: o espaço de busca é grande demais para fechar.

Jackson, a biblioteca de JSON mais usada em Java, reintroduz o mesmo problema quando configurada para aceitar tipo via input:

```java
// Configuracao venenosa: deixa o JSON dizer qual classe instanciar
ObjectMapper mapper = new ObjectMapper();
mapper.enableDefaultTyping();  // <- aqui mora o perigo

// Agora o atacante manda um JSON que especifica a classe:
// ["com.classe.Perigosa", {"comando": "..."}]
// e o Jackson instancia essa classe.
```

`enableDefaultTyping` literalmente diz "deixe o input escolher o tipo concreto". É JSON, que deveria estar na ponta segura do espectro, sendo arrastado para a ponta perigosa por uma decisão de configuração.

### .NET: o mesmo padrão, outro sotaque

.NET repete a história com `BinaryFormatter` e com `TypeNameHandling` no Newtonsoft.Json.

```csharp
// Veneno classico do .NET
JsonConvert.DeserializeObject<Conta>(inputDoAtacante, new JsonSerializerSettings
{
    TypeNameHandling = TypeNameHandling.All  // <- o input pode dizer o tipo
});

// Com TypeNameHandling.All, o JSON carrega um campo "$type":
// { "$type": "System.Configuration...", ... }
// e o atacante escolhe qual tipo instanciar, abrindo caminho para gadgets.
```

A Microsoft chegou a marcar `BinaryFormatter` como obsoleto e perigoso por design, exatamente por essa razão. Não dá para usar com segurança quando o input é controlável, porque a insegurança não está no uso, está na natureza do formato.

## Parser differentials: a inferência discordante

Tem um caso especial que conecta este artigo com os meus posts anteriores sobre smuggling e cache deception. Lá, o problema não era um sistema inferindo errado, era **dois sistemas inferindo coisas diferentes do mesmo input.**

```
Mesma requisição HTTP
        |
        v
   +---------+              +---------+
   |  Proxy  |              | Backend |
   +---------+              +---------+
        |                        |
  infere: 1 requisição     infere: 2 requisições
        |                        |
        +-----> desacordo = request smuggling
```

No request smuggling, o proxy lê `Content-Length` e o backend lê `Transfer-Encoding` (ou vice-versa), e cada um infere um limite de requisição diferente. No cache deception, o cache infere que `/account/leak.css` é um arquivo estático cacheável, enquanto o backend ignora o sufixo, resolve `/account` e devolve conteúdo dinâmico e autenticado.

É a mesma doença vista de outro ângulo. Em vez de "um runtime inferiu o tipo errado", é "dois sistemas inferiram tipos incompatíveis". A pré-condição quebrada é:

```
{proxy e backend concordam sobre o que este input significa}
```

E ninguém garantiu essa concordância, porque cada um foi escrito por uma equipe diferente, seguindo uma interpretação diferente da mesma especificação ambígua.

## A generalização

Agora junta tudo. O padrão por trás de prototype pollution, type juggling, desserialização insegura, mass assignment e parser differentials é um só:

> Sempre que um sistema toma uma decisão implícita sobre tipo, estrutura ou comportamento a partir de um input que o atacante controla, existe uma pré-condição que é difícil (ou impossível) de garantir. Essa pré-condição é a vulnerabilidade.

Formalizando o espectro de risco:

| Design | Quem decide o tipo | Superfície |
|---|---|---|
| Tipagem forte + explícita (Rust, Go) | O desenvolvedor, em tempo de compilação | Fechada |
| Tipagem forte + desserialização com schema (Protobuf) | O schema, fixo | Fechada |
| Tipagem fraca + coerção (JS, PHP) | O runtime, a cada operação | Aberta |
| Desserialização com tipo no input (pickle, Java, BinaryFormatter) | O atacante | Escancarada |

Quanto mais para baixo na tabela, mais decisões o input controla, e mais a pré-condição "isso é só dado seguro" se torna inverificável.

Isso explica um fato que parece misterioso: por que linguagens como Rust e Go têm menos classes inteiras de vulnerabilidade do que PHP e JavaScript. Não é que os programadores sejam melhores. É que a linguagem não delega ao input a decisão sobre tipo. A superfície simplesmente não existe.

E explica por que essas vulns reaparecem década após década. A indústria trata cada CVE como um incidente isolado: corrige o `__proto__` aqui, marca o `BinaryFormatter` como obsoleto ali. Mas a causa não é cada caso individual. É a decisão de design de deixar o input dirigir a inferência. Enquanto essa decisão existir, vão surgir novos casos.

### Um aparte sobre nomes

Esses bugs têm nomes que se confundem, e até relatórios sérios misturam. Vale separar:

| Nome | O que é | Exemplo neste artigo |
|---|---|---|
| Type juggling | Coerção implícita entre tipos em comparações ou operações | `0 == "0"` em PHP e JS |
| Prototype pollution | Caso especial de JS onde o input alcança o protótipo | `__proto__` em merge |
| Desserialização insegura | Reconstruir objeto cujo tipo ou comportamento vem do input | pickle, `ObjectInputStream` |
| Expression injection | Input avaliado como expressão (OGNL, SpEL, template) | Struts/OGNL, SSTI |
| Type confusion (memória) | Tratar memória de um tipo como se fosse outro | bugs de C++ e browser, fora do escopo aqui |

Os quatro primeiros são a mesma doença lógica deste artigo: o sistema decide tipo ou comportamento a partir de input. O último, type confusion de memória, é um primo de baixo nível, com a mesma intuição mas em outro domínio.

## No mundo real: a tese provada em produção

Tudo isso parece abstrato até você perceber que algumas das maiores quebras de segurança da última década são exatamente este padrão, em escala. Quatro casos, quatro linguagens, a mesma causa.

**Log4Shell (CVE-2021-44228): dado virou comportamento.** O Log4j, a biblioteca de logging mais usada do mundo Java, tinha um recurso de lookup: se uma string de log contivesse `${jndi:ldap://...}`, ele interpretava aquilo como uma instrução para buscar um recurso via JNDI e carregar a classe retornada. O detalhe fatal é que strings de log são quase sempre controladas pelo atacante (um User-Agent, um campo de formulário, um header). O sistema inferiu comportamento (faça um lookup, baixe e execute uma classe) a partir do que deveria ser apenas um dado (uma linha de log). A pré-condição quebrada: `{a string de log é apenas texto para registrar}`. Resultado: RCE não autenticado em boa parte da internet Java, e um dos bugs mais explorados da história. Na essência, é um sistema decidindo, a partir de input, que aquele texto era uma instrução.

**Rails (CVE-2013-0156): o input escolheu o tipo.** O parser de parâmetros do Ruby on Rails aceitava requisições em XML e, ao processá-las, fazia conversão de tipo baseada em tags. Uma tag de YAML ou de Symbol no corpo da requisição fazia o Rails instanciar objetos Ruby arbitrários durante o parsing dos parâmetros, antes de qualquer lógica de aplicação rodar. O atacante não mandava dados, mandava a descrição de quais objetos instanciar. A pré-condição quebrada: `{os parâmetros da requisição são dados, não tipos a instanciar}`. Resultado: RCE em praticamente qualquer aplicação Rails da época, no ponto mais fundamental do framework.

**lodash (CVE-2019-10744): prototype pollution em escala industrial.** A função `defaultsDeep` do lodash, uma biblioteca baixada mais de 80 milhões de vezes por mês, podia ser enganada para modificar `Object.prototype` via um payload `{constructor: {prototype: {...}}}` ou `__proto__`. É exatamente o exemplo que eu mostrei na seção de JavaScript, mas numa lib que estava em quase todo projeto Node do planeta. A chave que o atacante mandava era interpretada pelo runtime como referência ao protótipo, não como dado. Uma linha de input, e propriedades novas aparecem em todos os objetos da aplicação.

**Equifax (CVE-2017-5638): o primo expression injection.** Este é parente próximo, não idêntico, mas entra pela escala. O Apache Struts, ao falhar em parsear um header `Content-Type` inválido, usava o valor do header para montar uma mensagem de erro, e nesse processo avaliava o conteúdo como uma expressão OGNL. O atacante mandava uma expressão no `Content-Type`, e o servidor a executava. Não é inferência de tipo, é inferência de comportamento: o sistema decidiu tratar um header (dado) como uma expressão a avaliar (código). A pré-condição quebrada: `{o valor do Content-Type é um identificador de formato, não uma expressão}`. Resultado: os dados de mais de 140 milhões de pessoas vazados. A causa raiz é da mesma família: o sistema decidiu, a partir de input, que aquilo era executável.

O fio que costura os quatro: nenhum foi um zero-day exótico de corrupção de memória ou de criptografia. Todos foram um componente decidindo, a partir de input controlável, que um dado era na verdade um tipo, uma instrução ou uma expressão. A pré-condição "isso é só dado" era inverificável, e ninguém percebeu que ela era sequer uma pré-condição.

## Como caçar isso na prática

Esqueça por um momento a teoria. Quando eu estou olhando código procurando essa classe de bug, eu faço três perguntas, nessa ordem:

**1. Onde o sistema decide o tipo ou a estrutura a partir do input?**

Procure por: `==` solto em linguagens com coerção, funções de merge/extend/clone, `deserialize`/`unserialize`/`pickle.loads`/`readObject`, qualquer configuração com `TypeNameHandling`, `enableDefaultTyping`, `yaml.load` sem `safe`, binding automático de parâmetros para objetos (mass assignment em frameworks MVC).

**2. O atacante controla o input que alimenta essa decisão?**

Faça o taint tracking: source (parâmetro HTTP, body JSON, cookie, header, mensagem de fila, valor lido do banco que veio de input) até o sink (a operação que infere). Lembre que dado que passou por fila, cache ou banco mantém o taint. Second-order conta.

**3. A inferência acontece antes ou depois da validação?**

Esse é o ponto mais sutil e mais lucrativo. Muitos sistemas validam um tipo e usam outro. Validam a string, mas desserializam o objeto. Checam o IP, mas seguem o redirect. Se a validação olha para uma coisa e a execução olha para outra, o gap entre as duas é a sua entrada (hehe, sorry).

Se as respostas forem "aqui", "sim" e "antes", você provavelmente achou uma vulnerabilidade, mesmo que ela ainda não tenha nome no OWASP.

### Caçando em escala

Manual funciona para um alvo. Para uma base de código inteira, automatize o padrão. Ferramentas de análise estática com suporte a taint (CodeQL, Semgrep) conseguem expressar exatamente as três perguntas como query: encontre fluxos de uma source controlável até um sink de inferência. Uma regra de Semgrep para pegar `yaml.load` sem `SafeLoader`, ou uma query CodeQL para `ObjectInputStream.readObject` alimentado por dado de request, transforma a intuição em cobertura sistemática. O scanner não vai entender a cadeia de impacto (isso ainda é com você), mas vai apontar onde a pré-condição inverificável mora, em milhares de arquivos de uma vez.

## Defesas que funcionam

A defesa contra essa família não é "validar melhor". É **remover a inferência da equação.**

### 1. Fixe o tipo, não deixe o input escolher

Sempre que possível, use formatos e configurações que não deixam o input descrever tipo ou comportamento.

```python
# Ruim: o input escolhe o tipo
yaml.load(entrada, Loader=yaml.Loader)
pickle.loads(entrada)

# Bom: o tipo é fixo, o input é só dado
yaml.safe_load(entrada)
json.loads(entrada)  # JSON puro nao carrega tipo
```

```java
// Ruim
mapper.enableDefaultTyping();

// Bom: desserialize para uma classe concreta e conhecida,
// nunca deixe o input dizer o tipo
Conta conta = mapper.readValue(entrada, Conta.class);
```

```csharp
// Ruim
TypeNameHandling = TypeNameHandling.All

// Bom: o padrao, que nao deixa o input escolher o tipo
TypeNameHandling = TypeNameHandling.None
```

### 2. Use comparação estrita

Em linguagens com coerção, nunca compare valores sensíveis com o operador solto.

```javascript
// Ruim
if (tokenEnviado == tokenReal)

// Bom: compara identidade, sem coercao
if (tokenEnviado === tokenReal)

// Melhor ainda para segredos: comparacao constant-time
const crypto = require("crypto");
if (crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b)))
```

```php
// Ruim
if ($hashA == $hashB)

// Bom: === checa tipo e valor
if ($hashA === $hashB)

// Melhor para hashes e segredos:
if (hash_equals($hashConhecido, $hashTentativa))
```

### 3. Valide contra um schema rígido, antes de usar

A validação tem que olhar para a mesma coisa que a execução vai usar. Schema antes de desserializar, allowlist de campos antes de fazer binding.

```python
# Exemplo com schema explicito (pydantic)
from pydantic import BaseModel

class Conta(BaseModel):
    nome: str
    idade: int
    # Campos nao declarados sao rejeitados.
    # O input nao consegue introduzir estrutura inesperada.

conta = Conta.model_validate_json(entrada)  # valida o que sera usado
```

### 4. Bloqueie chaves perigosas em merges (JS)

Se você precisa fazer merge de objetos com input, rejeite explicitamente as chaves que o runtime interpreta de forma especial.

```javascript
const CHAVES_PROIBIDAS = ["__proto__", "constructor", "prototype"];

function mergeSeguro(destino, fonte) {
  for (let chave in fonte) {
    if (CHAVES_PROIBIDAS.includes(chave)) {
      continue;  // ignora chaves que poluem o prototipo
    }
    // ... resto do merge
  }
  return destino;
}

// Alternativas estruturais:
// - Use Map em vez de objeto literal (Map nao tem prototipo poluivel)
// - Use Object.create(null) para objetos sem prototipo
// - Congele Object.prototype com Object.freeze em runtimes que permitem
```

### 5. Allowlist de tipos quando a desserialização polimórfica é inevitável

Às vezes você precisa de polimorfismo (desserializar para um entre vários tipos). Nesse caso, declare explicitamente quais tipos são permitidos. Nunca aceite uma lista irrestrita.

```java
// Em vez de aceitar qualquer tipo, declare os permitidos
mapper.activateDefaultTyping(
    BasicPolymorphicTypeValidator.builder()
        .allowIfSubType(Pagamento.class)
        .allowIfSubType(Reembolso.class)
        .build()  // so esses dois tipos, nada mais
);
```

### 6. Defesa em profundidade: assuma que vai falhar

Mesmo com tudo acima, trate a desserialização e o binding como operações perigosas. Rode com privilégio mínimo, monitore instanciações inesperadas, e nunca confie que "esse input é interno". Input que veio de uma fila interna ainda é input.

## Conclusão

A coisa mais valiosa que eu tirei de pensar dessa forma não foi uma técnica nova de exploração. Foi parar de ver vulnerabilidades como uma lista de padrões para decorar, e começar a ver a causa que gera todos eles.

O que vale guardar deste post:

* Toda vulnerabilidade é uma tripla de Hoare cuja pré-condição o código não garante. Caçar bug é caçar pré-condição assumida e não verificada.
* Existe uma família inteira de vulns que compartilham a mesma causa: o sistema decide tipo, estrutura ou comportamento a partir de input controlável. Prototype pollution, type juggling, desserialização insegura, mass assignment e parser differentials são a mesma doença vista de ângulos diferentes.
* Quanto mais expressivo o formato de input, menos verificável é a pré-condição "isso é só dado". JSON puro é seguro. Pickle e BinaryFormatter são inseguros por design, não por implementação.
* A defesa não é "validar melhor", é remover a inferência: fixe o tipo, compare com identidade, valide contra schema rígido, bloqueie o vocabulário perigoso.
* Linguagens fortemente tipadas não têm classes inteiras dessas vulns não porque seus programadores são melhores, mas porque não delegam ao input a decisão sobre tipo. A superfície não existe.

Se você quer internalizar isso, pega um código em uma linguagem com coerção ou desserialização e faça o exercício das três perguntas: onde o tipo é inferido, quem controla o input, e a validação olha para a mesma coisa que a execução. Em algumas semanas isso vira automático, e você vai começar a enxergar a causa onde os scanners só veem sintoma.

A indústria trata CVE como incidente. Pesquisador enxerga o padrão gerador. A diferença entre os dois é a pergunta que você faz ao olhar para o código.

### Próximos passos

* **Gadget chains na prática**: montar uma cadeia de desserialização do zero em Java, do `readObject` ao RCE
* **Mass assignment**: como o binding automático de frameworks MVC vira escalada de privilégio
* **Server-side prototype pollution**: de uma chave `__proto__` em um body JSON até RCE via gadget de template engine
* **Verificação formal leve**: usar TLA+ para provar ausência de race condition em vez de mandar mil requisições e torcer

### Referências

* C. A. R. Hoare, "An Axiomatic Basis for Computer Programming", Communications of the ACM, 1969
* Edsger W. Dijkstra, "A Discipline of Programming", 1976 (weakest preconditions)
* Olivier Arteau, "Prototype Pollution and how to prevent it", 2018
* Chris Frohoff e Gabriel Lawrence, "Marshalling Pickles" (ysoserial), AppSecCali 2015
* Alvaro Munoz e Oleksandr Mirosh, "Friday the 13th: JSON Attacks", BlackHat USA 2017
* OWASP, "Deserialization Cheat Sheet"
* Documentação Microsoft, "BinaryFormatter security guide"
* CVE-2021-44228 (Log4Shell), Apache Log4j, JNDI lookup via string de log
* CVE-2013-0156, Ruby on Rails Action Pack, conversão de tipo YAML/Symbol no parsing de parâmetros
* CVE-2019-10744, lodash `defaultsDeep`, prototype pollution
* CVE-2017-5638, Apache Struts, OGNL injection via Content-Type (breach da Equifax)

*Publicado em junho de 2026. Este artigo nasceu de uma conversa sobre por que desserialização "sempre" parece ter um bypass. A resposta curta: porque a pré-condição é inverificável por design. A resposta longa é o post inteiro acima.*

*Curtiu? Compartilha com quem trabalha com segurança. Conteúdo técnico em português sobre ofensiva e fundamentos é raro e precisa circular mais.*

## How to cite

Renan Zapelini. "Inferência de Tipo é Superfície de Ataque: Quando o Runtime Decide pelo Atacante". *R0Z*, 2026. https://renansj.dev/inferencia-de-tipo

```bibtex
@misc{inferencia-de-tipo,
  author = {Renan Zapelini},
  title  = {Inferência de Tipo é Superfície de Ataque: Quando o Runtime Decide pelo Atacante},
  year   = {2026},
  url    = {https://renansj.dev/inferencia-de-tipo}
}
```
