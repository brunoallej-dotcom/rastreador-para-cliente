---
name: new-endpoint
description: Implementa um endpoint da API contract-first e ponta a ponta (domain → application → infrastructure → presentation → route.ts → testes), com withRoute, política igual ao x-auth-policy, Zod .strict(), mapeamento de erros e testes de API validados contra o OpenAPI. Use quando for criar ou alterar um Route Handler em src/app/api/v1 ou um caso de uso exposto por HTTP.
argument-hint: "<operationId> (ex.: approveCurrentStage)"
---

Endpoint: $ARGUMENTS

## 0. Contrato primeiro

1. Localize a operação em `contracts/openapi.v1.yaml` pelo `operationId`. Anote: método e path,
   `x-auth-policy`, `x-rate-limit`, parâmetros, `requestBody`, respostas e `code`s.
2. Se a operação não existir ou precisar mudar: **pare**. Atualize a spec e o contrato primeiro
   (mudança aditiva: bump minor de `info.version`; incompatível: `/api/v2`), confirme com o
   usuário e só então continue.
3. Identifique o módulo dono (`identity` ou `tracking`) e a onda no plano.

## 1. Domain (`src/modules/<mod>/domain/`)

- Entidades e value objects com comportamento (sem modelo anêmico), erros de domínio tipados e
  ports (interfaces) de que o caso de uso precisa. Sem I/O e sem imports de fora (exceto
  `@/shared/kernel`).
- Teste unitário de toda regra e invariante.

## 2. Application (`src/modules/<mod>/application/<verbo-substantivo>.ts`)

```ts
export type ApproveCurrentStageInput = { processId: ProcessId; expectedStageId: StageId };

export async function approveCurrentStage(
  deps: { processes: ProcessRepository; clock: Clock },
  principal: Principal,
  input: ApproveCurrentStageInput,
): Promise<Result<ProcessView, ApproveStageError>> {
  // 1. guarda de autorização de domínio (papel/posse), mesmo com o pipeline já tendo checado
  // 2. carrega o agregado (tenant derivado do principal, nunca do input)
  // 3. aplica a regra no agregado (falha rápido)
  // 4. persiste pela função do banco (autoridade final; atômica)
  // 5. devolve a view
}
```

- Testes com fakes in-memory dos ports, nomeados com os IDs (`it('AC-16: …')`).

## 3. Infrastructure (`src/modules/<mod>/infrastructure/`)

- Use o client **com escopo de usuário** de `@/shared/db` (RLS ativa). O admin client só é
  permitido no gateway de contas de `identity` e no rate limiter.
- Escrita = `supabase.rpc('<funcao>', { … })`. Leitura = `from(...).select('<colunas explícitas>')`
  com filtro de tenant **e** RLS.
- Proibido: SQL montada, template string em `.or()`/`.filter()`/`.textSearch()` e `auth.getSession()`.
- Valide a resposta do Supabase com Zod. Mapeie os erros pela tabela da spec §3.7; o que não for
  mapeado vira `InternalError`.

## 4. Presentation (`src/modules/<mod>/presentation/`)

```ts
export const approveCurrentStageHandler = withRoute(
  {
    access: 'authenticated',
    roles: ['ceo'],
    allowPending: [],
    rateLimit: { scope: 'user', limit: 60, windowSeconds: 60 }, // = x-rate-limit
    params: z.object({ processId: z.string().uuid() }).strict(),
    body: z.object({ expectedStageId: z.string().uuid() }).strict(),
  },
  async ({ principal, params, body, deps }) => {
    const result = await approveCurrentStage(deps.tracking(), principal, {
      processId: params.processId,
      expectedStageId: body.expectedStageId,
    });
    return result.ok ? json(200, toProcessDetailDto(result.value)) : result.error; // erro → problem+json
  },
);
```

- Os limites do Zod são **iguais** aos do contrato (`maxLength`, `minItems`, enums).
- O mapper de DTO lista os campos explicitamente; nada de spread de linha do banco.
- O handler monta as próprias dependências (sem container compartilhado).

## 5. Route (`src/app/api/v1/<path>/route.ts`)

```ts
export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';
export { approveCurrentStageHandler as POST } from '@/modules/tracking/presentation/approve-current-stage.handler';
```

Nada além disso: o hook de pós-edição recusa lógica, `@supabase/*` e `@/shared/db` em `route.ts`.

## 6. Testes de API (`tests/api/<area>.api.test.ts`)

Cada operação cobre, no mínimo:

- caminho feliz com `expectToMatchContract('<operationId>', status, body)`;
- 401 sem sessão; 403 com papel errado; 403 com pendência (quando a política não a permite);
- 404 cross-tenant com corpo idêntico ao de um UUID inexistente (recurso com dono): use a skill
  `tenant-isolation-tests`;
- 400 com campo desconhecido e com campo fora do limite;
- os 409/422 de domínio da operação e os edge cases E-xx da spec.

## 7. Fechar

1. `pnpm lint && pnpm typecheck && pnpm test && pnpm test:api && pnpm contract:lint`.
2. Rode o agent `contract-guardian` e corrija as divergências.
3. Se o comportamento ganhou um detalhe que a spec não tinha, atualize a spec no mesmo PR.
