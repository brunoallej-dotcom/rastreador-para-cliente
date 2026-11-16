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

Arquivo `approve-current-stage.handler.ts`. O handler **monta as próprias dependências, dentro do
próprio arquivo**: não existe container de DI nem fábrica compartilhada por módulo, para duas ondas
paralelas nunca editarem o mesmo arquivo.

```ts
import { z } from 'zod';
import { systemClock } from '@/shared/kernel';
import { json, withRoute } from '@/shared/http';
import { approveCurrentStage } from '../application/approve-current-stage';
import { createSupabaseProcessRepository } from '../infrastructure/supabase-process-repository';
import { toProcessDetailDto } from './process-dto';

export const approveCurrentStageHandler = withRoute(
  {
    access: 'authenticated',
    roles: ['ceo'], // = x-auth-policy.roles (lista não vazia)
    allowPending: [], // = x-auth-policy.allowPending (obrigatório; [] = nenhuma)
    // = x-rate-limit; group = nome do contador (ver abaixo); sempre array, nunca vazio
    rateLimit: [{ scope: 'user', group: 'writes', limit: 60, windowSeconds: 60 }],
    params: z.object({ processId: z.uuid() }).strict(),
    body: z.object({ expectedStageId: z.uuid() }).strict(),
  },
  async ({ principal, params, body, requestId, cookies }) => {
    // Dependências montadas aqui, por requisição. A infraestrutura do módulo recebe o que precisa
    // do contexto (cookies da sessão e requestId, que vai no header x-request-id para o banco).
    const processes = createSupabaseProcessRepository({ cookies, requestId });

    const result = await approveCurrentStage({ processes, clock: systemClock }, principal, {
      processId: params.processId,
      expectedStageId: body.expectedStageId,
    });
    // Erro de domínio: devolva (ou lance) o DomainError; o pipeline responde problem+json.
    return result.ok ? json(200, toProcessDetailDto(result.value)) : result.error;
  },
);
```

API do `withRoute(policy, handler)` (`@/shared/http`):

- **Política sem default.** `{ access: 'public' }` precisa ser escrito. `{ access: 'authenticated' }`
  exige `roles` (não vazio) e `allowPending`. `withRoute` sem política, ou com política incompleta,
  não compila. O tipo de `principal` no handler é `Principal` (nunca `null`) em rota autenticada e
  `null` em rota pública.
- **`rateLimit` é obrigatório e não vazio em toda rota** (o contrato declara `x-rate-limit` em todas
  as operações; sem ele a rota seria ilimitada, e `withRoute` não compila nem carrega). É um array de
  `{ scope: 'ip' | 'account' | 'user', group, limit, windowSeconds }`, com `limit` e `windowSeconds`
  iguais ao `x-rate-limit` do contrato. Rota pública exige ao menos uma regra `ip`. `ip` roda antes
  da autenticação, `user` logo depois dela. `account` só existe em rota pública, exige `body` e
  `accountKey: (body) => string` (login: o e-mail normalizado) e roda depois da validação.
- **`group`** é o nome do contador (spec §3.9), declarado por quem escreve a rota; o contador é
  `scope:group` (ex.: `user:writes`) por sujeito. Duas rotas dividem o mesmo contador só se tiverem
  o mesmo `scope` e o mesmo `group`, e todas as regras de um grupo têm os mesmos `limit` e
  `windowSeconds`. Os grupos (`RATE_LIMIT_GROUPS`):

  | `group` | Rotas |
  |---------|-------|
  | `login` | `POST /auth/login` (regras `ip` 20/15 min e `account` 10/15 min) |
  | `totp-enroll` | `POST /auth/mfa/totp/enroll` (user 10/15 min, vem do contrato) |
  | `totp-verify` | `POST /auth/mfa/totp/verify` (user 5/5 min) |
  | `password-change` | `POST /auth/password` (user 5/15 min) |
  | `client-user-admin` | provisionar e resetar senha de login de cliente, juntos (user 20/h) |
  | `writes` | as demais escritas autenticadas (user 60/min), `logout` inclusive |
  | `reads` | as leituras autenticadas (user 300/min), `GET /auth/session` inclusive |
  | `health` | `GET /health` (ip 60/min) |

- **Corpo e query.** Rota sem schema de `body` **ignora o corpo**: não o lê nem checa Content-Type
  ou tamanho (o contrato não documenta 400, 413 nem 415 para ela); o Origin de métodos não seguros
  vale sempre. Rota com schema de `body` leva todas as checagens (415, 413, 400). Rota sem schema de
  `query` ignora parâmetros desconhecidos; com schema, `.strict()` rejeita.
- **`params`, `query`, `body`**: objetos Zod `.strict()` opcionais (um schema que não seja `.strict()`
  faz o módulo falhar ao carregar). Para listas paginadas, use `pageQuerySchema`/`pageQueryShape` e
  `encodeCursor(kind, payload)`/`decodeCursor(cursor, kind, schema)` de `@/shared/http` (o `kind`
  amarra o cursor ao endpoint: um cursor de outro `kind` vira 400); para texto digitado pelo
  usuário, `visibleText({ min, max })`.
- **Contexto do handler**: `{ request, requestId, principal, params, query, body, cookies, logger }`.
  `cookies` grava na resposta final, inclusive nas respostas de erro, e é o **único** caminho para
  cookies: um `Set-Cookie` escrito direto no `Response` do handler é erro de programação (500).
  `logger` já carrega o `requestId`; o que ele escreve passa pelo redator de logs.
- **Retorno**: um `Response` (`json(status, dto)`, `noContent()`) ou um `DomainError` (devolvido ou
  lançado). Qualquer outra exceção vira 500 `INTERNAL_ERROR` sem detalhes.
- Os limites do Zod são **iguais** aos do contrato (`maxLength`, `minItems`, enums).
- O mapper de DTO lista os campos explicitamente; nada de spread de linha do banco.
- O limiter e o resolver de principal reais são ligados em um único arquivo,
  `src/shared/http/pipeline-deps.ts`; um handler nunca os cria. (Testes do próprio pipeline usam
  `createWithRoute` com fakes, ver `src/shared/http/testing.ts`.)

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
