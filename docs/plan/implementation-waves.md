# Implementation waves — Rastreador de entregas (backend + banco)

> Spec de origem: [`docs/specs/client-delivery-tracker.md`](../specs/client-delivery-tracker.md).
> Este arquivo é a fonte da verdade do roadmap de ondas; a tabela do `NOTES.md` espelha a coluna
> Status. Contrato: [`contracts/openapi.v1.yaml`](../../contracts/openapi.v1.yaml) (já escrito;
> as ondas implementam contra ele e não o alteram sem bump de versão).

| Onda | Entrega | Depende de | Paralela com | Status |
|------|---------|------------|--------------|--------|
| 0 | Fundação: scaffold, tooling, CI, Supabase CLI, env, kernel | — | — | ✅ |
| 1 | Plataforma HTTP: `withRoute`, erros, logs, headers, paginação, health, validador de contrato | 0 | 2 | ✅ |
| 2 | Banco: schema, RLS, funções de identidade, auditoria, rate limit, pgTAP | 0 | 1 | ✅ |
| 3 | Identidade: login, logout, sessão, rate limit real | 1, 2 | — | ✅ |
| 4 | Identidade: troca de senha obrigatória + script `ceo:create` | 3 | 5, 6 | ✅ |
| 5 | Identidade: MFA TOTP obrigatório para CEOs | 3 | 4 | ✅ |
| 6 | Rastreamento: clientes (CRUD de CEO) | 5 | 4 | ✅ |
| 6.1 | Identidade: elevação de CEO atestada pelo backend (F-50) e validade da senha temporária (F-41) | 5, 6 | — | ✅ |
| 7 | Identidade: logins de cliente (provisionar, listar, desativar, resetar senha) | 4, 6.1 | 8 | ✅ |
| 8 | Rastreamento: processos e fases (criar, listar, detalhar, renomear e cancelar, template) | 6.1 | 7 | ✅ |
| 9 | Rastreamento: aprovação de fase ("Ok") + linha do tempo | 8 | 10 | ✅ |
| 10 | Painel do cliente: leitura dos próprios processos | 8 | 9 | ✅ |
| 10.1 | Endurecimento do banco: sem DML do `service_role` no rastreamento, usuário totalmente ativo no RLS, auditoria de intenção e reversão no provisionamento (F-81, F-83, F-92b, F-93) | 7, 9, 10 | — | ⬜ |
| 11 | Hardening e go-live | 7, 9, 10, 10.1 | — | ⬜ |

```
0 ─┬─ 1 ─┐
   └─ 2 ─┴─ 3 ─┬─ 4 ─────────────────┐
               └─ 5 ─ 6 ─ 6.1 ─┬─────┴─ 7 ─┐
                               └─ 8 ─┬─ 9 ─┤
                                     └─ 10 ┴─ 11
```

A Onda 6.1 entrou em 2026-11-16, por decisão do usuário sobre os achados F-50 e F-41 (threat model
§8). Ela muda `private.is_ceo()` e `private.current_active_user_id()`, de que todas as ondas
seguintes dependem. Feita depois, obrigaria a refazer os testes das ondas 7 a 10.

**Por que os pares paralelos são seguros** (critérios: sem dependência, arquivos disjuntos, sem
interface pública compartilhada alterada e, na execução, sem usar o Supabase local ao mesmo
tempo):

| Par | (a) dependência | (b) arquivos | (c) interface compartilhada | (d) banco local |
|-----|-----------------|--------------|-----------------------------|-----------------|
| 1 ∥ 2 | 1 usa ports com fakes; 2 é só SQL | `src/shared/{http,observability,kernel}`, `src/app/api/v1/health`, `next.config.ts`, `tests/helpers/contract.ts`, `.claude/skills/new-endpoint/SKILL.md` × `supabase/**`, `src/shared/db/database.types.ts` | nenhuma: 1 não toca `src/shared/db` | só a 2 usa; sem fila |
| 4 ∥ 5 | ambas só dependem de 3 | 4: `identity/**/*password*`, `auth/password`, `scripts/` × 5: `identity/**/*totp*` e `*mfa*`, `auth/mfa/**`, `tests/helpers/mfa.ts`; **nenhuma tem migration** (as funções estão na Onda 2); dependências npm (`tsx`, `otpauth`) já instaladas na Onda 0 | o pipeline (`withRoute`) já trata as pendências desde a Onda 1; cada uma cria o próprio gateway, sem editar o da Onda 3 | as duas usam; gates em fila |
| 4 ∥ 6 | 6 depende de 5, não de 4 | `identity/**` + `scripts/` × `tracking/**` + `admin/clients/{route,[clientId]/route}` + migration de clientes | 6 só **adiciona** `getClientStatus` ao `tracking/index.ts` | as duas usam; gates em fila; só a 6 tem migration |
| 7 ∥ 8 | 7 usa `getClientStatus` (da Onda 6), não processos | `identity/**` + `admin/clients/[clientId]/users/**` (sem migration) × `tracking/**` (processos) + `admin/clients/[clientId]/processes` + `admin/processes/[processId]` + `admin/stage-templates` + migration de processos | 8 não altera `tracking/index.ts` | as duas usam; gates em fila; só a 8 tem migration |
| 9 ∥ 10 | ambas leem o agregado da Onda 8 | 9: `approve-*`, `*events*`, repositório de processo, migration de aprovação, `admin/processes/[processId]/{approvals,events}` × 10: `*my-process*`, `supabase-client-process-queries.ts` (query service separado), `me/processes/**`; 10 não tem migration | nenhuma: cada handler monta as próprias dependências, sem fábrica `deps.tracking()` compartilhada (Onda 1) | as duas usam; gates em fila; o AC-17 roda com o banco exclusivo |

### Sequência de execução

13 ondas em 9 passos. Caminho crítico: 0 → 2 → 3 → 5 → 6 → 6.1 → 8 → 9 → 11.

| Passo | Ondas | Quem executa |
|-------|-------|--------------|
| 1 | 0 | sessão principal |
| 2 | 1 ∥ 2 | 2 na sessão principal; 1 em subagente |
| 3 | 3 | sessão principal |
| 4 | 4 ∥ 5 | 5 na sessão principal; 4 em subagente |
| 5 | 6, em paralelo com o PR do contrato `1.0.0-draft.2` e com o da troca do CodeQL pelo Semgrep | subagentes; a sessão principal coordena a fila de gates de banco |
| 6 | 6.1 (depois do merge da 6 e do contrato, que mexe no mesmo verify de TOTP) | subagente, com revisão reforçada na sessão principal |
| 7 | 7 ∥ 8 | um subagente para cada; a sessão principal coordena a fila de gates de banco |
| 8 | 9 ∥ 10 | 9 na sessão principal; 10 em subagente |
| 9 | 10.1 | subagente, com revisão na sessão principal |
| 10 | 11 | sessão principal; as frentes independentes podem ir para subagentes (ver Notas de execução) |

### Pré-requisitos do paralelismo com subagentes

| Pré-requisito | Por quê | Onde |
|---------------|---------|------|
| Hooks resolvem a raiz pelo git do arquivo editado | Se `CLAUDE_PROJECT_DIR` apontar para o checkout principal, os caminhos de uma worktree não casam com `^src/` e `^supabase/`, e as checagens são puladas sem aviso | Onda 0 |
| `stop-gates.mjs` registrado também em `SubagentStop` | Subagentes terminam com `SubagentStop`, não com `Stop` | Onda 0 |
| Env de teste lido de `supabase status -o env` | Worktrees não têm `.env.local`, e os agentes não podem criá-lo | Onda 0 |
| Dependências previstas até a Onda 10 já instaladas | `pnpm add` pede aprovação (trava o subagente em background) e duas branches mexendo no lockfile conflitam | Onda 0 |
| ESLint permite `route.ts` importar `presentation/*.handler` | Sem isso, toda onda edita o `index.ts` do módulo | Onda 0 |
| Catálogo `ErrorCode` completo | Sem isso, as ondas 4, 5, 7 e 9 editam o mesmo arquivo | Onda 1 |
| Cada handler monta as próprias dependências | Uma fábrica `deps.<módulo>()` seria editada pelas ondas 9 e 10 | Onda 1 |
| Gates de banco em fila | Há um único Supabase local por máquina | Execução |

---

## Onda 0 — Fundação

- **Objetivo**: repositório executável e seguro desde o primeiro commit, com todos os gates rodando
  no CI.
- **Escopo (slices/arquivos)**: `package.json` (pnpm, scripts de `AGENTS.md` §Comandos),
  `pnpm-lock.yaml`, `tsconfig.json` (`strict`, `noUncheckedIndexedAccess`,
  `exactOptionalPropertyTypes`, alias `@/*`), `next.config.ts` (mínimo, `poweredByHeader: false`),
  `eslint.config.mjs` (fronteiras de módulo, `no-console`, `no-restricted-syntax` para template
  literal em `.or/.filter/.textSearch`, `no-explicit-any`), `.prettierrc`, `vitest.config.ts`
  (projetos `unit`, `int` e `api`), `vercel.json` (`regions: ["gru1"]`), `redocly.yaml`,
  `supabase/config.toml` via `supabase init` + hardening (`enable_signup = false`,
  `jwt_expiry = 900`, `minimum_password_length = 12`, `password_requirements`, TOTP com
  `enroll_enabled`/`verify_enabled`, rotação de refresh token), `src/shared/config/env.ts` (Zod,
  falha no boot), `src/shared/kernel/` (`Result`, `DomainError`, `Clock`),
  `.github/workflows/ci.yml` (Actions pinadas por SHA, `permissions: contents: read`; jobs: lint,
  typecheck, unit, contract lint, gitleaks, `pnpm audit --prod`, CodeQL ou Semgrep, pgTAP com
  Supabase CLI), `.github/dependabot.yml` (npm + github-actions). Sem páginas de UI. Os ADRs
  0001–0005 passam a `accepted` depois da revisão do usuário.
- **Escopo para o paralelismo com subagentes** (ver Pré-requisitos):
  1. Todas as dependências previstas até a Onda 10 já no `package.json`:
     `@supabase/supabase-js`, `@supabase/ssr`, `server-only`, `pino`, `@vercel/functions`, `zod`
     e, em dev, `ajv`, `ajv-formats`, `yaml`, `otpauth` e `tsx`.
  2. `tests/setup/local-env.ts` (globalSetup dos projetos `int` e `api` do Vitest): lê URL e
     chaves de `supabase status -o env`, aceita só URL local (`127.0.0.1`/`localhost`), define
     valores fixos de teste para `APP_ORIGIN` e `RATE_LIMIT_KEY_SECRET` e nunca lê `.env*`.
  3. Regra de fronteira do ESLint que permite a `src/app/**/route.ts` importar só
     `@/modules/*/presentation/*.handler`.
  4. `.claude/hooks/lib.mjs` resolvendo a raiz com `git rev-parse --show-toplevel` a partir da
     pasta do arquivo editado (no `Stop`/`SubagentStop`, a partir do `cwd` do evento), com
     `CLAUDE_PROJECT_DIR` só como último recurso; testes em `.claude/hooks/*.test.mjs`
     (`node --test`, sem dependências); `stop-gates.mjs` registrado também em `SubagentStop` no
     `.claude/settings.json`.
- **Depende de / paralela com**: — (sempre a primeira e sequencial).
- **Critérios de aceite**:
  - `pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test && pnpm contract:lint && pnpm build` → exit 0.
  - `pnpm db:start && pnpm db:reset` → exit 0 (banco local sobe sem migrations de domínio).
  - Teste unitário: env sem `SUPABASE_URL` → o boot falha com mensagem sem valores de segredo.
  - Workflow `ci.yml` verde no PR; `grep -E 'uses: [^@]+@[0-9a-f]{40}' .github/workflows/ci.yml` cobre todas as linhas `uses:`.
  - O `package.json` declara todas as dependências do item 1 do escopo de paralelismo.
  - Teste unitário do loader de env de teste: URL não local → falha, sem imprimir valores de chave.
  - Teste do ESLint (API do ESLint no Vitest): `route.ts` importando `presentation/*.handler`
    passa; importando `infrastructure/` ou `@/shared/db` falha.
  - `node --test .claude/hooks/*.test.mjs` → exit 0, incluindo o caso de um arquivo dentro de
    uma worktree com `CLAUDE_PROJECT_DIR` apontando para o checkout principal (a raiz resolvida
    é a da worktree).
  - `.claude/settings.json` registra `stop-gates.mjs` em `Stop` e em `SubagentStop`.
- **Goal command**: `/goal pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test && pnpm contract:lint && pnpm build terminam com exit 0, pnpm db:start && pnpm db:reset termina com exit 0, node --test .claude/hooks/*.test.mjs termina com exit 0, .claude/settings.json registra stop-gates.mjs em Stop e em SubagentStop, o package.json declara @supabase/supabase-js, @supabase/ssr, server-only, pino, @vercel/functions, zod, ajv, ajv-formats, yaml, otpauth e tsx, toda linha "uses:" de .github/workflows/ci.yml está pinada por SHA de 40 caracteres e "gh pr checks" não lista falhas, stop after 10 tries`

## Onda 1 — Plataforma HTTP

- **Objetivo**: pipeline único e seguro por onde passa toda rota, já com todas as políticas de
  acesso e pendências que as ondas seguintes vão usar.
- **Escopo (slices/arquivos)**: `src/shared/http/` (`with-route.ts` com o tipo `RoutePolicy` sem
  default, checagem de Origin, leitor de corpo com limite de 16 KiB e Content-Type, `problem.ts`,
  catálogo de `ErrorCode`, mapeamento de erro → status, `security-headers.ts`, `request-id.ts`,
  `pagination.ts` (codec de cursor + schema Zod), `rate-limit/` (port `RateLimiter` + fake
  in-memory), port `PrincipalResolver` + fake), `src/shared/observability/logger.ts` (pino com
  redação), `src/app/api/v1/health/route.ts`, headers em `next.config.ts`,
  `tests/helpers/contract.ts` (Ajv 2020 carregando `contracts/openapi.v1.yaml`, com
  `expectToMatchContract(operationId, status, body)`).
- **Escopo para o paralelismo com subagentes** (ver Pré-requisitos):
  - Catálogo `ErrorCode` **completo** desde já: todos os códigos de
    `components.schemas.ErrorCode` do contrato, para nenhuma onda seguinte editar o arquivo.
  - Contexto do `withRoute` sem container de DI: entrega `request`, `principal`, `params`,
    `query`, `body` e `requestId`, e cada handler monta as próprias dependências no próprio
    arquivo (sem fábrica `deps.<módulo>()`).
  - `rateLimit` declarado na política de cada rota, igual ao `x-rate-limit` (sem registro
    central de grupos).
  - Correção do exemplo de presentation em `.claude/skills/new-endpoint/SKILL.md`, que hoje usa
    `deps.tracking()`.
- **Depende de / paralela com**: 0 / **2** (justificativa na tabela acima).
- **Critérios de aceite**: AC-22, AC-23, AC-26 (helper + health), AC-27, AC-29. Teste da ordem
  do pipeline: requisição sem sessão e com corpo inválido → 401 (não 400). Teste de tipo:
  `withRoute` sem política não compila (`// @ts-expect-error`). Pendência fora do `allowPending`
  → 403 com o código certo, seguindo a prioridade da spec §3.5. Teste unitário: o catálogo
  `ErrorCode` é igual ao enum `components.schemas.ErrorCode` do contrato (nem a mais, nem a
  menos). `grep -rnE 'deps\.(tracking|identity)\(' src .claude/skills` não encontra nada.
- **Goal command**: `/goal pnpm lint && pnpm typecheck && pnpm test terminam com exit 0, pnpm test -t "AC-(22|23|26|27|29)" executa pelo menos 5 testes, todos verdes, o teste que compara o catálogo ErrorCode com o enum do contrato está verde e grep -rnE 'deps\.(tracking|identity)\(' src .claude/skills não encontra nada, stop after 10 tries`

## Onda 2 — Banco: schema, RLS e funções de identidade

- **Objetivo**: todas as tabelas, policies e funções de identidade da spec §4, com isolamento
  provado por pgTAP antes de existir qualquer endpoint de negócio.
- **Escopo (slices/arquivos)**: `supabase/migrations/<ts>_*.sql`: enums; tabelas `clients`,
  `profiles`, `processes`, `process_stages`, `stage_approvals`, `audit_events`,
  `default_stage_template` (seed placeholder de Q-01); schema `private` com
  `current_client_id()`, `is_ceo()` (`aal2`), `handle_new_auth_user()` (trigger que lê só
  `raw_app_meta_data`) e o bloqueio de mutação de auditoria; funções `current_principal`,
  `mark_password_changed`, `set_account_disabled`, `require_password_change`,
  `record_account_provisioned`, `list_client_users` e `rate_limit_hit` (só `service_role`) com
  `private.rate_limit_counters`; `REVOKE` de `anon`/`authenticated` + default privileges;
  `DROP EXTENSION pg_graphql`. Também `supabase/seed.sql` (só dados locais),
  `supabase/tests/000_helpers.sql` (`tests.create_user`, `tests.authenticate_as`),
  `supabase/tests/*.test.sql` e `src/shared/db/database.types.ts` (gerado).
- **Depende de / paralela com**: 0 / **1**.
- **Critérios de aceite**: AC-08, AC-09 (parte do banco), AC-10, AC-24, AC-25 e a parte de banco
  de AC-31 (trigger recusa papel ausente; `user_metadata` com `role: ceo` é ignorado). O agent
  `rls-auditor` não aponta achado CRÍTICO nem ALTO.
- **Nota de tamanho**: é a maior onda (SQL declarativo + testes). Se passar de ~700 linhas,
  dividir em 2a (identidade, auditoria e rate limit) e 2b (tabelas de rastreamento), ambas
  sequenciais.
- **Goal command**: `/goal pnpm db:reset && pnpm db:test && pnpm db:lint terminam com exit 0, pnpm db:types não deixa diff em src/shared/db/database.types.ts, e grep -lE "AC-(08|09|10|24|25)" supabase/tests/*.sql encontra os 5 IDs, stop after 12 tries`

## Onda 3 — Identidade: autenticação

- **Objetivo**: login, logout e sessão reais, com cookie HttpOnly, revogação efetiva e rate limit
  no Postgres.
- **Escopo (slices/arquivos)**: `src/shared/db/server-client.ts` (`@supabase/ssr`, cookie
  `__Host-rt-session` com flags forçadas, header `x-request-id`, fetch com timeout de 5 s),
  `src/shared/db/admin-client.ts` (`server-only`, único leitor de `SUPABASE_SECRET_KEY`),
  `src/shared/http/rate-limit/postgres-rate-limiter.ts` (HMAC), registro das implementações
  reais no pipeline, `src/modules/identity/` (domain: `Role`, `Principal`, `PendingAction`;
  application: `login`, `logout`, `get-session`; infrastructure: `supabase-auth-gateway`,
  `supabase-principal-resolver`; presentation), rotas `auth/login`, `auth/logout` e
  `auth/session`, `tests/helpers/{fixtures,http}.ts`, `tests/api/auth-session.api.test.ts`.
- **Depende de / paralela com**: 1, 2 / — (integra as duas e define helpers de teste usados por
  todas as ondas seguintes).
- **Critérios de aceite**: AC-01, AC-02, AC-03, AC-04; AC-26 para as três rotas; E-08 (perfil
  desativado com JWT válido → 401); E-11 (normalização de e-mail).
- **Goal command**: `/goal pnpm verify && pnpm test:api terminam com exit 0 e pnpm test:api -t "AC-0[1-4]" executa pelo menos 4 testes, todos verdes, stop after 10 tries`

## Onda 4 — Identidade: troca de senha e script de CEO

- **Objetivo**: troca de senha com re-autenticação e pendência obrigatória, e criação de CEO
  fora da API.
- **Escopo (slices/arquivos)**: `identity/domain/password-policy.ts`, `temporary-password.ts`
  (CSPRNG, 20 caracteres sem ambíguos), `identity/application/change-password.ts`,
  `identity/infrastructure/supabase-password-gateway.ts`, `identity/presentation/change-password.*`,
  rota `auth/password`, `scripts/create-ceo.ts` (+ script `ceo:create`; imprime a senha
  temporária uma única vez no stdout do operador), `tests/api/auth-password.api.test.ts`.
- **Depende de / paralela com**: 3 / **5, 6**.
- **Critérios de aceite**: AC-05, AC-06, AC-31 (parte do script e o teste negativo: nenhuma rota
  cria ou promove CEO); E-12, E-13.
- **Goal command**: `/goal pnpm verify && pnpm test:api terminam com exit 0, pnpm test:api -t "AC-0[56]|AC-31" executa pelo menos 3 testes verdes, e pnpm ceo:create --email ceo1@local.test --name "CEO Teste" contra o Supabase local termina com exit 0 e deixa o perfil com must_change_password = true, stop after 10 tries`

## Onda 5 — Identidade: MFA TOTP para CEOs

- **Objetivo**: CEO só usa o painel com sessão `aal2`.
- **Escopo (slices/arquivos)**: `identity/application/{enroll-totp,verify-totp}.ts`,
  `identity/infrastructure/supabase-mfa-gateway.ts`, `identity/presentation/*totp*`, rotas
  `auth/mfa/totp/enroll` e `auth/mfa/totp/verify`, `tests/helpers/mfa.ts`
  (`loginAsCeoWithMfa`, gerando códigos TOTP a partir do segredo devolvido),
  `tests/api/auth-mfa.api.test.ts`.
- **Depende de / paralela com**: 3 / **4**.
- **Critérios de aceite**: AC-07 (contra uma rota `/admin/*` de teste registrada só no ambiente
  de teste, ou contra `GET /admin/stage-templates/default` se a Onda 8 já existir); E-26, E-27,
  E-28; rate limit de 5 / 5 min na verificação.
- **Goal command**: `/goal pnpm verify && pnpm test:api terminam com exit 0 e pnpm test:api -t "AC-07|E-2[678]" executa pelo menos 4 testes, todos verdes, stop after 10 tries`

## Onda 6 — Rastreamento: clientes

- **Objetivo**: CEOs criam e gerenciam clientes (base das abas do painel).
- **Escopo (slices/arquivos)**: `tracking/domain/client.ts`,
  `tracking/application/{create,list,get,update}-client.ts`,
  `tracking/infrastructure/supabase-client-repository.ts`, `tracking/presentation/*client*`,
  `tracking/index.ts` (exporta `getClientStatus`), rotas `admin/clients` e
  `admin/clients/[clientId]`, migration com `create_client` e `update_client`,
  `supabase/tests/tracking_clients.test.sql`, `tests/helpers/clients.ts`,
  `tests/api/admin-clients.api.test.ts`.
- **Depende de / paralela com**: 5 (os testes precisam de CEO `aal2`) / **4**.
- **Critérios de aceite**: AC-11; AC-21 (parte de cliente em `/admin/clients`); E-29 (cursor
  adulterado).
- **Goal command**: `/goal pnpm verify && pnpm db:test && pnpm test:api terminam com exit 0 e pnpm test:api -t "AC-11|E-29" executa pelo menos 2 testes, todos verdes, stop after 10 tries`
- **Complemento F-51** (decidido pelo usuário em 2026-11-16, opção (a)): nome de cliente único
  entre os não arquivados, com 409 `CONFLICT` em `createClient` e `updateClient` (contrato
  `1.0.0-draft.3`), índice único parcial sobre o nome normalizado e casos E-40 a E-47.

## Onda 6.1 — Identidade: elevação de CEO atestada pelo backend e validade da senha temporária

- **Origem**: decisões do usuário em 2026-11-16, sobre os achados F-50 (b) e F-41 do threat model
  (§8).
- **Objetivo**:
  1. Uma sessão `aal2` só vale como CEO se o verify de TOTP passou pelo backend, que aplica os
     limites de força bruta (5 / 5 min e 20 / dia) e queima o código usado. Uma `aal2` obtida
     direto no Auth, com a senha e a publishable key, não dá poder de CEO nem pelo backend nem
     pelo PostgREST.
  2. A senha temporária, gerada na criação ou num reset, vale 72 h. Vencida, a conta perde o
     principal até receber um reset.
- **Escopo (slices/arquivos)**:
  - ADR 0013, mais a spec: SEC-11, RF-04, SEC-10, §3.5 e casos E-xx novos.
  - Threat model: F-50, F-41 e T-22.
  - Migration com:
    - a tabela de atestados por `session_id`, com FK para `auth.sessions` e `ON DELETE CASCADE`;
    - a função de atestado, executável só pelo `service_role`, chamada pelo cliente admin da
      infraestrutura de identidade (ADR 0006);
    - `private.is_ceo()` passando a exigir o atestado;
    - `private.current_active_user_id()` aplicando a validade, com base no registro da senha
      temporária que a Onda 2 já mantém.
  - O handler do verify grava o atestado.
  - `GET /auth/session` trata `aal2` sem atestado como pendência `VERIFY_MFA`.
  - Ajuste dos helpers pgTAP e de API (`loginAsCeoWithMfa` passa pelo backend e recebe o
    atestado).
- **Brecha a fechar (oráculo)**: quem tem a senha e a publishable key pode chutar o TOTP direto
  no Auth, descobrir um código válido e reapresentá-lo pelo backend ainda dentro da janela, porque
  o Auth não tem proteção contra replay. O atestado é recusado quando o fator tem, na janela do
  TOTP, um challenge verificado que não foi criado pelo backend. A recusa gera auditoria e alerta.
- **Depende de / paralela com**: 5, 6 e o PR do contrato `1.0.0-draft.2`, que mexe no mesmo
  verify / —.
- **Critérios de aceite**: os IDs novos da spec, a partir de E-32 (o E-31 é do contrato `draft.2`):
  - `aal2` obtida direto no Auth não executa função de CEO (pgTAP e API);
  - código descoberto fora do backend e reapresentado por ele é recusado com 422;
  - senha temporária com mais de 72 h fica sem principal, e o login é recusado com o erro
    genérico;
  - um reset renova o prazo.
- **Goal command**: `/goal pnpm verify && pnpm db:test && pnpm test:api terminam com exit 0 e pnpm test:api -t "E-3[2-9]" executa pelo menos 4 testes, todos verdes, stop after 10 tries`

## Onda 7 — Identidade: logins de cliente

- **Objetivo**: CEOs provisionam, listam, desativam e resetam logins de clientes.
- **Escopo (slices/arquivos)**:
  `identity/application/{provision-client-user,list-client-users,update-client-user,reset-client-user-password}.ts`,
  `identity/infrastructure/{supabase-account-admin-gateway,supabase-account-repository}.ts`,
  `identity/presentation/*client-user*`, rotas `admin/clients/[clientId]/users/**`,
  `tests/helpers/client-users.ts`, `tests/api/admin-client-users.api.test.ts`. **Sem migration**
  (funções criadas na Onda 2).
- **Depende de / paralela com**: 4 (gerador de senha temporária), 6 (`getClientStatus`), 6.1
  (validade da senha temporária) / **8**.
- **Critérios de aceite**: AC-12, AC-13, AC-14; E-16, E-17, E-18, E-19, E-23, E-24. O reset de
  senha de cliente renova o prazo de 72 h da senha temporária (F-41, Onda 6.1).
- **Goal command**: `/goal pnpm verify && pnpm test:api terminam com exit 0 e pnpm test:api -t "AC-1[234]|E-(1[6789]|2[34])" executa pelo menos 9 testes, todos verdes, stop after 12 tries`

## Onda 8 — Rastreamento: processos e fases

- **Objetivo**: CEOs criam processos com fases (template ou informadas), consultam, renomeiam e
  cancelam; o agregado `Process` implementa a máquina de estados completa.
- **Escopo (slices/arquivos)**: `tracking/domain/{process,stage,errors}.ts` (invariantes I1–I6,
  incluindo a transição de aprovação, pura e testada),
  `tracking/application/{create-process,list-client-processes,get-process,update-process,get-default-stage-template}.ts`,
  `tracking/infrastructure/supabase-process-repository.ts`, `tracking/presentation/*process*`,
  rotas `admin/clients/[clientId]/processes`, `admin/processes/[processId]` e
  `admin/stage-templates/default`, migration com `create_process` e `update_process`,
  `supabase/tests/tracking_processes.test.sql`, `tests/helpers/processes.ts`,
  `tests/api/admin-processes.api.test.ts`.
- **Depende de / paralela com**: 6.1 (os testes de CEO usam o atestado) / **7**.
- **Critérios de aceite**: AC-15, AC-19; testes unitários cobrindo I1–I6 (cobertura ≥ 80% em
  `tracking/domain` e `tracking/application`); E-16, E-20.
- **Goal command**: `/goal pnpm verify && pnpm db:test && pnpm test:api terminam com exit 0, pnpm test:api -t "AC-1[59]|E-(16|20)" executa pelo menos 4 testes verdes, e a cobertura de src/modules/tracking/{domain,application} é ≥ 80%, stop after 12 tries`

## Onda 9 — Rastreamento: aprovação ("Ok") e linha do tempo

- **Objetivo**: o "Ok" de um CEO avança a fase de forma atômica e auditada, seguro sob
  concorrência.
- **Escopo (slices/arquivos)**:
  `tracking/application/{approve-current-stage,list-process-events}.ts`, método de aprovação em
  `tracking/infrastructure/supabase-process-repository.ts`,
  `tracking/infrastructure/supabase-process-event-queries.ts`,
  `tracking/presentation/{approve*,*events*}`, rotas
  `admin/processes/[processId]/approvals` e `admin/processes/[processId]/events`, migration com
  `approve_current_stage`, `supabase/tests/017_tracking_approvals.test.sql`,
  `tests/api/admin-approvals.api.test.ts`, `tests/helpers/held-transaction.ts` (segunda sessão do
  banco que segura a trava, para provar a concorrência sem `sleep`).
- **Depende de / paralela com**: 8 / **10**.
- **Critérios de aceite**: AC-16, AC-17, AC-18, AC-28; E-01, E-02, E-03, E-04.
- **Goal command**: `/goal pnpm verify && pnpm db:test && pnpm test:api terminam com exit 0 e pnpm test:api -t "AC-(1[678]|28)|E-0[1-4]" executa pelo menos 8 testes, todos verdes, em 3 execuções seguidas (sem flakiness no teste de concorrência), stop after 12 tries`

## Onda 10 — Painel do cliente

- **Objetivo**: o cliente lê os próprios processos, e só eles, sem campos internos.
- **Escopo (slices/arquivos)**: `tracking/application/{list-my-processes,get-my-process}.ts`,
  `tracking/infrastructure/supabase-client-process-queries.ts` (query service, filtro por tenant
  da sessão + RLS), `tracking/presentation/*my-process*`, rotas `me/processes` e
  `me/processes/[processId]`, `tests/api/client-panel.api.test.ts` (fixtures com aprovações
  inseridas por psql no container via `tests/helpers/db.ts`, sem `service_role` e sem depender da
  Onda 9), `supabase/tests/018_client_panel_isolation.test.sql`. **Sem migration.**
- **Depende de / paralela com**: 8 / **9**.
- **Critérios de aceite**: AC-09 (parte da API), AC-20, AC-21; E-05, E-06, E-07. A validação de
  contrato falha se o DTO tiver campo extra (`additionalProperties: false`).
- **Goal command**: `/goal pnpm verify && pnpm test:api terminam com exit 0 e pnpm test:api -t "AC-(09|2[01])|E-0[567]" executa pelo menos 6 testes, todos verdes, stop after 10 tries`

## Onda 10.1 — Endurecimento do banco

- **Origem**: revisões das Ondas 7, 8, 9 e 10 (threat model F-81, F-83, F-92b, F-93), em
  2026-11-16. Não depende da configuração de produção.
- **Escopo**:
  - revogar o DML do `service_role` em `clients`, `processes`, `process_stages` e
    `stage_approvals` (F-81). As fixtures dos testes passam a usar `tests/helpers/db.ts` (psql no
    container), e só as funções `SECURITY DEFINER` escrevem. Inclui `seedProcesses`
    (`tests/helpers/clients.ts`), que hoje grava com a secret key processos ativos sem fase;
  - usuário totalmente ativo no RLS (F-83, T-42): login com a senha temporária pendente
    (`must_change_password = true`) não lê processos, fases nem clientes pelo PostgREST. O pgTAP
    018 já marca as asserções a inverter (login `a4`, "F-83 residual (Onda 10.1 inverte)").
    Avaliar o mesmo predicado em `is_ceo()` (CEO com senha temporária pendente e atestado);
  - higiene do pgTAP: os arquivos 010, 012, 013 e 016 contam linhas da tabela inteira e falham
    quando `pnpm db:test` roda depois de `pnpm test:api` sem `db:reset` (a CI reseta antes, por
    isso não aparece lá). Restringir essas asserções às fixtures de cada arquivo, como já fazem
    017 e 018;
  - `begin_client_login_admin(client_id, user_id, action)`: confere `is_ceo`, dono e papel e grava
    uma auditoria de intenção antes de cada escrita no Auth (F-92b);
  - `record_account_provisioned` devolve a linha do login, sem releitura, mais o evento
    `account.provision_reverted` antes da compensação e o registro tardio no reset de recuperação
    (F-93).
- **Depende de / paralela com**: 7, 9, 10 / —.
- **Critérios de aceite**: pgTAP provando que o `service_role` não escreve nas tabelas de
  rastreamento; pgTAP provando que login com a senha temporária pendente não lê pelo PostgREST
  (F-83); `pnpm test:api` seguido de `pnpm db:test`, sem reset, verde; suítes verdes com as
  fixtures novas; testes de API dos eventos novos.
- **Opcional, se couber**: extrair os helpers repetidos entre as Ondas 8, 9 e 10 (`safeCause`,
  `DATA_EXCEPTION_CLASS`, `invalidPosition`, `parseRows`, a paginação keyset em duas consultas)
  para um módulo compartilhado de `infrastructure/`.

## Onda 11 — Hardening e go-live

- **Objetivo**: produção segura, observável e operável.
- **Escopo (slices/arquivos)**: migration com `pg_cron` (limpeza de `rate_limit_counters`;
  retenção de auditoria conforme Q-07); log drain e alertas (spec §3.10); job de OWASP ZAP
  baseline no CI contra o preview; teste de carga k6 (`tests/load/`); runbooks em
  `docs/how-to/` (criar CEO, resetar MFA de CEO, rotacionar a secret key, anonimizar dados de
  cliente, resposta a incidente); revisão do threat model; configuração de produção (Supabase Pro
  em `sa-east-1`, HIBP ligado, chaves JWT assimétricas, `supabase config push`; Vercel com
  domínio, env de produção e Deployment Protection nos previews); skill `security-scan`; ADRs
  `accepted`.
- **Gates de go-live herdados das ondas 3–5** (threat model §8). Nenhum ambiente hospedado recebe
  contas reais antes de cumpri-los:
  - **F-40:** `security_update_password_require_current_password` ligado no Auth hospedado.
  - Auth hospedado:
    - `disable_signup` ligado;
    - provider de e-mail ativo;
    - `[auth.sessions]` com timebox de 12 h e inatividade de 4 h (plano Pro);
    - `sign_in_sign_ups` acima do teto global de login (300 por 5 min);
    - `token_refresh` dimensionado;
    - assinatura assimétrica, com o segredo HS256 legado revogado.
  - p95 da recusa de conta desativada medido. Se passar de 400 ms, subir `REFUSED_LOGIN_FLOOR_MS`.
  - **F-50 (c), decidido em 2026-11-16:**
    - a publishable key é tratada como segredo: só no servidor, nunca em log, e rotacionada a
      qualquer exposição;
    - proteção de senha vazada (HIBP) ligada;
    - alerta sobre falhas de login e de MFA nos logs do Auth.
  - **F-20, decidido em 2026-11-16:** o cadastro do TOTP fica amarrado à sessão que limpou
    `CHANGE_PASSWORD`.
  - **Scripts operacionais de CEO**, sem os quais um CEO pode ficar trancado:
    - reset de senha (F-41: a senha temporária vence em 72 h);
    - reset de MFA (E-25), nesta ordem: apagar o fator TOTP do usuário pela Admin API do Auth
      (o que leva junto as linhas dele no registro de fatores do backend) e depois a linha dele
      em `private.mfa_first_activations` (F-64, F-75). Sem isso, o CEO que perde o celular não
      cadastra outro fator, por desenho.
  - **Alerta sobre `audit_events`** com `auth.mfa_attestation_refused` e `auth.mfa.reenrollment_refused`
    (F-68, F-75), e não só sobre o log do app.
  - **Conferências no Supabase hospedado** (Onda 6.1 e F-51):
    - triggers em `auth.mfa_factors` e `REFERENCES` para `auth.sessions` e `auth.mfa_factors`
      permitidos;
    - retenção dos challenges de MFA por pelo menos 120 s (oráculo do F-50 b, F-71);
    - locale do banco com `lower()` Unicode (índice `clients_active_name_key`).
  - **Runbook de upgrade do Auth:** o trigger `on_mfa_factor_verified` depende da coluna
    `auth.mfa_factors.status`. Uma migration do GoTrue que mude essa coluna falha com o trigger no
    lugar, então o runbook é: remover o trigger, fazer o upgrade e recriar o trigger.
  - **F-23:** `refresh_token_reuse_interval` mais baixo no projeto hospedado.
- **Também na Onda 11, decididos em 2026-11-16**:
  - **F-03 (c):** cookie de dispositivo, na linha da recomendação da OWASP. O navegador que já
    entrou com sucesso não fica bloqueado pelo ataque à conta. Muda o §3.9 da spec.
  - BAIXOs do security-scan:
    - OTP de e-mail mais curto no `config.toml` (`max_frequency` e `otp_expiry`);
    - headers `Cross-Origin-Opener-Policy` e `Cross-Origin-Resource-Policy`.
- Candidatos de implementação:
  - `pg_cron` que apaga as sessões que `session_is_alive()` já nega;
  - trigger que detecta troca de senha feita direto no Auth.
- **Depende de / paralela com**: 7, 9, 10 / —.
- **Critérios de aceite**: AC-30 completo; k6 dentro do RNF-02; ZAP sem alertas High;
  `GET https://<domínio>/api/v1/health` → 200; `security-scan` sem achados críticos ou altos;
  runbooks revisados.
- **Goal command**: `/goal pnpm verify && pnpm test:api terminam com exit 0, o job de ZAP baseline e o k6 (p95 < 300 ms em leitura, < 500 ms em escrita) passam no CI, curl -fsS https://$APP_DOMAIN/api/v1/health devolve {"status":"ok"} e todos os arquivos de docs/adr/ têm "Status:** accepted", stop after 8 tries`

## Notas de execução

- Ondas sequenciais rodam na sessão principal, uma branch e um PR por onda
  (`feat/wave-<n>-<slug>`, squash merge, Conventional Commits). A skill de projeto `/run-wave`
  automatiza abertura, checagem de dependências e fechamento.
- Uma onda sequencial pode rodar como **goal loop**: invoque o Goal command dela e deixe o
  avaliador manter a sessão presa aos critérios de aceite, em vez de confiar em "parece pronto".
  Feche a onda com a skill `verify` antes de marcá-la como ✅.
- **Quem executa o quê.** As ondas de segurança crítica (2, 3, 5 e 9: RLS, autenticação, MFA e
  concorrência) ficam na sessão principal. As demais (1, 4, 6, 7, 8 e 10) podem rodar como
  subagente Sonnet 5.5 com esforço xhigh (`model: sonnet`, `effort: xhigh`,
  `isolation: worktree`), uma onda por agente, a partir da `main` atualizada. A ordem está em
  "Sequência de execução".
- **Antes do primeiro fan-out** (passo 2), a Onda 0 precisa estar mergeada: é ela que corrige os
  hooks para worktrees e para `SubagentStop`, cria o env de teste e instala as dependências.
- **No subagente:** `pnpm install --frozen-lockfile` na worktree; sem `.env.local` (o setup de
  testes lê o Supabase local); sem `pnpm add` (se faltar dependência, o agente para e avisa, e a
  sessão principal a adiciona num commit próprio); só os arquivos do escopo da onda; `pnpm lint`,
  `pnpm typecheck` e `pnpm test` à vontade; **nenhum** gate de banco.
- **Gates de banco em fila.** Há um único Supabase local por máquina (portas e containers fixos
  pelo `supabase/config.toml`, que é versionado e não muda por worktree). Por isso
  `pnpm db:reset`, `pnpm db:test`, `pnpm test:int` e `pnpm test:api` rodam uma worktree por vez,
  coordenados pela sessão principal, sempre começando por `pnpm db:reset` a partir daquela
  worktree (as migrations diferem entre as ondas). O teste de concorrência da Onda 9 (AC-17) roda
  com o banco exclusivo. O par 1 ∥ 2 não precisa de fila, porque a Onda 1 não usa banco.
- **Merge** um PR por vez. O segundo faz rebase na `main` e roda de novo
  `pnpm db:reset && pnpm db:test` e `pnpm test:api`. Em cada par, no máximo uma onda tem
  migration, então só ela regenera `src/shared/db/database.types.ts`.
- Regras que mantêm o paralelismo seguro: sem container de DI compartilhado (cada handler monta
  as suas dependências); cada onda cria os **próprios** arquivos em `tests/helpers/`; nenhuma
  onda altera `contracts/openapi.v1.yaml` sem bump de versão aprovado.
- **Paralelismo dentro da onda** (opcional): na Onda 2, um subagente pode escrever os testes
  pgTAP a partir dos AC enquanto a sessão principal escreve as migrations, combinando antes o
  `supabase/tests/000_helpers.sql`. Na Onda 11, runbooks, k6, job do ZAP e migration de
  `pg_cron` são frentes independentes; a configuração de produção fica com o usuário.
- **Agentes fora do Claude Code** (Codex, Cursor, modelos GPT) não executam os hooks de
  `.claude/hooks/`, os agents de projeto nem as skills. Eles não fazem as ondas 2, 3, 5 e 9; em
  qualquer outra onda, `rls-auditor` (se tocar `supabase/`), `contract-guardian` e
  `code-reviewer` rodam no Claude Code antes do PR.
- Antes de abrir o PR de uma onda que toca `supabase/`, rode o agent `rls-auditor`; em toda onda
  com rota nova, rode o agent `contract-guardian`. Nas ondas feitas por subagente, a sessão
  principal roda esses agents quando ele devolver a worktree.
- Quando uma onda terminar, marque-a como ✅ aqui **e** no `NOTES.md`, e então atualize o status
  atual do `NOTES.md` antes de encerrar a sessão.
