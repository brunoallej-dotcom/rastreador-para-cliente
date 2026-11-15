# Implementation waves — Rastreador de entregas (backend + banco)

> Spec de origem: [`docs/specs/client-delivery-tracker.md`](../specs/client-delivery-tracker.md).
> Este arquivo é a fonte da verdade do roadmap de ondas; a tabela do `NOTES.md` espelha a coluna
> Status. Contrato: [`contracts/openapi.v1.yaml`](../../contracts/openapi.v1.yaml) (já escrito;
> as ondas implementam contra ele e não o alteram sem bump de versão).

| Onda | Entrega | Depende de | Paralela com | Status |
|------|---------|------------|--------------|--------|
| 0 | Fundação: scaffold, tooling, CI, Supabase CLI, env, kernel | — | — | ⬜ |
| 1 | Plataforma HTTP: `withRoute`, erros, logs, headers, paginação, health, validador de contrato | 0 | 2 | ⬜ |
| 2 | Banco: schema, RLS, funções de identidade, auditoria, rate limit, pgTAP | 0 | 1 | ⬜ |
| 3 | Identidade: login, logout, sessão, rate limit real | 1, 2 | — | ⬜ |
| 4 | Identidade: troca de senha obrigatória + script `ceo:create` | 3 | 5, 6 | ⬜ |
| 5 | Identidade: MFA TOTP obrigatório para CEOs | 3 | 4 | ⬜ |
| 6 | Rastreamento: clientes (CRUD de CEO) | 5 | 4 | ⬜ |
| 7 | Identidade: logins de cliente (provisionar, listar, desativar, resetar senha) | 4, 6 | 8 | ⬜ |
| 8 | Rastreamento: processos e fases (criar, listar, detalhar, renomear e cancelar, template) | 6 | 7 | ⬜ |
| 9 | Rastreamento: aprovação de fase ("Ok") + linha do tempo | 8 | 10 | ⬜ |
| 10 | Painel do cliente: leitura dos próprios processos | 8 | 9 | ⬜ |
| 11 | Hardening e go-live | 7, 9, 10 | — | ⬜ |

```
0 ─┬─ 1 ─┐
   └─ 2 ─┴─ 3 ─┬─ 4 ───────────┐
               └─ 5 ─ 6 ─┬─────┴─ 7 ─┐
                         └─ 8 ─┬─ 9 ─┤
                               └─ 10 ┴─ 11
```

**Por que os pares paralelos são seguros** (critérios: sem dependência, arquivos disjuntos, sem
interface pública compartilhada alterada):

| Par | (a) dependência | (b) arquivos | (c) interface compartilhada |
|-----|-----------------|--------------|-----------------------------|
| 1 ∥ 2 | 1 usa ports com fakes; 2 é só SQL | `src/shared/{http,observability,kernel}`, `src/app/api/v1/health`, `next.config.ts`, `tests/helpers/contract.ts` × `supabase/**`, `src/shared/db/database.types.ts` | nenhuma: 1 não toca `src/shared/db` |
| 4 ∥ 5 | ambas só dependem de 3 | 4: `identity/**/*password*`, `auth/password`, `scripts/` × 5: `identity/**/*totp*` e `*mfa*`, `auth/mfa/**`, `tests/helpers/mfa.ts`; **nenhuma tem migration** (as funções estão na Onda 2) | o pipeline (`withRoute`) já trata as pendências desde a Onda 1; cada uma cria o próprio gateway, sem editar o da Onda 3 |
| 4 ∥ 6 | 6 depende de 5, não de 4 | `identity/**` + `scripts/` × `tracking/**` + `admin/clients/{route,[clientId]/route}` + migration de clientes | 6 só **adiciona** `getClientStatus` ao `tracking/index.ts` |
| 7 ∥ 8 | 7 usa `getClientStatus` (da Onda 6), não processos | `identity/**` + `admin/clients/[clientId]/users/**` (sem migration) × `tracking/**` (processos) + `admin/clients/[clientId]/processes` + `admin/processes/[processId]` + `admin/stage-templates` + migration de processos | 8 não altera `tracking/index.ts` |
| 9 ∥ 10 | ambas leem o agregado da Onda 8 | 9: `approve-*`, `*events*`, repositório de processo, migration de aprovação, `admin/processes/[processId]/{approvals,events}` × 10: `*my-process*`, `supabase-client-process-queries.ts` (query service separado), `me/processes/**`; 10 não tem migration | nenhuma |

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
- **Depende de / paralela com**: — (sempre a primeira e sequencial).
- **Critérios de aceite**:
  - `pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test && pnpm contract:lint && pnpm build` → exit 0.
  - `pnpm db:start && pnpm db:reset` → exit 0 (banco local sobe sem migrations de domínio).
  - Teste unitário: env sem `SUPABASE_URL` → o boot falha com mensagem sem valores de segredo.
  - Workflow `ci.yml` verde no PR; `grep -E 'uses: [^@]+@[0-9a-f]{40}' .github/workflows/ci.yml` cobre todas as linhas `uses:`.
- **Goal command**: `/goal pnpm install --frozen-lockfile && pnpm lint && pnpm typecheck && pnpm test && pnpm contract:lint && pnpm build terminam com exit 0, pnpm db:start && pnpm db:reset termina com exit 0, toda linha "uses:" de .github/workflows/ci.yml está pinada por SHA de 40 caracteres e "gh pr checks" não lista falhas, stop after 8 tries`

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
- **Depende de / paralela com**: 0 / **2** (justificativa na tabela acima).
- **Critérios de aceite**: AC-22, AC-23, AC-26 (helper + health), AC-27, AC-29. Teste da ordem
  do pipeline: requisição sem sessão e com corpo inválido → 401 (não 400). Teste de tipo:
  `withRoute` sem política não compila (`// @ts-expect-error`). Pendência fora do `allowPending`
  → 403 com o código certo, seguindo a prioridade da spec §3.5.
- **Goal command**: `/goal pnpm lint && pnpm typecheck && pnpm test terminam com exit 0 e pnpm test -t "AC-(22|23|26|27|29)" executa pelo menos 5 testes, todos verdes, stop after 10 tries`

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

## Onda 7 — Identidade: logins de cliente

- **Objetivo**: CEOs provisionam, listam, desativam e resetam logins de clientes.
- **Escopo (slices/arquivos)**:
  `identity/application/{provision-client-user,list-client-users,update-client-user,reset-client-user-password}.ts`,
  `identity/infrastructure/{supabase-account-admin-gateway,supabase-account-repository}.ts`,
  `identity/presentation/*client-user*`, rotas `admin/clients/[clientId]/users/**`,
  `tests/helpers/client-users.ts`, `tests/api/admin-client-users.api.test.ts`. **Sem migration**
  (funções criadas na Onda 2).
- **Depende de / paralela com**: 4 (gerador de senha temporária), 6 (`getClientStatus`) / **8**.
- **Critérios de aceite**: AC-12, AC-13, AC-14; E-16, E-17, E-18, E-19, E-23, E-24.
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
- **Depende de / paralela com**: 6 / **7**.
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
  `approve_current_stage`, `supabase/tests/tracking_approvals.test.sql`,
  `tests/api/admin-approvals.api.test.ts`.
- **Depende de / paralela com**: 8 / **10**.
- **Critérios de aceite**: AC-16, AC-17, AC-18, AC-28; E-01, E-02, E-03, E-04.
- **Goal command**: `/goal pnpm verify && pnpm db:test && pnpm test:api terminam com exit 0 e pnpm test:api -t "AC-(1[678]|28)|E-0[1-4]" executa pelo menos 8 testes, todos verdes, em 3 execuções seguidas (sem flakiness no teste de concorrência), stop after 12 tries`

## Onda 10 — Painel do cliente

- **Objetivo**: o cliente lê os próprios processos, e só eles, sem campos internos.
- **Escopo (slices/arquivos)**: `tracking/application/{list-my-processes,get-my-process}.ts`,
  `tracking/infrastructure/supabase-client-process-queries.ts` (query service, filtro por tenant
  da sessão + RLS), `tracking/presentation/*my-process*`, rotas `me/processes` e
  `me/processes/[processId]`, `tests/api/client-panel.api.test.ts` (fixtures com aprovações
  inseridas via `service_role`, sem depender da Onda 9). **Sem migration.**
- **Depende de / paralela com**: 8 / **9**.
- **Critérios de aceite**: AC-09 (parte da API), AC-20, AC-21; E-05, E-06, E-07. A validação de
  contrato falha se o DTO tiver campo extra (`additionalProperties: false`).
- **Goal command**: `/goal pnpm verify && pnpm test:api terminam com exit 0 e pnpm test:api -t "AC-(09|2[01])|E-0[567]" executa pelo menos 6 testes, todos verdes, stop after 10 tries`

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
- Grupos paralelos (1∥2, 4∥5, 4∥6, 7∥8, 9∥10) podem rodar como subagents em worktrees isoladas,
  uma onda por agent, com os resultados mergeados um PR por vez. Migrations paralelas precisam de
  timestamps distintos; quem mergear depois roda `pnpm db:reset && pnpm db:test` de novo.
- Regras que mantêm o paralelismo seguro: sem container de DI compartilhado (cada handler monta
  as suas dependências); cada onda cria os **próprios** arquivos em `tests/helpers/`; nenhuma
  onda altera `contracts/openapi.v1.yaml` sem bump de versão aprovado.
- Antes de abrir o PR de uma onda que toca `supabase/`, rode o agent `rls-auditor`; em toda onda
  com rota nova, rode o agent `contract-guardian`.
- Quando uma onda terminar, marque-a como ✅ aqui **e** no `NOTES.md`, e então atualize o status
  atual do `NOTES.md` antes de encerrar a sessão.
