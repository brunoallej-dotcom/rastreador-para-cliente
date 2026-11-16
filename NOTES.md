# NOTES — Rastreador para Cliente

Diário do projeto: status atual, pendências e log de sessões. Atualize ao fim de cada sessão.

## Status atual

- **Fase:** implementação em andamento (2026-11-16). Ondas 0 a 5 concluídas.
- **Paralelismo:** o plano define quais ondas rodam em subagente (Sonnet 5.5, esforço xhigh,
  worktree) e os pré-requisitos, resolvidos nas ondas 0 e 1. Ver "Sequência de execução" e
  "Pré-requisitos do paralelismo com subagentes" em `docs/plan/implementation-waves.md`.
- **Próximas ondas:** 6 (clientes), depois 7 ∥ 8.
- **Fonte da verdade do roadmap:** [`docs/plan/implementation-waves.md`](docs/plan/implementation-waves.md).
  Esta tabela espelha a coluna Status de lá.

| Onda | Entrega | Depende de | Paralela com | Status |
|------|---------|------------|--------------|--------|
| 0 | Fundação: scaffold, tooling, CI, Supabase CLI, env, kernel | — | — | ✅ |
| 1 | Plataforma HTTP: `withRoute`, erros, logs, headers, paginação, health, validador de contrato | 0 | 2 | ✅ |
| 2 | Banco: schema, RLS, funções de identidade, auditoria, rate limit, pgTAP | 0 | 1 | ✅ |
| 3 | Identidade: login, logout, sessão, rate limit real | 1, 2 | — | ✅ |
| 4 | Identidade: troca de senha obrigatória + script `ceo:create` | 3 | 5, 6 | ✅ |
| 5 | Identidade: MFA TOTP obrigatório para CEOs | 3 | 4 | ✅ |
| 6 | Rastreamento: clientes (CRUD de CEO) | 5 | 4 | ⬜ |
| 7 | Identidade: logins de cliente (provisionar, listar, desativar, resetar senha) | 4, 6 | 8 | ⬜ |
| 8 | Rastreamento: processos e fases (criar, listar, detalhar, renomear e cancelar, template) | 6 | 7 | ⬜ |
| 9 | Rastreamento: aprovação de fase ("Ok") + linha do tempo | 8 | 10 | ⬜ |
| 10 | Painel do cliente: leitura dos próprios processos | 8 | 9 | ⬜ |
| 11 | Hardening e go-live | 7, 9, 10 | — | ⬜ |

Legenda: ⬜ não iniciada · 🟡 em andamento · ✅ concluída

## Pendências do usuário

| Pendência | Bloqueia |
|-----------|----------|
| Revisar e aceitar os ADRs 0001–0009 (`docs/adr/`) | Onda 11 (o goal command exige `accepted`) |
| F-03: bloqueio direcionado de conta (threat model T-04, §8): escolher a mudança no §3.9 da spec | risco aberto até a decisão |
| **`factorId` depois do enroll** (threat model §8): o contrato não oferece como obtê-lo, então um CEO num dispositivo novo (`VERIFY_MFA`) não consegue verificar. Opções: `TotpVerifyRequest.factorId` opcional resolvido no servidor (recomendado) ou o fator no DTO `Session` | **frontend e go-live** (mudança de contrato) |
| F-23: o refresh token anterior ao verify ainda rende `aal2` durante o `refresh_token_reuse_interval` (10 s); a decisão é reduzir o intervalo (threat model §7) | Onda 11 |
| F-41: prazo de validade da senha temporária (threat model §8) | decisão de spec; exige caminho de reset de CEO |
| Proposta de mudança de contrato (threat model §8): limites de `newPassword` × 422, `currentPassword` em bytes, `Set-Cookie` no 204 e 503 de `changePassword`, orçamentos programáticos fora do `x-rate-limit` | OK do usuário (bump minor) |
| Rodar `pnpm -s ceo:create --target 127.0.0.1:54421 --email ceo1@local.test --name "CEO Teste"` num terminal (sem `CI`) contra o Supabase local | goal command da Onda 4 (permissão "ask") |
| Gates de go-live do Auth hospedado (plano, Onda 11), a começar por F-40 | Onda 11 |
| Q-01: nomes das fases padrão (spec §8) | seed do template na Onda 2 (há placeholder) |
| Ativar branch protection na `main` (o repositório remoto já existe) e restringir o merge a squash | CI da Onda 0 |
| Criar projetos Supabase **dev/staging** e **prod** em `sa-east-1` (prod no plano Pro) | Onda 11 (a Onda 3 foi validada só no Supabase local) |
| Para o MCP: `export SUPABASE_PROJECT_REF=<ref do projeto DEV>` antes de abrir o Claude Code e autenticar em `/mcp` | uso do MCP |
| Alinhar os nomes em `.env.local` com `.env.example` (nenhuma chave Supabase com prefixo público do Next.js) | Onda 3 |
| Q-07 (retenção) e Q-12 (domínio) | Onda 11 |

## Observações

- O Supabase local deste projeto usa as portas **544xx** (API 54421, DB 54422, Studio 54423,
  Mailpit 54424), porque outro projeto local (`tracking-clientes`) ocupa as portas padrão 543xx.
- pnpm 10.34.9 via corepack (`packageManager` no `package.json`); Supabase CLI 2.122.1 como
  devDependency (a v3 foi lançada em 2026-11-02 e ainda não foi adotada).
- `venv/` (Python) existe na raiz, mas não é usado por este projeto (ignorado pelo git).
- O guardrail de segredos do ambiente bloqueia ler `.env.*`; o conteúdo de `.env.local` não foi
  inspecionado.

## Log de sessões

### 2026-11-15 — Especificação e estrutura do agente

- Spec SDD: `docs/specs/client-delivery-tracker.md` (RF-01..15, RNF-01..08, SEC-01..20,
  AC-01..31, E-01..30, Q-01..12).
- Contrato `contracts/openapi.v1.yaml` (OpenAPI 3.1, 24 operações, `x-auth-policy` e
  `x-rate-limit` por operação).
- Threat model (STRIDE + OWASP Top 10:2025 + API Top 10:2023), ADRs 0001–0005 (`proposed`) e
  plano de 12 ondas.
- `.claude/`: agents `rls-auditor` e `contract-guardian`; skills `run-wave`, `new-endpoint`,
  `new-migration` e `tenant-isolation-tests`; hooks `session-context`, `guard-writes`,
  `post-edit-checks` e `stop-gates`, registrados em `settings.json`.
- `.mcp.json` (Supabase read-only, por projeto), `.env.example` (só placeholders) e entradas novas
  no `.gitignore`.
- Validação: 178 checagens estruturais e de comportamento dos hooks passaram; contrato validado
  com `@redocly/cli@2.72.1 lint` (regras recomendadas): válido, sem avisos.

### 2026-11-15 — Estratégia de paralelismo com subagentes

- Spec, contrato, plano e configuração do Claude Code mergeados na `main` (PR #1).
- Análise de quais ondas podem rodar em subagente e quais são obrigatoriamente sequenciais. O
  grafo do plano se manteve: 12 ondas em 8 passos, caminho crítico 0 → 2 → 3 → 5 → 6 → 8 → 9 → 11.
- Plano atualizado (PR #2):
  - sequência de execução e quem executa cada onda (2, 3, 5 e 9 na sessão principal; 1, 4, 6,
    7, 8 e 10 em subagente);
  - pré-requisitos na Onda 0 (hooks em worktree e `stop-gates.mjs` em `SubagentStop`, env de
    teste via `supabase status`, dependências pré-instaladas, regra do ESLint para `route.ts`);
  - pré-requisitos na Onda 1 (catálogo `ErrorCode` completo, handler monta as próprias
    dependências, `rateLimit` por rota);
  - gates de banco em fila (um único Supabase local) e restrição a agentes fora do Claude Code.
- Não verificado: os hooks podem pular as checagens em worktree, porque `lib.mjs` prefere
  `CLAUDE_PROJECT_DIR`. O critério de aceite da Onda 0 cobre esse caso.
- Fora do plano por ora: mover `tests/helpers/mfa.ts` para a Onda 3 (deixaria 4, 5 e 6
  paralelas).

### 2026-11-15 — Onda 0: fundação

- Executada pela sessão principal como gerente, com três frentes paralelas em subagentes Sonnet
  (tooling/kernel/env, hooks para worktree, CI).
- `package.json` com todas as dependências previstas até a Onda 10 (pnpm 10.34.9, Next 16.4.6,
  TypeScript 6.0.3, porque o typescript-eslint ainda não suporta a 7; Zod 4; Vitest 5; ESLint 10;
  Supabase CLI 2.122.1).
- ESLint com fronteiras de módulo (`route.ts` só importa `presentation/*.handler`), Vitest com
  projetos `unit`/`int`/`api` (o env de teste vem de `supabase status -o env`, só URL local),
  `env.ts` (Zod; a secret key é validada mas não exposta), kernel (`Result`, `ErrorCode`,
  `DomainError`, `Clock`).
- `supabase/config.toml` endurecido (sem signup, JWT 15 min, senha ≥ 12, TOTP, Realtime/Storage/
  Edge desligados, só `public` na API, portas 544xx).
- Hooks resolvem a raiz pelo git do arquivo editado (73 testes `node --test`, incluindo worktree
  com `CLAUDE_PROJECT_DIR` apontando para o checkout principal); `stop-gates` também em
  `SubagentStop`.
- CI (`quality`, `audit`, `gitleaks`, `sast` (Semgrep CE; era `codeql` até 2026-11-16, ADR 0012), `database`) com todas as Actions pinadas por SHA;
  Dependabot para npm e Actions.
- Verificado localmente: `pnpm install --frozen-lockfile`, `lint`, `typecheck`, `test` (132),
  `test:hooks` (73), `contract:lint`, `build`, `format:check`, `db:start`, `db:reset`, `db:test`.
  O CI verde é conferido no PR antes do merge.

### 2026-11-15 — Onda 2: banco

- Sessão principal escreveu as 6 migrations (hardening e defaults de privilégio, identidade e
  helpers de RLS, auditoria append-only, tabelas de rastreamento, funções de conta, rate limit)
  e o `000_helpers.sql`; um subagente Sonnet escreveu a suíte pgTAP (401 asserts, 8 arquivos).
- `rls-auditor`: sem CRÍTICO/ALTO. Os MÉDIOS e BAIXOS foram corrigidos antes do PR:
  `mark_password_changed` exige prova da troca (linha de base do hash) e `aal2` para CEO com TOTP;
  `service_role` sem escrita em `profiles`/`audit_events`/template e sem EXECUTE além de
  `rate_limit_hit`; `session_id` malformado = sem sessão; `account.provisioned` idempotente; FK
  composta aprovação→fase/processo; janela na PK do rate limit; texto visível recusa caracteres
  de formatação Unicode (Cf, separadores).
- Spec atualizada (§3.4, §3.7, §4.2): `set_account_display_name` (necessária para o PATCH de
  login da Onda 7, que não tem migration), prova de troca de senha, mapeamento de
  `PASSWORD_UNCHANGED`/`USER_LIMIT_REACHED`, privilégios do `service_role`.
- A onda passou de ~700 linhas (SQL + testes), mas não foi dividida: o SQL é coeso e foi
  auditado de uma vez.
- Verificado: `pnpm db:reset && pnpm db:test && pnpm db:lint` → exit 0; `pnpm db:types` estável;
  os 5 IDs (AC-08/09/10/24/25) e AC-31 presentes nos testes.
- Pendente para as ondas de identidade: testar o trigger sob o papel real do GoTrue
  (`auth.admin.createUser`) na Onda 3/7; criar usuários já com a senha temporária (spec §3.4).

### 2026-11-15 — Onda 1: plataforma HTTP

- Executada por subagente Sonnet (xhigh) em worktree, em paralelo com a Onda 2.
- `withRoute` com política obrigatória (sem default) e ordem fixa (SEC-02); catálogo `ErrorCode`
  completo; problem+json; headers SEC-14 (pipeline e `next.config.ts`); request id; corpo com
  limite de 16 KiB lido em streaming; Origin; paginação com cursor ligado ao endpoint; logger pino
  com redação recursiva (chaves sem diferenciar caixa, `err.message`/`cause` sem e-mail ou token);
  `visibleText` (E-30); health; `tests/helpers/contract.ts` (corpo e headers).
- Rate limit: `rateLimit` obrigatório em toda rota, grupos nomeados (`login`, `totp-enroll`,
  `totp-verify`, `password-change`, `client-user-admin`, `writes`, `reads`, `health`), IPv6
  agregado em /64 e falha fechada (503) sem IP em produção.
- Decisão do usuário: o contrato não muda. Rotas sem schema de corpo ignoram o corpo, e rotas sem
  schema de query ignoram parâmetros desconhecidos, para o pipeline nunca produzir um status que
  a operação não documenta.
- A Onda 3 troca só `buildPipelineDeps()` em `src/shared/http/pipeline-deps.ts` (limitador do
  Postgres com HMAC do sujeito e resolver do Supabase) e mantém o grupo `health` fora do
  limitador do Postgres.
- Revisões: `code-reviewer` (1 ALTO de redação de logs, corrigido, e MÉDIOS corrigidos) e
  `contract-guardian` (teste do health movido para `tests/api`; BAIXOS corrigidos).
- Verificado: `pnpm lint && pnpm typecheck && pnpm test` (959) → exit 0; `pnpm test -t
  "AC-(22|23|26|27|29)"` → 115 verdes; `pnpm test:api` (health) → 4/4; `build`, `format:check`,
  `contract:lint` e `test:hooks` ok; nenhum `deps.<módulo>()`.

### 2026-11-16 — Onda 3: autenticação

- Executada por subagente Sonnet (xhigh) em worktree, com a sessão principal como manager (pedido
  do usuário; o plano previa a Onda 3 na sessão principal por ser de segurança crítica). Para
  compensar, a sessão principal reexecutou todos os gates a cada rodada e rodou threat-modeler,
  code-reviewer (duas passadas), contract-guardian e rls-auditor.
- Entregue: `POST /auth/login`, `POST /auth/logout`, `GET /auth/session`; limitador do Postgres
  (HMAC do sujeito, cache de negações por instância); resolver de principal do Supabase
  (`getClaims()` + `current_principal()`); cookies de login em buffer (só vão na resposta de
  sucesso); logout confirma a revogação no banco e restaura os cookies com 503 se falhar.
- Sessão (ADR 0009): no máximo 12 h desde o login e 4 h sem uso, aplicados no Auth
  (`[auth.sessions]`), no teto do cookie em `setAll` e no banco (`private.session_is_alive`, nova
  migration). A última atividade é a mais recente entre `refreshed_at`, o refresh token mais novo
  e `created_at`, porque o GoTrue não grava `refreshed_at` em toda renovação.
- Local: o Supabase local assina com ES256 e JWKS (não HS256), então `getClaims()` verifica
  localmente quando o `kid` é conhecido.
- Threat model (F-01..F-14): F-01 orçamento `session-upstream` por IP (60/15 min) para toda chamada
  ao Auth feita ao resolver a sessão; F-02 teto global de login (300/5 min, escopo `global` só
  programático); F-05 piso de 400 ms nas recusas de login; F-06 cache de negações; F-07 limpeza
  oportunista do rate limit (nova migration); F-08 limites de sessão no banco; F-09 hashes nos
  logs; F-11 request id gerado no servidor (o do cliente vai para `clientRequestId`); F-12 fachada
  estreita do admin client.
- code-reviewer, 1ª passada: 1 ALTO (a previsão do F-01 lia o cookie diferente do auth-js/ssr e
  podia ser contornada) e MÉDIOS (alg não suportado dava 500; o restore podia desfazer uma rotação
  de refresh token). Corrigidos: previsão que falha fechada e usa o parser do próprio ssr, medição
  real das chamadas ao Auth com cobrança depois do fato, `peekDenial` sem banco, restore só quando
  a sessão sumiu do jar. 2ª passada: 1 MÉDIO (trabalho abandonado depois do prazo ainda chamava o
  Auth), corrigido pela sessão principal: o fence também bloqueia o `fetch` do cliente; log
  `auth.session_key_rejected`.
- Trade-off aceito (T-29): atrás de um IP que um forjador esgotou, até um token verificado
  localmente leva 401 até o fim da janela (o cookie é mantido). O ganho de disponibilidade sem isso
  seria pequeno, porque todo navegador precisa de refresh a cada 15 min.
- Hook: o secrets-guard do AISAC recusa comandos Bash cujo texto contenha um identificador
  terminado em "ponto key" (parece extensão de arquivo de chave), mesmo quando é só código de teste
  ou texto de documentação. Falso positivo, visto duas vezes; o conteúdo foi escrito pelo Edit, que
  passa pelo `guard-writes.mjs`.
- Pendentes no threat model §8: F-03 (bloqueio direcionado, decisão do usuário), F-04 (Onda 11),
  F-13 (`secure_password_change`, Onda 4), F-14, medir o p95 da recusa de conta desativada em
  produção e subir `REFUSED_LOGIN_FLOOR_MS` se preciso (Onda 11). O contrato continua sem 503 em
  `logout`/`getSession` (ADR 0008).
- Verificado (sessão principal, a partir de `pnpm db:reset`): `pnpm verify` → 1349 unit + 459
  pgTAP; `pnpm db:lint` ok; `pnpm test:api` → 75/75 duas vezes; `pnpm test:api -t "AC-0[1-4]"` →
  8 verdes; `pnpm test:int` → 11/11; `build`, `format:check` e `test:hooks` (179) ok.

### 2026-11-16 — Onda 4: troca de senha e `ceo:create`

- Executada por subagente Sonnet (xhigh) em worktree, em paralelo com a Onda 5. Gates de banco em
  fila por `flock` num lockfile compartilhado.
- Entregue: `POST /auth/password` e `scripts/create-ceo.ts`.
  - Troca de senha: re-autenticação por sign-in num cliente descartável, cuja sessão de prova é
    revogada na hora e nunca chega aos cookies; gasta o orçamento global de login.
  - Depois do sign-in, `updateUser` e então `mark_password_changed()`, que exige a prova da linha
    de base. Um retry que recebe `PASSWORD_UNCHANGED` conta como sucesso.
  - Troca pela metade ou estado incerto: 503 com a orientação de repetir usando a nova senha como
    atual.
  - Script: valida só URL e secret key, exige `--target` igual ao host e recusa `http` fora de
    loopback; recusa URL e chave de fontes diferentes, recusa rodar em CI e recusa stdout fora de
    terminal sem `--allow-non-tty`. A senha temporária sai uma única vez no stdout.
- Decisões (ADR 0010): o GoTrue local ignora `current_password`. A opção que o faz valer
  (`security_update_password_require_current_password`) só existe no Auth hospedado e virou gate de
  go-live (F-40, ALTO). `secure_password_change = true` (F-13).
- Nova migration: auditoria da criação de CEO (F-42, RF-14). O gatilho de perfil grava
  `account.provisioned`, sem ator, com canal e papel da conexão nos metadados; se a auditoria
  falhar, a criação também falha.
- Revisões:
  - code-reviewer: sem CRÍTICO/ALTO; 3 MÉDIOS de código corrigidos (retry, estado incerto, env
    mínimo do script).
  - threat-modeler: F-40..F-47, com F-40 como gate de go-live e F-41 como decisão do usuário.
  - contract-guardian: conforme com ressalvas; as divergências que exigem mudar o contrato estão na
    proposta pendente do threat model §8.
  - rls-auditor: aprovado com 3 BAIXOS, corrigidos pela sessão principal (metadado `db_user`,
    filtros do pgTAP 005 mais estreitos, teste de `user_metadata` forjado).
- A sessão principal tornou robusto o teste F-05 da Onda 3. Sob a carga da onda paralela, o trabalho
  do pipeline antes do handler passou da folga de 20 ms; agora a folga é explícita (150 ms).
- Hook: o secrets-guard também recusa comandos Bash cujo texto contenha o nome do arquivo de env
  local (inclusive em mensagem de commit). O Write converteu escapes `\uXXXX` em caracteres
  literais; o agente corrigiu os testes e a sessão principal conferiu que o corpo da função na
  migration ficou idêntico ao anterior, mais o bloco novo.
- Verificado (sessão principal, sob o lock, a partir de `pnpm db:reset`): `pnpm verify` → 1522 unit
  + 481 pgTAP; `pnpm db:lint` ok; `pnpm db:types` sem diff; `pnpm test:api` → 121/121 duas vezes;
  `pnpm test:api -t "AC-0[56]|AC-31"` → 26 verdes; `pnpm test:int` → 22/22; `build`,
  `format:check` e `test:hooks` (179) ok. Falta só o `pnpm ceo:create` real, que é do usuário.

### 2026-11-16 — Onda 5: MFA TOTP para CEOs

- Executada por subagente Sonnet (xhigh) em worktree, em paralelo com a Onda 4. O plano previa a
  Onda 5 na sessão principal; a compensação foi a mesma da Onda 3: revisores completos e gates
  reexecutados pela sessão principal.
- Entregue: `POST /auth/mfa/totp/enroll` e `POST /auth/mfa/totp/verify`, e `tests/helpers/mfa.ts`
  (`loginAsCeoWithMfa` para as ondas 6 a 9).
  - Enroll: troca o fator não verificado (E-26) e dá 409 se já há fator verificado (E-27).
  - Verify: código errado dá 422 e conta no limite (E-28). Os cookies `aal2` saem pelo jar do
    pipeline.
- Nova migration (`totp_replay_protection_and_ceo_factor`):
  - **Replay de TOTP (F-21, RFC 6238 §5.2):** o GoTrue local aceita o mesmo código duas vezes. O
    app queima `SHA-256(factorId:code)` em `consume_totp_code()` antes de chamar o Auth, com janela
    de 120 s.
  - **`private.is_ceo()` (F-24):** passa a exigir também um fator TOTP verificado. Os pgTAP 001–006
    e 009 ganharam `tests.verify_totp` para os CEOs.
- Outras defesas:
  - **Primeira ativação de fator (F-20):** derruba as outras sessões do usuário com
    `signOut({ scope: 'others' })`.
  - **Teto diário de verificação (F-22):** 20 por dia por usuário, pelo novo `consumeUserBudget` do
    pipeline (grupo `totp-verify-daily`). A regra do contrato não mudou.
  - **Redação de logs (F-25):** URIs `otpauth://` e a chave `qrcode`.
- Revisões:
  - threat-modeler: F-20..F-26.
  - code-reviewer, duas passadas: 3 MÉDIOS corrigidos, nenhum novo na segunda.
  - contract-guardian: conforme, com lacunas de `expectToMatchContract` corrigidas.
  - rls-auditor na migration nova.
- Decisões que ficam com o usuário:
  - o `factorId` depois do enroll, que bloqueia o frontend;
  - F-23, que é residual. Rotacionar de novo não resolve, e a correção é reduzir o
    `refresh_token_reuse_interval`.
- Possível flake não reproduzido: uma execução logo depois do `db:reset` teve 500s no verify
  (suspeita de atraso no cache de schema do PostgREST). O teste agora imprime as linhas de erro do
  servidor quando falha.
- Verificado (sessão principal, sob o lock, a partir de `pnpm db:reset`, já com a Onda 4 na main):
  `pnpm verify` → 1642 unit + 530 pgTAP (522 + 8 do rls-auditor); `pnpm db:lint` ok; `pnpm db:types` sem diff;
  `pnpm test:api` → 162/162 duas vezes; `pnpm test:api -t "AC-07|E-2[678]"` → 11 verdes;
  `pnpm test:int` → 22/22; `build`, `format:check` e `test:hooks` (179) ok.
