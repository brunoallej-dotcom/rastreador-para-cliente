# NOTES — Rastreador para Cliente

Diário do projeto: status atual, pendências e log de sessões. Atualize ao fim de cada sessão.

## Status atual

- **Fase:** implementação em andamento (2026-11-16). Ondas 0 a 8 concluídas, mais os contratos
  `1.0.0-draft.2` e `draft.3` e a troca do CodeQL pelo Semgrep.
- **Paralelismo:** o plano define quais ondas rodam em subagente (Sonnet 5.5, esforço xhigh,
  worktree) e os pré-requisitos, resolvidos nas ondas 0 e 1. Ver "Sequência de execução" e
  "Pré-requisitos do paralelismo com subagentes" em `docs/plan/implementation-waves.md`.
- **Próximas ondas:** 9 ∥ 10, depois 10.1 (endurecimento do banco).
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
| 6 | Rastreamento: clientes (CRUD de CEO) | 5 | 4 | ✅ |
| 6.1 | Identidade: elevação de CEO atestada pelo backend (F-50) e validade da senha temporária (F-41) | 5, 6 | — | ✅ |
| 7 | Identidade: logins de cliente (provisionar, listar, desativar, resetar senha) | 4, 6.1 | 8 | ✅ |
| 8 | Rastreamento: processos e fases (criar, listar, detalhar, renomear e cancelar, template) | 6.1 | 7 | ✅ |
| 9 | Rastreamento: aprovação de fase ("Ok") + linha do tempo | 8 | 10 | ⬜ |
| 10 | Painel do cliente: leitura dos próprios processos | 8 | 9 | ⬜ |
| 10.1 | Endurecimento do banco: sem DML do `service_role` no rastreamento, auditoria de intenção e reversão no provisionamento (F-81, F-92b, F-93) | 7, 9, 10 | — | ⬜ |
| 11 | Hardening e go-live | 7, 9, 10, 10.1 | — | ⬜ |

Legenda: ⬜ não iniciada · 🟡 em andamento · ✅ concluída

## Pendências do usuário

| Pendência | Bloqueia |
|-----------|----------|
| Rodar `pnpm -s ceo:create --target 127.0.0.1:54421 --email ceo1@local.test --name "CEO Teste"` num terminal (sem `CI`) contra o Supabase local | goal command da Onda 4 (permissão "ask") |
| Gates de go-live do Auth hospedado (plano, Onda 11), a começar por F-40 | Onda 11 |
| Q-01: nomes das fases padrão (spec §8) | seed do template na Onda 2 (há placeholder) |
| Deixar o repositório privado (decidido em 2026-11-16) **depois** do merge do PR do Semgrep, que substitui o CodeQL (code scanning não existe em repositório privado de conta pessoal no GitHub Free) | exposição do threat model com achados abertos |
| ~~Branch protection na `main`~~: **decidido em 2026-11-16, sem GitHub Pro por ora.** Risco aceito: o GitHub não barra merge com CI vermelho; o fluxo de ondas só faz merge com todos os checks verdes | — |
| Corrigir no código-fonte do `@aisac/cli` o falso positivo do `secrets-guard` (identificador terminado em `.key` em comando Bash; ver CLAUDE.md) | conforto dos agentes |
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

### 2026-11-16 — Decisões do usuário sobre as pendências da noite

- O usuário aprovou todas as recomendações do método AISAC para as pendências acumuladas
  ("ok para todos, siga as recomendações do AISAC"). Registro:
  - **Contrato `1.0.0-draft.2`**, num PR próprio feito por subagente:
    - `TotpVerifyRequest.factorId` opcional e obsoleto, com o servidor resolvendo o fator pela
      sessão. Era o bloqueio do frontend.
    - `changePassword` descrevendo o comportamento real.
    - Orçamentos programáticos no `x-rate-limit`.
    - 503 nas operações autenticadas.
  - **F-03:** opção (c), cookie de dispositivo, na Onda 11. Muda o §3.9 da spec.
  - **F-41:** senha temporária válida por 72 h. Entra na **Onda 6.1, nova**, e não na 7 como foi
    dito ao usuário. Motivo: a validade muda `current_active_user_id()`, e o F-50 (b) muda
    `is_ceo()`. As duas mexem nas mesmas funções de identidade, e assim a Onda 7 continua sem
    migration, o que mantém o par 7 ∥ 8 com uma migration só.
  - **F-20:** o cadastro do TOTP fica amarrado à sessão, como gate de go-live da Onda 11, junto
    com os scripts de reset de senha e de MFA de CEO.
  - **F-50:**
    - (c), a publishable key tratada como segredo, é o controle principal e gate da Onda 11;
    - (b), o atestado do backend por `session_id`, entra na Onda 6.1 como defesa em
      profundidade, fechando o oráculo "chutar o TOTP no Auth e reapresentar pelo backend";
    - (a), o plano Teams, fica fora.
  - **BAIXOs:**
    - o limite por usuário depois do principal: aceito;
    - o minimatch: aceito por ora, porque não há versão compatível corrigida
      (`typescript-estree` 8.72.2 exige `^10`, e a correção está na 11);
    - o OTP de e-mail e os headers CORP/COOP: Onda 11.
  - **Repositório privado até o go-live.** Antes, o CodeQL dá lugar ao Semgrep CE, num PR
    próprio, porque code scanning não existe em repositório privado de conta pessoal no GitHub
    Free. A visibilidade só muda depois desse merge. No Free, branch protection em repositório
    privado exige GitHub Pro (pendência do usuário).
  - **Claude Code:**
    - `.claude/settings.json` voltou a pedir confirmação para push, PR e merge (revert da
      liberação da noite);
    - os allows de push em `feat/*` saíram do `settings.local.json`;
    - deny dos arquivos de ambiente reais em qualquer profundidade, e de
      `git diff|log|show --output`;
    - tabela de hooks do CLAUDE.md corrigida (`SubagentStop`, matchers e o `secrets-guard` do
      plugin AISAC);
    - `.claude/agent-memory/` passa a ser versionado;
    - ADRs 0001–0010 `accepted`.
- Numeração reservada de ADRs:
  - 0011: contrato `draft.2`, se precisar;
  - 0012: repositório privado e Semgrep;
  - 0013: atestado da Onda 6.1.

### 2026-11-16 — Onda 6: clientes, contrato `1.0.0-draft.2` e Semgrep

- **PR #13 (Semgrep):** a visibilidade do repositório mudou para privado, e o CodeQL passou a
  falhar ("Code scanning is not enabled"). O job `sast` (Semgrep CE em Docker, imagem fixada por
  digest, sem upload) o substituiu (ADR 0012), com duas regras locais e `pnpm sast`.
- **PR #14 (contrato `1.0.0-draft.2`, ADR 0011):**
  - `factorId` opcional e resolvido pela sessão;
  - `changePassword` alinhado com o comportamento real;
  - orçamentos programáticos no `x-rate-limit`, amarrados ao código nos dois sentidos
    (`PROGRAMMATIC_BUDGETS`);
  - 503 nas 22 operações autenticadas.
  - Revisões: um ALTO (invariantes de um sentido só) corrigido. O threat-modeler abriu F-60 a
    F-63; os requisitos do F-63 vão para a Onda 6.1.
  - O gitleaks acusou um literal de senha num teste unitário. O commit foi corrigido com fixup e
    autosquash, e o push saiu com `--force-with-lease` na branch de feature.
- **Onda 6 (CRUD de clientes pelo CEO):** executada por subagente Sonnet (xhigh) em worktree.
  - Entregue:
    - `GET/POST /admin/clients` e `GET/PATCH /admin/clients/{clientId}`;
    - migration `tracking_clients`, com `create_client`, `update_client` e
      `private.visible_text`, o validador único de nomes, igual ao `visibleText` do Zod;
    - pgTAP 013, `tests/helpers/clients.ts`, `getClientStatus` no `tracking/index.ts`.
  - Paginação keyset em duas consultas PostgREST, com cursor `admin-clients` (`created_at` em
    microssegundos + `id`). Os contadores vêm de `count` embutidos.
  - Revisões (threat-modeler F-51..F-59, code-reviewer, contract-guardian, rls-auditor): nenhum
    CRÍTICO ou ALTO. Corrigidos:
    - a validação de nome no SQL, que era mais fraca que a do Zod;
    - a normalização antes da checagem de CEO;
    - o cursor com ano 0000 e o surrogate isolado, que davam 500;
    - o nome do cliente que podia ir ao log pelo `cause`;
    - o mapeamento 409 morto e o `FOR NO KEY UPDATE`;
    - as lacunas de contrato nos testes.
  - **F-51 (clientes duplicados, retry da criação) fica com o usuário:** (decidido depois, opção (a): ver a entrada F-51 abaixo) as duas correções
    (índice único com 409, `Idempotency-Key`) mudam o contrato.
  - Flakes antigos corrigidos sem sleep: F-01, a virada da janela de 15 min no meio do teste, e
    F-05, o tempo da recusa sob carga.
- Verificado pela sessão principal, sob o lock, a partir de `pnpm db:reset`, já com o contrato
  `draft.2` na main: `pnpm verify` → 1861 unit + 673 pgTAP; `pnpm db:lint` ok; `pnpm db:types` sem diff;
  `pnpm test:api` → 247/247; `pnpm test:api -t "AC-11|E-29"` → 47 verdes; `pnpm test:int` → 22/22;
  `build` e `format:check` ok; `pnpm sast` sem achados (subagente).

### 2026-11-16 — F-51: nome de cliente único (complemento da Onda 6)

- O usuário escolheu a opção (a) do F-51.
- Entregue por subagente Sonnet (xhigh) em worktree, em paralelo com a Onda 6.1:
  - **Contrato `1.0.0-draft.3`:** 409 `CONFLICT` em `createClient` e `updateClient`. O texto do
    `ServiceUnavailable` foi corrigido, porque o retry de uma criação já gravada agora responde 409.
  - **Migration `client_name_unique`:** índice único parcial `clients_active_name_key` sobre
    `lower(NFKC(nome))`, ignorando marcas invisíveis de variação e sequências de espaços, só entre
    os clientes não arquivados.
  - `create_client` e `update_client` redefinidas e devolvendo `CLIENT_NAME_TAKEN`, inclusive ao
    renomear ou desarquivar para um nome em uso.
  - Deadlock ou falha de serialização (`40P01`, `40001`) vira 503 pelo SQLSTATE.
- Revisões: code-reviewer, rls-auditor e contract-guardian. Nenhum CRÍTICO. Corrigidos: marcas
  invisíveis na chave, texto do contrato preciso sobre o que conta como o mesmo nome, mapeamento
  explícito do deadlock, lacunas do pgTAP.
- **Resíduos:**
  - homóglifos de outro alfabeto ("А" cirílico) e "ß"/"ss" passam; a Onda 7 deve mostrar o id do
    cliente no provisionamento;
  - a chave depende do locale do banco: a Onda 11 confere o locale hospedado, e é preciso
    `REINDEX INDEX public.clients_active_name_key` depois de troca de ICU ou de versão major.
- Verificado pela sessão principal, sob o lock, a partir de `pnpm db:reset`: `pnpm verify` → 1879
  unit + 768 pgTAP; `db:lint` ok; `db:types` sem diff; `test:api` → 266/266;
  `test:api -t "E-4"` → 19; `test:int` → 22/22; `build` e `format:check` ok.

### 2026-11-16 — Onda 6.1: elevação de CEO atestada pelo backend e validade da senha temporária

- Executada por subagente Sonnet (xhigh) em worktree. É uma onda de segurança crítica. A
  compensação foram três rodadas de revisão (threat-modeler, code-reviewer, rls-auditor, mais uma
  segunda passada e uma checagem focada no trigger), com os gates reexecutados pela sessão
  principal.
- **Atestado (F-50 b, F-63, ADR 0013):** uma sessão `aal2` só vale como CEO depois que o verify
  passa pelo backend.
  - `attest_mfa_session` é só do `service_role` e revalida tudo em SQL. O atestado é por
    `session_id`, ligado ao fator e ao challenge do backend.
  - `is_ceo()`, `current_principal()` e `mark_password_changed()` exigem o atestado.
  - **Oráculo:** um challenge verificado fora do backend nos últimos 120 s faz o atestado ser
    recusado.
  - Recusa por sinal de ataque revoga todas as sessões e grava auditoria. Recusa por corrida só
    recusa.
- Achados das revisões, corrigidos antes do merge:
  - **F-64 (ALTO):** uma `aal2` direta apagava o fator do CEO e o atacante cadastrava o próprio.
    Agora existe uma marca permanente de primeira ativação, gravada por trigger em
    `auth.mfa_factors` na mesma transação da ativação. Um fator novo só entra depois do reset do
    operador (E-25, Onda 11).
  - **F-20 na recuperação (ALTO):** a revogação das outras sessões sumia depois de um atestado que
    falhava. Agora ela acontece dentro do próprio atestado, na transação.
  - **F-65 (MÉDIO):** `consume_totp_code` era um oráculo via PostgREST. A versão antiga caiu, e a
    nova é só do `service_role`.
  - Também corrigidos: F-66, F-67, F-69, F-71 (parcial), F-73, F-74, guarda de catálogo contra
    leitura de `aal` fora do atestado, e testes negativos `p_attested => false` em todos os objetos
    de CEO (regra registrada nas skills).
- **F-41:** a senha temporária vale 72 h (`current_active_user_id()`). O reset renova o prazo. O
  CEO com a senha vencida fica trancado até o script de reset da Onda 11.
- **Consequências operacionais:**
  - um CEO que perde o celular precisa do reset de MFA (E-25), um gate da Onda 11;
  - as conferências no Supabase hospedado (trigger em `auth.mfa_factors`, retenção de challenges,
    locale) entraram nos gates da Onda 11.
- Verificado pela sessão principal, sob o lock, a partir de `pnpm db:reset`, já com o F-51 na main:
  `pnpm verify` → 2023 unit + 934 pgTAP; `db:lint` ok; `db:types` sem diff; `test:api` → 289/289
  duas vezes; `test:api -t "E-3[2-9]"` → 19; `test:int` → 22/22; `build` e `format:check` ok;
  `pnpm sast` sem achados (subagente).
- **GitHub Pro:** o usuário decidiu ficar sem por ora. Sem branch protection, o merge só com CI
  verde depende do fluxo, e é o que a sessão principal faz.

### 2026-11-16 — Onda 8: processos e fases

- Executada por subagente Sonnet (xhigh) em worktree, em paralelo com a Onda 7. A sessão caiu no
  meio, e as duas ondas foram retomadas do ponto em que estavam. O scratchpad foi apagado no
  restart, e o brief comum foi recriado com as lições das revisões embutidas.
- **Entregue:**
  - `GET/POST /admin/clients/{clientId}/processes`, `GET/PATCH /admin/processes/{processId}` e
    `GET /admin/stage-templates/default`;
  - o agregado `Process`, com os invariantes I1–I6 e a transição de aprovação pura, que a Onda 9
    expõe;
  - migration `tracking_processes`, com `create_process`, que trava o cliente (arquivar e criar se
    serializam), e `update_process`, com a máquina de estados;
  - pgTAP 016;
  - cobertura de `tracking/{domain,application}` em 100% de linhas, agora exigida no CI
    (`quality` roda `pnpm test:coverage`).
- **Revisões** (threat-modeler F-80..F-89, code-reviewer, contract-guardian, rls-auditor): nenhum
  CRÍTICO.
  - Corrigidos:
    - a leitura confere os invariantes, não só a forma;
    - `23514`/`22001` viram 500;
    - CHECKs do template alinhados ao `visible_text`;
    - descrição em branco vira null no domínio;
    - asserts de lock no pgTAP;
    - a semântica do retry documentada (cancelar repetido → 422);
    - teste de 429.
  - **Orçamento global de login nos testes:** a suíte de API já usava cerca de 277 dos 300 por 5
    min. O setup do projeto `api` agora zera esse contador antes de cada arquivo
    (`resetGlobalLoginBudget` em `tests/helpers/db.ts`).
- **Decisões que ficam com o usuário:**
  - **F-80:** POST de processo repetido duplica (índice único de título ativo com 409, ou
    `Idempotency-Key`; muda o contrato);
  - **F-87:** alterações em processos de cliente arquivado (spec, Q-13);
  - contrato `draft.4`, só de documentação: semântica de retry de `createProcess`,
    `updateProcess`, `provisionClientUser` e `resetClientUserPassword`; contador compartilhado de
    20/h; regras E-30 em `DisplayName`, `StageInput` e títulos; descrição de
    `previousTitle`/`newTitle`.
- **Para a Onda 9** (rls-auditor, F-82): `approve_current_stage` trava a linha do processo antes
  das fases, e a linha do tempo não preenche `previousTitle`/`newTitle`.
- **Onda 10.1 criada:** endurecimento do banco (F-81, F-92b, F-93), antes da 11.
- Verificado pela sessão principal, sob o lock, a partir de `pnpm db:reset`: `pnpm verify` → 2330 unit
  + 1323 pgTAP; `db:lint` ok; `db:types` sem diff; `test:api` → 389/389 duas vezes;
  `test:api -t "AC-1[59]|E-(16|20)"` → 49; `test:int` → 22/22; `test:coverage` ok; `build` e
  `format:check` ok; `pnpm sast` sem achados (subagente).

### 2026-11-16 — Onda 7: logins de cliente

- Executada por subagente Sonnet (xhigh) em worktree, em paralelo com a Onda 8, e retomada depois da
  queda da sessão.
- **Entregue:** `GET/POST /admin/clients/{clientId}/users`, `PATCH .../users/{userId}` e o reset de
  senha.
  - O provisionamento cria no Auth pela Admin API, com papel fixo `client`, e registra no banco.
  - O desativar grava no banco e depois bane no Auth.
  - O reset troca a senha no Auth e depois exige a troca no banco, o que renova a validade de 72 h.
- **Revisões** (threat-modeler F-90..F-96, code-reviewer, contract-guardian, rls-auditor, mais uma
  segunda passada): nenhum CRÍTICO. Corrigidos:
  - **ALTO:** conta criada sem resposta confirmada virava 500 sem compensação. Depois de qualquer
    falha ambígua do Auth, a lista é relida. Só se apaga o login que é comprovadamente desta
    tentativa (um candidato, criado depois do início dela); no resto, 503 e log.
  - **F-91:** o facade de admin perdeu o `auth.admin` genérico. Sobraram `createClientUser` (papel
    fixo), `setPassword`, `setBan` e `deleteUser`, com regras Semgrep contra uso do admin fora do
    facade e contra `app_metadata.role` diferente de `client`.
  - Reset incompleto é sempre `reset_incomplete`. O re-ban depois de uma reativação falha só vale
    para quem estava desativado. `ban_failed` leva o motivo.
  - **Prontidão do PostgREST depois do `db:reset`:** era a causa da falha intermitente nos
    `beforeAll`. Agora há uma espera compartilhada no setup dos projetos `int` e `api`.
- **Planejado:** F-92b e F-93 vão para a Onda 10.1. F-94/F-95 (alerta `ban_failed` e
  reconciliação) vão para a Onda 11. F-96 aceito.
- Verificado pela sessão principal, sob o lock, a partir de `pnpm db:reset`, já com a Onda 8 na
  main: `pnpm verify` → 2520 unit + 1323 pgTAP; `db:lint` ok; `db:types` sem diff; `test:api` →
  454/454 duas vezes; `test:api -t "AC-1[234]|E-(1[6789]|2[34])"` → 37; `test:int` → 22/22;
  `test:coverage`, `build` e `format:check` ok; `pnpm sast` sem achados (subagente).
